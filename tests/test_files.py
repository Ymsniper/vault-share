import io
import os
import subprocess

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.db import get_db
from security.pki import load_certificate

CONTRACT = b"Supply contract: 1,200 units at 40 EUR, delivery in March."


def upload(client, data=CONTRACT, name="contract.txt"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(data), name), "description": "Supply contract"},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def stored_path(app, name="contract.txt"):
    return os.path.join(app.config["UPLOAD_FOLDER"], name)


def my_files(client, q=""):
    return client.get("/", query_string={"q": q}).data.split(b"Shared with me")[0]


def shared_with_me(client):
    return client.get("/").data.split(b"Shared with me")[1]


def user_id(app, username):
    with app.app_context():
        return get_db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def test_upload_stores_only_ciphertext(app, alice):
    assert upload(alice).request.path == "/files/1"
    with open(stored_path(app), "rb") as f:
        stored = f.read()
    assert CONTRACT not in stored
    # AES-GCM adds a 16-byte authentication tag
    assert len(stored) == len(CONTRACT) + 16


def test_upload_requires_a_file(alice):
    r = alice.post("/upload", data={}, content_type="multipart/form-data")
    assert b"Choose a file to upload." in r.data


def test_download_returns_the_original_bytes(alice):
    assert b"Integrity verified" in upload(alice).data
    assert alice.get("/files/1/download").data == CONTRACT


def test_modified_file_fails_verification(app, alice):
    upload(alice)
    with open(stored_path(app), "r+b") as f:
        first = f.read(1)
        f.seek(0)
        f.write(bytes([first[0] ^ 1]))

    assert b"the stored file was modified" in alice.get("/files/1").data
    assert alice.get("/files/1/download").headers["Location"] == "/files/1"


def test_changed_hash_fails_verification(app, alice):
    upload(alice)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET sha256 = ? WHERE id = 1", ("0" * 64,))
        db.commit()

    assert b"does not match its SHA-256 hash" in alice.get("/files/1").data


def test_share_then_revoke(app, alice, bob):
    upload(alice)
    r = alice.post("/files/1/share", data={"username": "bob"}, follow_redirects=True)
    assert b"Shared with bob." in r.data
    assert b"contract.txt" in shared_with_me(bob)
    assert bob.get("/files/1/download").data == CONTRACT

    alice.post("/files/1/revoke", data={"recipient_id": user_id(app, "bob")})
    assert b"contract.txt" not in shared_with_me(bob)

    alice.post("/files/1/share", data={"username": "bob"})
    assert b"contract.txt" in shared_with_me(bob)


def test_share_rejects_unknown_user_and_owner(alice):
    upload(alice)
    r = alice.post("/files/1/share", data={"username": "nobody"}, follow_redirects=True)
    assert b"Unknown user." in r.data
    r = alice.post("/files/1/share", data={"username": "alice"}, follow_redirects=True)
    assert b"The owner already has access." in r.data


def test_search_filters_my_files(alice):
    upload(alice)
    upload(alice, name="invoice-0412.txt")
    page = my_files(alice, "invoice")
    assert b"invoice-0412.txt" in page
    assert b"contract.txt" not in page


def test_delete_removes_file_and_shares(app, alice, bob):
    upload(alice)
    alice.post("/files/1/share", data={"username": "bob"})
    alice.post("/files/1/delete")

    assert not os.path.exists(stored_path(app))
    assert alice.get("/files/1").status_code == 404
    assert b"contract.txt" not in shared_with_me(bob)


def test_unknown_file_is_404(alice):
    assert alice.get("/files/42").status_code == 404


def test_file_page_names_the_signer(alice):
    assert b"Signature valid, signed by alice." in upload(alice).data


def test_changed_signature_fails_verification(app, alice):
    upload(alice)
    with app.app_context():
        db = get_db()
        signature = bytearray(db.execute("SELECT signature FROM files").fetchone()[0])
        signature[-1] ^= 1
        db.execute("UPDATE files SET signature = ?", (bytes(signature),))
        db.commit()

    assert b"the signature is not valid" in alice.get("/files/1").data
    assert alice.get("/files/1/download").headers["Location"] == "/files/1"


def test_signature_checks_out_with_openssl(app, alice, tmp_path):
    upload(alice)
    with app.app_context():
        row = get_db().execute(
            "SELECT f.signature, c.pem FROM files f JOIN certificates c ON c.id = f.cert_id"
        ).fetchone()
    public_key = load_certificate(row["pem"]).public_key()
    (tmp_path / "alice.pub").write_bytes(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    (tmp_path / "sig.der").write_bytes(row["signature"])
    (tmp_path / "contract.txt").write_bytes(CONTRACT)

    r = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", "alice.pub", "-signature", "sig.der", "contract.txt"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert r.stdout.strip() == "Verified OK"


def check_copy(client, data):
    return client.post(
        "/files/1/check",
        data={"copy": (io.BytesIO(data), "my-copy.txt")},
        content_type="multipart/form-data",
        follow_redirects=True,
    ).data


def test_check_local_copy(alice):
    upload(alice)
    assert b"identical to the original, signed by alice" in check_copy(alice, CONTRACT)
    edited = CONTRACT.replace(b"40 EUR", b"14 EUR")
    assert b"different from the original" in check_copy(alice, edited)


def test_search_is_not_injectable(alice, bob):
    upload(alice)
    page = my_files(alice, "' OR 1=1 --")
    assert b"contract.txt" not in page
    page = my_files(alice, "' UNION SELECT id, username, 0, 'x' FROM users--")
    assert b"bob" not in page


def test_search_treats_wildcards_as_text(alice):
    upload(alice)
    assert b"contract.txt" not in my_files(alice, "%")


def test_names_and_descriptions_are_escaped(alice):
    payload = "<script>alert(1)</script>"
    r = alice.post(
        "/upload",
        data={"file": (io.BytesIO(CONTRACT), "contract.txt"), "description": payload},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert payload.encode() not in r.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in r.data


def test_security_headers(alice):
    headers = alice.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def test_other_users_get_403(app, alice, bob):
    upload(alice)
    assert bob.get("/files/1").status_code == 403
    assert bob.get("/files/1/download").status_code == 403
    r = bob.post(
        "/files/1/check",
        data={"copy": (io.BytesIO(CONTRACT), "copy.txt")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 403
    assert bob.post("/files/1/share", data={"username": "bob"}).status_code == 403
    assert bob.post("/files/1/revoke", data={"recipient_id": "1"}).status_code == 403
    assert bob.post("/files/1/delete").status_code == 403

    assert alice.get("/files/1/download").data == CONTRACT
    with app.app_context():
        denied = get_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'access' AND outcome = 'denied'"
        ).fetchone()[0]
    assert denied == 6


def test_recipient_can_read_but_not_manage(alice, bob):
    upload(alice)
    alice.post("/files/1/share", data={"username": "bob"})
    assert bob.get("/files/1/download").data == CONTRACT
    assert bob.post("/files/1/share", data={"username": "bob"}).status_code == 403
    assert bob.post("/files/1/delete").status_code == 403


def test_revoked_recipient_loses_access(app, alice, bob):
    upload(alice)
    alice.post("/files/1/share", data={"username": "bob"})
    alice.post("/files/1/revoke", data={"recipient_id": user_id(app, "bob")})
    assert bob.get("/files/1/download").status_code == 403
