import io
import os
import re
import stat
import subprocess
import uuid

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import create_app
from app.db import get_db
from security.pki import load_certificate

CONTRACT = b"Supply contract: 1,200 units at 40 EUR, delivery in March."
PDF = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"


def upload(client, data=CONTRACT, name="contract.txt", description="Supply contract"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(data), name), "description": description},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def new_file(client, data=CONTRACT, name="contract.txt"):
    """Upload a file and return the URL of its page."""
    return upload(client, data, name).request.path


def file_id(url):
    return url.rsplit("/", 1)[-1]


def stored_path(app, url):
    return os.path.join(app.config["STORAGE_FOLDER"], file_id(url))


def my_files(client, q=""):
    return client.get("/", query_string={"q": q}).data.split(b"Shared with me")[0]


def shared_with_me(client):
    return client.get("/").data.split(b"Shared with me")[1]


def user_id(app, username):
    with app.app_context():
        return get_db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def test_upload_stores_only_ciphertext(app, alice):
    url = new_file(alice)
    assert re.fullmatch(r"/files/[0-9a-f-]{36}", url)
    with open(stored_path(app, url), "rb") as f:
        stored = f.read()
    assert CONTRACT not in stored
    # 12-byte nonce in front, 16-byte GCM authentication tag at the end
    assert len(stored) == 12 + len(CONTRACT) + 16


def test_same_content_never_gives_the_same_ciphertext(app, alice):
    first, second = new_file(alice), new_file(alice)
    with open(stored_path(app, first), "rb") as a, open(stored_path(app, second), "rb") as b:
        assert a.read() != b.read()


def test_files_cannot_be_swapped_on_disk(app, alice):
    first = new_file(alice)
    second = new_file(alice, b"Second contract: 300 units at 55 EUR.", name="second.txt")
    os.replace(stored_path(app, second), stored_path(app, first))
    assert b"the stored file was modified" in alice.get(first).data


def test_files_need_the_master_key(app, alice, tmp_path):
    url = new_file(alice)
    path = os.path.join(app.config["SECRETS_DIR"], "master.key")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert os.path.getsize(path) == 32

    # same database and encrypted files, but not the same master key
    thief = create_app(
        {
            **{k: app.config[k] for k in ("TESTING", "WTF_CSRF_ENABLED", "DATABASE", "STORAGE_FOLDER")},
            "SECRETS_DIR": str(tmp_path / "another-machine"),
            "SECRET_KEY": app.config["SECRET_KEY"],
        }
    )
    client = thief.test_client()
    client.set_cookie("sid", alice.get_cookie("sid").value)
    assert b"key was modified" in client.get(url).data


def test_upload_requires_a_file(alice):
    r = alice.post("/upload", data={}, content_type="multipart/form-data")
    assert b"Choose a file to upload." in r.data


def test_download_returns_the_original_bytes(alice):
    assert b"Integrity verified" in upload(alice).data
    url = new_file(alice)
    assert alice.get(f"{url}/download").data == CONTRACT


def test_download_is_always_an_attachment(alice):
    url = new_file(alice)
    r = alice.get(f"{url}/download")
    assert r.headers["Content-Disposition"].startswith("attachment;")
    assert r.mimetype == "text/plain"


def test_upload_refuses_types_not_on_the_list(alice):
    for name in ("page.html", "drawing.svg", "run.sh", "no-extension", "invoice.pdf.html"):
        r = upload(alice, b"<html><script>alert(1)</script></html>", name=name)
        assert b"This file type is not allowed." in r.data
    assert b"No files found." in my_files(alice)


def test_upload_refuses_content_that_does_not_match(alice):
    r = upload(alice, b"<html>not a pdf</html>", name="report.pdf")
    assert b"does not match the .pdf extension" in r.data
    r = upload(alice, b"\xff\xfe\x00binary", name="notes.txt")
    assert b"must contain UTF-8 text" in r.data
    assert b"Uploaded report.pdf." in upload(alice, PDF, name="report.pdf").data


def test_upload_over_10_mb_is_refused(alice):
    r = upload(alice, b"a" * (10 * 1024 * 1024 + 1), name="big.txt")
    assert r.status_code == 413


def test_path_in_the_name_is_ignored(app, alice, tmp_path):
    url = new_file(alice, name="../../evil.txt")
    assert b"evil.txt" in my_files(alice)
    assert os.listdir(app.config["STORAGE_FOLDER"]) == [file_id(url)]
    assert not os.path.exists(tmp_path / "evil.txt")


def test_modified_file_fails_verification(app, alice):
    url = new_file(alice)
    with open(stored_path(app, url), "r+b") as f:
        first = f.read(1)
        f.seek(0)
        f.write(bytes([first[0] ^ 1]))

    assert b"the stored file was modified" in alice.get(url).data
    assert alice.get(f"{url}/download").headers["Location"] == url


def test_changed_hash_fails_verification(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET sha256 = ? WHERE id = ?", ("0" * 64, file_id(url)))
        db.commit()

    assert b"does not match its SHA-256 hash" in alice.get(url).data


def test_share_then_revoke(app, alice, bob):
    url = new_file(alice)
    r = alice.post(f"{url}/share", data={"username": "bob"}, follow_redirects=True)
    assert b"Shared with bob." in r.data
    assert b"contract.txt" in shared_with_me(bob)
    assert bob.get(f"{url}/download").data == CONTRACT

    alice.post(f"{url}/revoke", data={"recipient_id": user_id(app, "bob")})
    assert b"contract.txt" not in shared_with_me(bob)

    alice.post(f"{url}/share", data={"username": "bob"})
    assert b"contract.txt" in shared_with_me(bob)


def test_share_rejects_unknown_user_and_owner(alice):
    url = new_file(alice)
    r = alice.post(f"{url}/share", data={"username": "nobody"}, follow_redirects=True)
    assert b"Unknown user." in r.data
    r = alice.post(f"{url}/share", data={"username": "alice"}, follow_redirects=True)
    assert b"The owner already has access." in r.data


def test_search_filters_my_files(alice):
    new_file(alice)
    new_file(alice, name="invoice-0412.txt")
    page = my_files(alice, "invoice")
    assert b"invoice-0412.txt" in page
    assert b"contract.txt" not in page


def test_delete_removes_file_and_shares(app, alice, bob):
    url = new_file(alice)
    alice.post(f"{url}/share", data={"username": "bob"})
    alice.post(f"{url}/delete")

    assert not os.path.exists(stored_path(app, url))
    assert alice.get(url).status_code == 404
    assert b"contract.txt" not in shared_with_me(bob)


def test_unknown_file_is_404(alice):
    assert alice.get(f"/files/{uuid.uuid4()}").status_code == 404
    assert alice.get("/files/1").status_code == 404


def test_file_page_names_the_signer(alice):
    assert b"Signature valid, signed by alice." in upload(alice).data


def test_changed_signature_fails_verification(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        signature = bytearray(db.execute("SELECT signature FROM files").fetchone()[0])
        signature[-1] ^= 1
        db.execute("UPDATE files SET signature = ?", (bytes(signature),))
        db.commit()

    assert b"the signature is not valid" in alice.get(url).data
    assert alice.get(f"{url}/download").headers["Location"] == url


def test_signature_checks_out_with_openssl(app, alice, tmp_path):
    new_file(alice)
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


def check_copy(client, url, data):
    return client.post(
        f"{url}/check",
        data={"copy": (io.BytesIO(data), "my-copy.txt")},
        content_type="multipart/form-data",
        follow_redirects=True,
    ).data


def test_check_local_copy(alice):
    url = new_file(alice)
    assert b"identical to the original, signed by alice" in check_copy(alice, url, CONTRACT)
    edited = CONTRACT.replace(b"40 EUR", b"14 EUR")
    assert b"different from the original" in check_copy(alice, url, edited)


def test_search_is_not_injectable(alice, bob):
    new_file(alice)
    page = my_files(alice, "' OR 1=1 --")
    assert b"contract.txt" not in page
    page = my_files(alice, "' UNION SELECT id, username, 0, 'x' FROM users--")
    assert b"bob" not in page


def test_search_treats_wildcards_as_text(alice):
    new_file(alice)
    assert b"contract.txt" not in my_files(alice, "%")


def test_names_and_descriptions_are_escaped(alice):
    payload = "<script>alert(1)</script>"
    r = upload(alice, description=payload)
    assert payload.encode() not in r.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in r.data


def test_security_headers(alice):
    headers = alice.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"


def test_other_users_get_403(app, alice, bob):
    url = new_file(alice)
    assert bob.get(url).status_code == 403
    assert bob.get(f"{url}/download").status_code == 403
    r = bob.post(
        f"{url}/check",
        data={"copy": (io.BytesIO(CONTRACT), "copy.txt")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 403
    assert bob.post(f"{url}/share", data={"username": "bob"}).status_code == 403
    assert bob.post(f"{url}/revoke", data={"recipient_id": "1"}).status_code == 403
    assert bob.post(f"{url}/delete").status_code == 403

    assert alice.get(f"{url}/download").data == CONTRACT
    with app.app_context():
        denied = get_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'access' AND outcome = 'denied'"
        ).fetchone()[0]
    assert denied == 6


def test_recipient_can_read_but_not_manage(alice, bob):
    url = new_file(alice)
    alice.post(f"{url}/share", data={"username": "bob"})
    assert bob.get(f"{url}/download").data == CONTRACT
    assert bob.post(f"{url}/share", data={"username": "bob"}).status_code == 403
    assert bob.post(f"{url}/delete").status_code == 403


def test_revoked_recipient_loses_access(app, alice, bob):
    url = new_file(alice)
    alice.post(f"{url}/share", data={"username": "bob"})
    alice.post(f"{url}/revoke", data={"recipient_id": user_id(app, "bob")})
    assert bob.get(f"{url}/download").status_code == 403
