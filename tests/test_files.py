import io
import os
import re
import shlex
import sqlite3
import stat
import subprocess
import uuid
import zipfile

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlcipher3 import dbapi2 as sqlcipher

from app import create_app
from app.db import get_db
from app.files import mac_key
from app.identity import unlock_encryption_key
from security.crypto import decrypt
from security.hybrid import unwrap_file_key
from security.integrity import record_mac
from security.pki import load_certificate

from .samples import CHECKED, ELF, EXE, zipped

PASSWORD = "contract-2026"
CONTRACT = b"Supply contract: 1,200 units at 40 EUR, delivery in March."
PDF = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"


def upload(client, data=CONTRACT, name="contract.txt", description="Supply contract"):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(data), name), "description": description, "password": PASSWORD},
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def new_file(client, data=CONTRACT, name="contract.txt"):
    """Upload a file and return the URL of its page."""
    return upload(client, data, name).request.path


def download(client, url, password=PASSWORD, **kwargs):
    """Download a file the way the page does: the password opens the key."""
    return client.post(f"{url}/download", data={"password": password}, **kwargs)


def share(client, url, username, password=PASSWORD, **kwargs):
    return client.post(f"{url}/share", data={"username": username, "password": password}, **kwargs)


def revoke(client, url, recipient_id, password=PASSWORD, **kwargs):
    data = {"recipient_id": recipient_id, "password": password}
    return client.post(f"{url}/revoke", data=data, **kwargs)


def delete(client, url, password=PASSWORD, **kwargs):
    return client.post(f"{url}/delete", data={"password": password}, **kwargs)


def file_id(url):
    return url.rsplit("/", 1)[-1]


def stored_path(app, url):
    return os.path.join(app.config["STORAGE_FOLDER"], file_id(url))


def my_files(client, q=""):
    return client.post("/", data={"q": q}).data.split(b"Shared with me")[0]


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
    assert b"the stored file was modified" in download(alice, first, follow_redirects=True).data


def test_files_need_the_master_key(app, alice, tmp_path):
    url = new_file(alice)
    path = os.path.join(app.config["SECRETS_DIR"], "master.key")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert os.path.getsize(path) == 32

    # same database and encrypted files, but not the same master key
    thief = create_app(
        {
            **{
                k: app.config[k]
                for k in ("TESTING", "WTF_CSRF_ENABLED", "HTTPS", "DATABASE", "STORAGE_FOLDER")
            },
            "SECRETS_DIR": str(tmp_path / "another-machine"),
            "SECRET_KEY": app.config["SECRET_KEY"],
        }
    )
    # without the master key even the database cannot be opened, so the
    # wrapped file keys stay out of reach too
    with thief.app_context():
        with pytest.raises(sqlcipher.DatabaseError):
            get_db().execute("SELECT * FROM files").fetchall()


def test_the_database_file_is_encrypted(app, alice, bob):
    new_file(alice, name="merger-plan.txt")
    with open(app.config["DATABASE"], "rb") as f:
        raw = f.read()
    assert not raw.startswith(b"SQLite format 3")
    for text in (b"alice", b"bob", b"merger-plan", b"argon2id", b"127.0.0.1"):
        assert text not in raw
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(app.config["DATABASE"]).execute("SELECT * FROM users").fetchall()


def test_upload_requires_a_file(alice):
    r = alice.post("/upload", data={}, content_type="multipart/form-data")
    assert b"Choose a file to upload." in r.data


def test_download_returns_the_original_bytes(alice):
    assert b"Record verified" in upload(alice).data
    url = new_file(alice)
    assert download(alice, url).data == CONTRACT


def test_download_is_always_an_attachment(alice):
    url = new_file(alice)
    r = download(alice, url)
    assert r.headers["Content-Disposition"].startswith("attachment;")
    assert r.mimetype == "text/plain"
    # a POST with the password: never a link, so the password never sits in a URL
    assert alice.get(f"{url}/download").status_code == 405


def test_upload_refuses_types_not_on_the_list(alice):
    for name in ("page.html", "drawing.svg", "run.sh", "no-extension", "invoice.pdf.html"):
        r = upload(alice, b"<html><script>alert(1)</script></html>", name=name)
        assert b"This file type is not allowed." in r.data
    assert b"No files found." in my_files(alice)


@pytest.mark.parametrize("name", sorted(CHECKED))
def test_common_types_are_checked_and_accepted(alice, name):
    assert f"Uploaded {name}.".encode() in upload(alice, CHECKED[name], name=name).data


@pytest.mark.parametrize(
    "name",
    ["letter.doc", "budget.xls", "slides.ppt", "letter.rtf", "page.htm", "feed.xml",
     "app.js", "setup.exe", "setup.msi"],
)
def test_types_left_out_are_refused(alice, name):
    assert b"This file type is not allowed." in upload(alice, b"anything", name=name).data


def test_renamed_content_is_refused(alice):
    for data, name in (
        (ELF, "photo.png"),
        (EXE, "clip.mp4"),
        (zipped([("a.txt", "x")]), "report.pdf"),
        (CHECKED["photo.jpg"], "chart.png"),
    ):
        assert b"does not match the ." in upload(alice, data, name=name).data, name
    assert b"No files found." in my_files(alice)


def test_the_upload_page_explains_the_checks(alice):
    page = alice.get("/upload").data.decode()
    assert page.count('<details class="vs-fold">') == 3
    for title in ("Checked", "Signed", "Sealed"):
        assert f"<strong>{title}</strong>" in page
    # the lists come from the same table as the checks
    assert "PDF, DOCX, XLSX, PPTX, ODT, ODS, ODP" in page
    assert "ZIP, 7Z, RAR, TAR, GZ, TGZ, BZ2, XZ" in page
    assert "it must be 10 MB or less" in page
    assert 'accept=".pdf,.docx,' in page and ".zip," in page


def test_toml_must_parse(alice):
    assert b"is not valid TOML" in upload(alice, b"name = ", name="app.toml").data


def test_downloads_keep_the_type_from_the_list(alice):
    url = new_file(alice, CHECKED["clip.mov"], name="clip.mov")
    assert download(alice, url).mimetype == "video/quicktime"


def test_upload_refuses_content_that_does_not_match(alice):
    r = upload(alice, b"<html>not a pdf</html>", name="report.pdf")
    assert b"does not match the .pdf extension" in r.data
    r = upload(alice, b"\xff\xfe\x00binary", name="notes.txt")
    assert b"must contain UTF-8 text" in r.data
    assert b"Uploaded report.pdf." in upload(alice, PDF, name="report.pdf").data


def test_upload_over_10_mb_is_refused(alice):
    r = upload(alice, b"a" * (10 * 1024 * 1024 + 1), name="big.txt")
    assert b"This file is over the 10 MB limit." in r.data
    # far over it, Flask refuses the request before the app reads it
    r = upload(alice, b"a" * (11 * 1024 * 1024), name="big.txt")
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

    # the page checks the record, which needs no key; opening the file at
    # download is what finds a change in the stored bytes
    assert b"Record verified" in alice.get(url).data
    r = download(alice, url, follow_redirects=True)
    assert r.request.path == url
    assert b"the stored file was modified" in r.data


def test_changed_hash_fails_verification(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET sha256 = ? WHERE id = ?", ("0" * 64, file_id(url)))
        db.commit()

    # caught by the HMAC: the hash alone could be rewritten to match
    assert b"record of this file was changed in the database" in alice.get(url).data


def test_every_field_of_a_record_is_under_its_hmac(app, alice, bob):
    with app.app_context():
        bob_cert = get_db().execute(
            "SELECT id FROM certificates WHERE user_id = ?", (user_id(app, bob.handle),)
        ).fetchone()[0]
    for column, value in (
        ("filename", "contract-final.txt"),
        ("description", "Signed by both sides"),
        ("signature", b"\x30" * 70),
        ("cert_id", bob_cert),
        ("mime", "application/pdf"),
        ("checked", 0),
    ):
        url = new_file(alice)
        with app.app_context():
            db = get_db()
            db.execute(f"UPDATE files SET {column} = ? WHERE id = ?", (value, file_id(url)))
            db.commit()
        page = alice.get(url).data
        assert b"record of this file was changed in the database" in page, column


def test_fields_of_a_record_cannot_run_into_each_other():
    key = bytes(32)
    record = {
        "id": "8b5d", "owner_id": 1, "sha256": "ab" * 32, "size": 3, "mime": "text/plain",
        "checked": 1, "uploaded_at": "2026-11-12 10:00:00", "signature": b"sig", "cert_id": 1,
    }
    # joined with "|", these two would be the same message
    one = record_mac(key, {**record, "filename": "q3|final", "description": "draft"})
    two = record_mac(key, {**record, "filename": "q3", "description": "final|draft"})
    assert one != two


def test_share_then_revoke(app, alice, bob):
    url = new_file(alice)
    r = share(alice, url, bob.handle, follow_redirects=True)
    assert f"Shared with {bob.handle}.".encode() in r.data
    assert b"contract.txt" in shared_with_me(bob)
    assert download(bob, url).data == CONTRACT

    revoke(alice, url, user_id(app, bob.handle))
    assert b"contract.txt" not in shared_with_me(bob)

    share(alice, url, bob.handle)
    assert b"contract.txt" in shared_with_me(bob)


def test_share_rejects_unknown_user_and_owner(alice):
    url = new_file(alice)
    r = share(alice, url, "nobody", follow_redirects=True)
    assert b"Unknown user." in r.data
    r = share(alice, url, alice.handle, follow_redirects=True)
    assert b"The owner already has access." in r.data


def test_search_filters_my_files(alice):
    new_file(alice)
    new_file(alice, name="invoice-0412.txt")
    page = my_files(alice, "invoice")
    assert b"invoice-0412.txt" in page
    assert b"contract.txt" not in page


def test_delete_removes_file_and_shares(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    delete(alice, url)

    assert not os.path.exists(stored_path(app, url))
    assert alice.get(url).status_code == 404
    assert b"contract.txt" not in shared_with_me(bob)


def test_delete_and_revoke_ask_for_the_password(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    bob_id = user_id(app, bob.handle)

    # a stolen session cookie alone destroys nothing and cuts nobody off
    r = delete(alice, url, "a guess", follow_redirects=True)
    assert b"Wrong password: nothing was deleted." in r.data
    r = alice.post(f"{url}/delete", follow_redirects=True)
    assert b"Type your password to delete the file." in r.data
    r = revoke(alice, url, bob_id, "a guess", follow_redirects=True)
    assert b"Wrong password: the share stays." in r.data
    r = alice.post(f"{url}/revoke", data={"recipient_id": bob_id}, follow_redirects=True)
    assert b"Type your password to revoke the share." in r.data
    assert download(bob, url).data == CONTRACT
    assert os.path.exists(stored_path(app, url))

    revoke(alice, url, bob_id)
    assert download(bob, url).status_code == 403
    delete(alice, url)
    assert alice.get(url).status_code == 404


def test_wrong_passwords_at_delete_count_toward_the_lock(alice):
    url = new_file(alice)
    for _ in range(5):
        delete(alice, url, "a guess")
    assert delete(alice, url).status_code == 429
    assert alice.get(url).status_code == 200


def test_unknown_file_is_404(alice):
    assert alice.get(f"/files/{uuid.uuid4()}").status_code == 404
    assert alice.get("/files/1").status_code == 404


def test_file_page_names_the_signer(alice):
    assert f"Signature valid, signed by {alice.handle}.".encode() in upload(alice).data


def test_changed_signature_fails_verification(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        f = dict(db.execute("SELECT * FROM files").fetchone())
        signature = bytearray(f["signature"])
        signature[-1] ^= 1
        f["signature"] = bytes(signature)
        # with the master key, the record can get a valid HMAC; the
        # signature itself still does not check out
        db.execute(
            "UPDATE files SET signature = ?, record_mac = ?",
            (f["signature"], record_mac(mac_key(), f)),
        )
        db.commit()

    assert b"the signature is not valid" in alice.get(url).data
    assert download(alice, url).headers["Location"] == url


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
    assert download(bob, url).status_code == 403
    r = bob.post(
        f"{url}/check",
        data={"copy": (io.BytesIO(CONTRACT), "copy.txt")},
        content_type="multipart/form-data",
    )
    assert r.status_code == 403
    assert share(bob, url, bob.handle).status_code == 403
    assert revoke(bob, url, "1").status_code == 403
    assert delete(bob, url).status_code == 403

    assert download(alice, url).data == CONTRACT
    with app.app_context():
        denied = get_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'access' AND outcome = 'denied'"
        ).fetchone()[0]
    assert denied == 6


def test_recipient_can_read_but_not_manage(alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    assert download(bob, url).data == CONTRACT
    assert share(bob, url, bob.handle).status_code == 403
    assert delete(bob, url).status_code == 403


def test_revoked_recipient_loses_access(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    revoke(alice, url, user_id(app, bob.handle))
    assert download(bob, url).status_code == 403


def proof_of(client, url, tmp_path):
    """Unpack a file's signature proof into tmp_path; return its README's
    commands."""
    proof = client.get(f"{url}/proof")
    assert proof.headers["Content-Disposition"].startswith("attachment;")
    with zipfile.ZipFile(io.BytesIO(proof.data)) as z:
        assert sorted(z.namelist()) == ["README.txt", "ca.crt", "signature.sig", "signer.crt"]
        z.extractall(tmp_path)
    readme = (tmp_path / "README.txt").read_text()
    return [line.strip() for line in readme.splitlines() if line.strip().startswith("openssl ")]


def run(command, copy, cwd):
    """One README command, as typed, with FILE replaced by the copy."""
    args = shlex.split(command.replace("FILE", copy))
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def test_signature_proof_checks_out_offline(app, alice, tmp_path):
    url = new_file(alice)
    commands = proof_of(alice, url, tmp_path)
    assert len(commands) == 3
    (tmp_path / "copy.txt").write_bytes(download(alice, url).data)
    results = [run(c, "copy.txt", tmp_path) for c in commands]
    assert [r.returncode for r in results] == [0, 0, 0], [r.stderr for r in results]
    assert results[-1].stdout.strip() == "Verified OK"

    (tmp_path / "copy.txt").write_bytes(CONTRACT.replace(b"40 EUR", b"14 EUR"))
    assert run(commands[-1], "copy.txt", tmp_path).stdout.strip() == "Verification failure"


def test_the_proof_commands_hold_no_file_name(alice, tmp_path):
    name = "q$(touch PWNED).pdf"
    url = new_file(alice, PDF, name)
    commands = proof_of(alice, url, tmp_path)
    for command in commands:
        assert name not in command and "$" not in command and "`" not in command
    (tmp_path / "copy.pdf").write_bytes(download(alice, url).data)
    results = [run(c, "copy.pdf", tmp_path) for c in commands]
    assert results[-1].stdout.strip() == "Verified OK"
    assert not (tmp_path / "PWNED").exists()


def test_signature_proof_needs_access(alice, bob):
    url = new_file(alice)
    assert bob.get(f"{url}/proof").status_code == 403


def test_upload_tells_a_plain_zip_from_a_docx(alice):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("payload.txt", "not a Word document")
    r = upload(alice, buf.getvalue(), name="report.docx")
    assert b"does not match the .docx extension" in r.data


def test_forms_refuse_bad_input(alice):
    r = alice.post(
        "/upload",
        data={"file": (io.BytesIO(CONTRACT), "contract.txt")},
        content_type="multipart/form-data",
    )
    assert b"Type your password to sign the file." in r.data
    r = upload(alice, description="x" * 1001)
    assert b"limited to 1000 characters" in r.data

    url = new_file(alice)
    r = share(alice, url, "", follow_redirects=True)
    assert b"Type a username." in r.data
    assert revoke(alice, url, "1 OR 1=1").status_code == 400


def test_search_terms_stay_out_of_the_url(alice):
    new_file(alice)
    new_file(alice, name="invoice-0412.txt")
    # a query string is ignored: GET always lists everything
    page = alice.get("/", query_string={"q": "invoice"}).data.split(b"Shared with me")[0]
    assert b"contract.txt" in page and b"invoice-0412.txt" in page
    assert b"contract.txt" not in my_files(alice, "invoice")


def test_logged_in_pages_are_never_cached(client, alice):
    assert alice.get("/").headers["Cache-Control"] == "no-store"
    url = new_file(alice)
    assert download(alice, url).headers["Cache-Control"] == "no-store"
    # the stylesheet holds nothing private and may be cached
    assert "no-store" not in client.get("/static/vault.css").headers.get("Cache-Control", "")


def test_deeply_nested_json_and_toml_are_refused_cleanly(alice):
    deep = b"[" * 100_000 + b"]" * 100_000
    assert b"is not valid JSON" in upload(alice, deep, name="deep.json").data
    assert b"is not valid TOML" in upload(alice, b"a = " + deep, name="deep.toml").data


def test_markdown_config_and_json_files(alice):
    for name, data in (
        ("notes.md", b"# Meeting\n\n- sign the contract\n"),
        ("server.cfg", b"[server]\nport = 8443\n"),
        ("export.json", b'{"invoices": [412, 413]}'),
    ):
        assert f"Uploaded {name}.".encode() in upload(alice, data, name=name).data
    assert b"is not valid JSON" in upload(alice, b"{not json", name="broken.json").data
    assert b"must contain UTF-8 text" in upload(alice, b"\xff\xfe", name="notes.md").data
    url = new_file(alice, b'{"invoices": [412]}', name="export2.json")
    r = download(alice, url)
    assert r.mimetype == "application/json"
    assert r.headers["Content-Disposition"].startswith("attachment;")


def test_pages_load_the_form_helpers(alice):
    page = alice.get("/upload").data
    assert b'src="/static/app.js"' in page
    script = alice.get("/static/app.js")
    assert script.status_code == 200 and script.mimetype == "text/javascript"


def test_duress_field_is_not_a_password_field(alice):
    page = alice.get("/auth/duress").data
    field = re.search(rb'<input[^>]*name="duress_password"[^>]*>', page).group(0)
    assert b'type="text"' in field and b"masked" in field and b'autocomplete="off"' in field


def copies_of(app, url):
    with app.app_context():
        return {
            row["user_id"]: row["wrapped_key"]
            for row in get_db().execute(
                "SELECT user_id, wrapped_key FROM file_keys WHERE file_id = ?", (file_id(url),)
            )
        }


def test_only_the_password_opens_a_stored_file(app, alice):
    url = new_file(alice)
    alice_id = user_id(app, alice.handle)
    # nothing in the files table, and nothing the master key derives,
    # opens the file: its key exists only as copies for its readers
    with app.app_context():
        columns = [c["name"] for c in get_db().execute("PRAGMA table_info(files)")]
    assert "wrapped_key" not in columns
    copies = copies_of(app, url)
    assert list(copies) == [alice_id]

    # with the whole server in hand, alice's copy still needs her password
    with app.app_context():
        with pytest.raises(InvalidTag):
            unlock_encryption_key(alice_id, alice.handle, "a guess")
        private_key = unlock_encryption_key(alice_id, alice.handle, PASSWORD)
    file_key = unwrap_file_key(private_key, copies[alice_id], file_id(url), alice_id)
    with open(stored_path(app, url), "rb") as f:
        assert decrypt(file_key, f.read(), file_id(url).encode()) == CONTRACT


def test_guessing_recipients_is_limited(alice, bob):
    url = new_file(alice)
    for i in range(10):
        r = share(alice, url, f"bob#{i:06d}", follow_redirects=True)
        assert b"Unknown user." in r.data
    # each wrong tag was a guess at someone's username
    r = share(alice, url, bob.handle, follow_redirects=True)
    assert b"Too many unknown usernames." in r.data
    assert f"Shared with {bob.handle}.".encode() not in r.data


def test_download_needs_the_right_password(alice):
    url = new_file(alice)
    r = download(alice, url, password="a guess", follow_redirects=True)
    assert CONTRACT not in r.data
    assert b"Wrong password." in r.data
    # counted for the account: after 5 wrong ones even the right password waits
    for _ in range(4):
        download(alice, url, password="a guess")
    assert download(alice, url).status_code == 429


def test_share_needs_the_right_password(app, alice, bob):
    url = new_file(alice)
    r = share(alice, url, bob.handle, password="a guess", follow_redirects=True)
    assert b"Wrong password." in r.data
    assert b"contract.txt" not in shared_with_me(bob)
    assert user_id(app, bob.handle) not in copies_of(app, url)


def test_every_reader_has_their_own_copy(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    copies = copies_of(app, url)
    assert set(copies) == {user_id(app, alice.handle), user_id(app, bob.handle)}
    assert copies[user_id(app, alice.handle)] != copies[user_id(app, bob.handle)]
    # each copy opens only with its own reader's key
    with app.app_context():
        alice_key = unlock_encryption_key(user_id(app, alice.handle), alice.handle, PASSWORD)
    bob_id = user_id(app, bob.handle)
    with pytest.raises(InvalidTag):
        unwrap_file_key(alice_key, copies[bob_id], file_id(url), bob_id)


def test_a_revoked_share_stays_closed_even_if_the_row_comes_back(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    revoke(alice, url, user_id(app, bob.handle))
    assert user_id(app, bob.handle) not in copies_of(app, url)

    # someone with write access to the database brings the share back
    with app.app_context():
        db = get_db()
        db.execute("UPDATE shares SET revoked_at = NULL WHERE file_id = ?", (file_id(url),))
        db.commit()
    r = download(bob, url, follow_redirects=True)
    assert CONTRACT not in r.data
    assert b"You have no key for this file." in r.data


def test_revoking_the_owner_changes_nothing(app, alice):
    url = new_file(alice)
    revoke(alice, url, user_id(app, alice.handle))
    assert download(alice, url).data == CONTRACT


def test_share_with_someone_who_has_no_encryption_key(app, alice, bob):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute("DELETE FROM encryption_keys WHERE user_id = ?", (user_id(app, bob.handle),))
        db.commit()
    r = share(alice, url, bob.handle, follow_redirects=True)
    assert f"{bob.handle} cannot receive files until they log in again.".encode() in r.data
    assert b"contract.txt" not in shared_with_me(bob)


def test_the_saved_login_stays_out_of_the_recipient_field(alice):
    page = alice.get(new_file(alice)).data
    form = page[page.index(b'/share"'):]
    recipient = re.search(rb'<input[^>]*name="username"[^>]*>', form).group(0)
    assert b'autocomplete="off"' in recipient
    hint = f'<input type="text" autocomplete="username" value="{alice.handle}" hidden>'
    assert hint.encode() in form
