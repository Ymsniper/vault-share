import io
import os

from app.db import get_db

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
