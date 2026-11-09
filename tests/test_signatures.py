import io
import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from app.db import get_db
from app.files import mac_key
from security.integrity import record_mac
from security.signing import sign_digest

from .test_files import CONTRACT, download, file_id, new_file, signing_key


def private_key_of(app, username, password="contract-2026"):
    return signing_key(app, username, password)


def resign(app, url, key, cert_pem=None):
    """Replace a file's signature, and maybe its certificate, as an attacker
    with write access to the database and the master key would: the record
    gets a valid HMAC, so only the certificate checks are left to catch it."""
    with app.app_context():
        db = get_db()
        f = dict(db.execute("SELECT * FROM files WHERE id = ?", (file_id(url),)).fetchone())
        f["signature"] = sign_digest(key, bytes.fromhex(f["sha256"]))
        db.execute(
            "UPDATE files SET signature = ?, record_mac = ? WHERE id = ?",
            (f["signature"], record_mac(mac_key(), f), file_id(url)),
        )
        if cert_pem is not None:
            db.execute("UPDATE certificates SET pem = ? WHERE id = ?", (cert_pem, f["cert_id"]))
        db.commit()


def page(client, url):
    return client.get(url).data


def test_owner_changed_in_the_database(app, alice, bob):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE files SET owner_id = (SELECT id FROM users WHERE username = ?)",
            (bob.handle,),
        )
        db.commit()
    assert b"record of this file was changed in the database" in page(bob, url)
    assert CONTRACT not in download(bob, url, follow_redirects=True).data


def test_signature_by_another_user_is_refused(app, alice, bob):
    url = new_file(alice)
    resign(app, url, private_key_of(app, bob.handle))
    assert b"the signature is not valid" in page(alice, url)


def test_a_signature_swapped_without_the_master_key_breaks_the_record(app, alice, bob):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        f = db.execute("SELECT sha256 FROM files").fetchone()
        signature = sign_digest(private_key_of(app, bob.handle), bytes.fromhex(f["sha256"]))
        db.execute("UPDATE files SET signature = ?", (signature,))
        db.commit()
    assert b"record of this file was changed in the database" in page(alice, url)


def test_certificate_of_another_user_is_refused(app, alice, bob):
    url = new_file(alice)
    with app.app_context():
        bob_cert = get_db().execute(
            "SELECT c.pem FROM certificates c JOIN users u ON u.id = c.user_id"
            " WHERE u.username = ?",
            (bob.handle,),
        ).fetchone()[0]
    resign(app, url, private_key_of(app, bob.handle), bob_cert)
    assert b"the certificate belongs to someone else" in page(alice, url)


def test_expired_certificate_is_refused(app, alice, test_certs):
    url = new_file(alice)
    key = load_pem_private_key((test_certs / "expired.key").read_bytes(), None)
    resign(app, url, key, (test_certs / "expired.crt").read_text())
    assert b"the certificate was not valid when the file was uploaded" in page(alice, url)


def test_certificate_from_an_unknown_ca_is_refused(app, alice, test_certs):
    url = new_file(alice)
    key = load_pem_private_key((test_certs / "rogue.key").read_bytes(), None)
    resign(app, url, key, (test_certs / "rogue.crt").read_text())
    assert b"the certificate was not issued by the local CA" in page(alice, url)
    assert download(alice, url).headers["Location"] == url


def test_revoked_certificate_is_refused(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        # revoked for every file it signed
        db.execute("UPDATE certificates SET revoked_at = datetime('now'), invalid_from = not_before")
        db.commit()
    assert b"the certificate was revoked" in page(alice, url)


def test_valid_file_still_passes(alice):
    url = new_file(alice)
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in page(alice, url)


def test_private_keys_are_stored_encrypted(app, alice):
    with app.app_context():
        db = get_db()
        signing = db.execute("SELECT enc_private_key FROM signing_keys").fetchone()[0]
        locks = [r[0] for r in db.execute("SELECT lock FROM credentials")]
    assert b"PRIVATE KEY" not in signing
    assert all(len(lock) == 60 for lock in locks)
    with pytest.raises(InvalidTag):
        private_key_of(app, alice.handle, "wrong password!")
    assert private_key_of(app, alice.handle)


def upload_with_password(client, password):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(CONTRACT), "contract.txt"), "password": password},
        content_type="multipart/form-data",
    )


def test_upload_with_the_wrong_password_signs_nothing(app, alice):
    r = upload_with_password(alice, "not my password")
    assert b"Wrong password: your signing key stays locked" in r.data
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert os.listdir(app.config["STORAGE_FOLDER"]) == []


def test_wrong_upload_passwords_count_toward_the_lock(alice):
    for _ in range(5):
        upload_with_password(alice, "not my password")
    r = upload_with_password(alice, "contract-2026")
    assert b"Too many failed attempts" in r.data
