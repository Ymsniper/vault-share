import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from app.db import get_db
from security.signing import load_private_key, sign_digest

from .test_files import CONTRACT, file_id, new_file

PKI = Path(__file__).parent.parent / "pki"


@pytest.fixture
def test_certs(ca_dir, ca_passphrase, tmp_path):
    out = tmp_path / "test-certs"
    subprocess.run(
        ["sh", str(PKI / "make_test_certs.sh"), "alice", str(ca_dir), str(out)],
        env={**os.environ, "CA_PASSPHRASE": ca_passphrase},
        check=True,
        capture_output=True,
    )
    return out


def private_key_of(app, username):
    with app.app_context():
        pem = get_db().execute(
            "SELECT k.private_key FROM user_keys k JOIN users u ON u.id = k.user_id"
            " WHERE u.username = ?",
            (username,),
        ).fetchone()[0]
    return load_private_key(pem)


def resign(app, url, key, cert_pem=None):
    """Replace a file's signature, and maybe its certificate, as an attacker
    with write access to the database would."""
    with app.app_context():
        db = get_db()
        f = db.execute("SELECT sha256, cert_id FROM files WHERE id = ?", (file_id(url),)).fetchone()
        signature = sign_digest(key, bytes.fromhex(f["sha256"]))
        db.execute("UPDATE files SET signature = ? WHERE id = ?", (signature, file_id(url)))
        if cert_pem is not None:
            db.execute("UPDATE certificates SET pem = ? WHERE id = ?", (cert_pem, f["cert_id"]))
        db.commit()


def page(client, url):
    return client.get(url).data


def test_owner_changed_in_the_database(app, alice, bob):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET owner_id = (SELECT id FROM users WHERE username = 'bob')")
        db.commit()
    assert b"record of this file was changed in the database" in page(bob, url)
    assert CONTRACT not in bob.get(f"{url}/download", follow_redirects=True).data


def test_signature_by_another_user_is_refused(app, alice, bob):
    url = new_file(alice)
    resign(app, url, private_key_of(app, "bob"))
    assert b"the signature is not valid" in page(alice, url)


def test_certificate_of_another_user_is_refused(app, alice, bob):
    url = new_file(alice)
    with app.app_context():
        bob_cert = get_db().execute(
            "SELECT c.pem FROM certificates c JOIN users u ON u.id = c.user_id"
            " WHERE u.username = 'bob'"
        ).fetchone()[0]
    resign(app, url, private_key_of(app, "bob"), bob_cert)
    assert b"the certificate belongs to someone else" in page(alice, url)


def test_expired_certificate_is_refused(app, alice, test_certs):
    url = new_file(alice)
    key = load_pem_private_key((test_certs / "expired.key").read_bytes(), None)
    resign(app, url, key, (test_certs / "expired.crt").read_text())
    assert b"the certificate has expired or is not valid yet" in page(alice, url)


def test_certificate_from_an_unknown_ca_is_refused(app, alice, test_certs):
    url = new_file(alice)
    key = load_pem_private_key((test_certs / "rogue.key").read_bytes(), None)
    resign(app, url, key, (test_certs / "rogue.crt").read_text())
    assert b"the certificate was not issued by the local CA" in page(alice, url)
    assert alice.get(f"{url}/download").headers["Location"] == url


def test_revoked_certificate_is_refused(app, alice):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE certificates SET revoked_at = datetime('now')")
        db.commit()
    assert b"the certificate was revoked" in page(alice, url)


def test_valid_file_still_passes(alice):
    url = new_file(alice)
    assert b"Integrity verified. Signature valid, signed by alice." in page(alice, url)
