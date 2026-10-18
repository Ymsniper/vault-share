import os
import stat
import subprocess
from pathlib import Path

from cryptography import x509

from app import create_app
from app.db import get_db, init_db
from security.pki import common_name, load_certificate

PKI = Path(__file__).parent.parent / "pki"


def openssl_verify(ca_cert, cert_path):
    r = subprocess.run(
        ["openssl", "verify", "-CAfile", str(ca_cert), str(cert_path)],
        capture_output=True,
        text=True,
    )
    return r.returncode, r.stdout + r.stderr


def test_ca_script_makes_an_encrypted_ca(ca_dir):
    key = (ca_dir / "ca.key").read_text()
    assert key.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert stat.S_IMODE(os.stat(ca_dir / "ca.key").st_mode) == 0o600

    ca = x509.load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign


def test_ca_script_refuses_to_overwrite(ca_dir, ca_passphrase):
    r = subprocess.run(
        ["sh", str(PKI / "create_ca.sh"), str(ca_dir)],
        env={**os.environ, "CA_PASSPHRASE": ca_passphrase},
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0
    assert "not overwriting" in r.stderr


def test_registration_issues_a_certificate(app, ca_dir, tmp_path, alice):
    with app.app_context():
        pem = get_db().execute("SELECT pem FROM certificates").fetchone()["pem"]
    cert = load_certificate(pem)
    assert common_name(cert) == alice.handle
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 365
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and not usage.key_cert_sign

    (tmp_path / "alice.crt").write_text(pem)
    code, out = openssl_verify(ca_dir / "ca.crt", tmp_path / "alice.crt")
    assert code == 0, out


def test_registration_needs_the_ca(tmp_path, ca_dir):
    app = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "HTTPS": False,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "STORAGE_FOLDER": str(tmp_path / "storage"),
            "SECRETS_DIR": str(tmp_path / "secrets"),
            "CA_CERT": str(ca_dir / "ca.crt"),
            "CA_KEY": str(ca_dir / "ca.key"),
            "CA_CRL": str(tmp_path / "crl.pem"),
            "CA_PASSPHRASE": "not the passphrase",
        }
    )
    with app.app_context():
        init_db()
    client = app.test_client()
    client.post("/auth/register", data={"username": "alice"})
    r = client.post("/auth/register/password", data={"password": "contract-2026"})
    assert b"the certificate authority is not set up" in r.data
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_test_certs_are_refused_by_openssl(ca_dir, ca_passphrase, tmp_path):
    out = tmp_path / "test-certs"
    subprocess.run(
        ["sh", str(PKI / "make_test_certs.sh"), "alice", str(ca_dir), str(out)],
        env={**os.environ, "CA_PASSPHRASE": ca_passphrase},
        check=True,
        capture_output=True,
    )

    code, msg = openssl_verify(ca_dir / "ca.crt", out / "expired.crt")
    assert code != 0 and "certificate has expired" in msg
    code, msg = openssl_verify(ca_dir / "ca.crt", out / "rogue.crt")
    assert code != 0 and "unable to get local issuer certificate" in msg
    assert common_name(load_certificate((out / "rogue.crt").read_text())) == "alice"
