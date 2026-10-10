import os
import subprocess
from pathlib import Path

import pytest

from app import create_app, limiter
from app.db import init_db

CA_SCRIPT = Path(__file__).parent.parent / "pki" / "create_ca.sh"
CA_PASSPHRASE = "test passphrase for the CA"


@pytest.fixture(scope="session")
def ca_passphrase():
    return CA_PASSPHRASE


@pytest.fixture(scope="session")
def ca_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("ca")
    subprocess.run(
        ["sh", str(CA_SCRIPT), str(out)],
        env={**os.environ, "CA_PASSPHRASE": CA_PASSPHRASE},
        check=True,
        capture_output=True,
    )
    return out


@pytest.fixture(scope="session")
def tls_dir(ca_dir, ca_passphrase, tmp_path_factory):
    """The HTTPS certificate of this machine, issued by the test CA."""
    out = tmp_path_factory.mktemp("tls")
    subprocess.run(
        ["sh", str(CA_SCRIPT.parent / "create_server_cert.sh"), str(ca_dir), str(out)],
        env={**os.environ, "CA_PASSPHRASE": ca_passphrase},
        check=True,
        capture_output=True,
    )
    return out


@pytest.fixture
def test_certs(ca_dir, ca_passphrase, tmp_path):
    """Certificates the app must refuse, made by pki/make_test_certs.sh for alice."""
    out = tmp_path / "test-certs"
    subprocess.run(
        ["sh", str(CA_SCRIPT.parent / "make_test_certs.sh"), "alice", str(ca_dir), str(out)],
        env={**os.environ, "CA_PASSPHRASE": CA_PASSPHRASE},
        check=True,
        capture_output=True,
    )
    return out


@pytest.fixture
def app(tmp_path, ca_dir):
    app = create_app(
        {
            "TESTING": True,
            # tests post forms directly; test_csrf.py turns the check back on
            "WTF_CSRF_ENABLED": False,
            "HTTPS": False,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "STORAGE_FOLDER": str(tmp_path / "storage"),
            "SECRETS_DIR": str(tmp_path / "secrets"),
            "USB_MOUNT_ROOTS": [str(tmp_path / "media")],
            "CA_CERT": str(ca_dir / "ca.crt"),
            "CA_KEY": str(ca_dir / "ca.key"),
            "CA_CRL": str(tmp_path / "crl.pem"),
            "CA_PASSPHRASE": CA_PASSPHRASE,
            # never the real instance/tls, which may hold a certificate
            "TLS_CERT": str(tmp_path / "tls" / "server.crt"),
            "TLS_KEY": str(tmp_path / "tls" / "server.key"),
        }
    )
    with app.app_context():
        init_db()
    # the limiter keeps its counters in memory, shared by every test app
    limiter.reset()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def logged_in(app, username):
    c = app.test_client()
    c.post("/auth/register", data={"username": username, "password": "contract-2026"})
    c.post("/auth/login", data={"username": username, "password": "contract-2026"})
    return c


@pytest.fixture
def alice(app):
    return logged_in(app, "alice")


@pytest.fixture
def bob(app):
    return logged_in(app, "bob")
