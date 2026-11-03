import os
import subprocess
from pathlib import Path

import pytest

from app import auth, create_app, limiter, public_link
from app.db import init_db
from app.invites import create_invite

CA_SCRIPT = Path(__file__).parent.parent / "pki" / "create_ca.sh"
CA_PASSPHRASE = "test passphrase for the CA"


@pytest.fixture(autouse=True)
def no_tailscale(monkeypatch):
    """Tests never ask this machine's real tailscale; test_public_link.py
    puts a fake one in its place."""
    monkeypatch.setattr(public_link, "run", lambda args, timeout=10: None)


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
            # nor the real port and upload limit
            "SETTINGS_FILE": str(tmp_path / "server.toml"),
        }
    )
    with app.app_context():
        init_db()
    # the limiter keeps its counters in memory, shared by every test app,
    # and so do the count of password checks in flight and the locks logged
    limiter.reset()
    auth._in_flight.clear()
    auth._reported.clear()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


PASSWORD = "contract-2026"


def invite_code(app):
    """A new invite code, made at the server as the console does."""
    with app.app_context():
        return create_invite()


def register(client, name="alice", password=PASSWORD):
    """Both steps of registering, with a new invite code; returns the
    username the server made."""
    code = invite_code(client.application)
    r = client.post("/auth/register", data={"code": code, "username": name})
    assert r.headers.get("Location") == "/auth/register/password", r.data
    with client.session_transaction() as s:
        handle = s["new_handle"]
    r = client.post("/auth/register/password", data={"password": password})
    assert r.headers.get("Location") == "/auth/login", r.data
    return handle


def logged_in(app, name):
    """A client registered and logged in; its username is in .handle."""
    c = app.test_client()
    c.handle = register(c, name)
    c.post("/auth/login", data={"username": c.handle, "password": PASSWORD})
    return c


@pytest.fixture
def alice(app):
    return logged_in(app, "alice")


@pytest.fixture
def bob(app):
    return logged_in(app, "bob")
