import os
import subprocess
from pathlib import Path

import pytest

from app import create_app
from app.db import init_db

CA_SCRIPT = Path(__file__).parent.parent / "pki" / "create_ca.sh"
CA_PASSPHRASE = "test passphrase for the CA"


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


@pytest.fixture
def app(tmp_path, ca_dir):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "CA_CERT": str(ca_dir / "ca.crt"),
            "CA_KEY": str(ca_dir / "ca.key"),
            "CA_PASSPHRASE": CA_PASSPHRASE,
        }
    )
    with app.app_context():
        init_db()
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
