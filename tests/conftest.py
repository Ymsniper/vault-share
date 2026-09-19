import pytest

from app import create_app
from app.db import init_db


@pytest.fixture
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
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
