import os
import tempfile

import pytest

from app import create_app
from app.db import init_db


@pytest.fixture
def app():
    fd, path = tempfile.mkstemp()
    app = create_app({"TESTING": True, "DATABASE": path})
    with app.app_context():
        init_db()

    yield app

    os.close(fd)
    os.unlink(path)


@pytest.fixture
def client(app):
    return app.test_client()
