import os
import stat

from app import create_app


def test_secret_key_is_random_and_private(app):
    path = os.path.join(app.config["SECRETS_DIR"], "secret_key")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    with open(path, "rb") as f:
        assert f.read() == app.config["SECRET_KEY"]
    assert len(app.config["SECRET_KEY"]) == 32


def test_secret_key_survives_a_restart(app):
    restarted = create_app(
        {
            "TESTING": True,
            "DATABASE": app.config["DATABASE"],
            "STORAGE_FOLDER": app.config["STORAGE_FOLDER"],
            "SECRETS_DIR": app.config["SECRETS_DIR"],
        }
    )
    assert restarted.config["SECRET_KEY"] == app.config["SECRET_KEY"]


def test_each_install_gets_its_own_key(app, tmp_path):
    other = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "other.sqlite3"),
            "STORAGE_FOLDER": str(tmp_path / "other-storage"),
            "SECRETS_DIR": str(tmp_path / "other-secrets"),
        }
    )
    assert other.config["SECRET_KEY"] != app.config["SECRET_KEY"]
