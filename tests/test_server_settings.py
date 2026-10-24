import os
import stat

import pytest

from app import create_app, server_settings
from app.db import get_db

from .test_files import my_files, upload


def write(tmp_path, text):
    path = tmp_path / "server.toml"
    path.write_text(text)
    return str(path)


def settings(app, *args):
    return app.test_cli_runner().invoke(args=["server-settings", *args])


def test_defaults_when_there_is_no_file(tmp_path):
    assert server_settings.load(str(tmp_path / "server.toml")) == (
        {"port": 5000, "max_upload_mb": 10}, None
    )


def test_values_from_the_file(tmp_path):
    path = write(tmp_path, "port = 5101\nmax_upload_mb = 25\n")
    assert server_settings.load(path) == ({"port": 5101, "max_upload_mb": 25}, None)


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("port = 80", "port must be a whole number from 1024 to 65535"),
        ("port = 70000", "port must be a whole number from 1024 to 65535"),
        ('port = "5101"', "port must be a whole number"),
        ("port = true", "port must be a whole number"),
        ("max_upload_mb = 0", "max_upload_mb must be a whole number from 1 to 100 MB"),
        ("max_upload_mb = 101", "max_upload_mb must be a whole number from 1 to 100 MB"),
        ("max_upload_mb = 1.5", "max_upload_mb must be a whole number"),
        ("host = '0.0.0.0'", "unknown settings (host)"),
        ("port = ", "cannot be read"),
    ],
)
def test_a_bad_file_falls_back_to_the_defaults(tmp_path, text, reason):
    values, problem = server_settings.load(write(tmp_path, text))
    assert values == {"port": 5000, "max_upload_mb": 10}
    assert reason in problem and "so the defaults are used" in problem


def test_save_checks_then_writes_for_the_owner_only(tmp_path):
    path = str(tmp_path / "server.toml")
    with pytest.raises(ValueError, match="Port must be a whole number from 1024 to 65535"):
        server_settings.save(path, port=22)
    assert not os.path.exists(path)
    assert server_settings.save(path, port=5101) == {"port": 5101, "max_upload_mb": 10}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert server_settings.load(path) == ({"port": 5101, "max_upload_mb": 10}, None)
    server_settings.save(path, max_upload_mb=25)
    assert server_settings.load(path)[0] == {"port": 5101, "max_upload_mb": 25}
    # written to a new file, then moved into place: nothing left behind
    assert sorted(os.listdir(tmp_path)) == ["server.toml"]


def test_the_command_shows_and_changes_the_settings(app):
    assert settings(app).output == "port 5000, uploads up to 10 MB\n"
    r = settings(app, "--port", "5101", "--max-upload-mb", "25")
    assert "Saved: port 5101, uploads up to 25 MB." in r.output
    assert server_settings.load(app.config["SETTINGS_FILE"])[0] == {
        "port": 5101, "max_upload_mb": 25
    }
    with app.app_context():
        row = get_db().execute(
            "SELECT detail FROM audit_log WHERE action = 'settings'"
        ).fetchone()
    assert row["detail"] == "port 5000 to 5101; upload limit 10 MB to 25 MB"
    r = settings(app, "--port", "80")
    assert r.exit_code != 0
    assert "Port must be a whole number from 1024 to 65535." in r.output


def test_the_app_uses_the_file(app, tmp_path):
    server_settings.save(app.config["SETTINGS_FILE"], port=5101, max_upload_mb=2)
    fresh = create_app({k: v for k, v in app.config.items() if k.isupper()
                        and k not in ("PORT", "MAX_UPLOAD_MB", "MAX_CONTENT_LENGTH")})
    assert fresh.config["PORT"] == 5101
    assert fresh.config["MAX_UPLOAD_MB"] == 2
    assert fresh.config["MAX_CONTENT_LENGTH"] == 2 * 1024 * 1024 + 64 * 1024


def test_a_bad_file_does_not_stop_the_app(app, tmp_path):
    path = write(tmp_path, "port = 80\n")
    fresh = create_app({k: v for k, v in app.config.items() if k.isupper()
                        and k not in ("PORT", "MAX_UPLOAD_MB", "MAX_CONTENT_LENGTH")}
                       | {"SETTINGS_FILE": path})
    assert fresh.config["PORT"] == 5000
    assert "so the defaults are used" in fresh.config["SETTINGS_PROBLEM"]


def test_a_smaller_limit_refuses_bigger_files(app, alice):
    server_settings.apply(app, {"port": 5000, "max_upload_mb": 1})
    assert b"Up to 1 MB." in alice.get("/upload").data
    r = upload(alice, b"a" * (1024 * 1024 + 1), name="big.txt")
    assert b"This file is over the 1 MB limit." in r.data
    assert b"No files found." in my_files(alice)
