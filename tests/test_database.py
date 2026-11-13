"""The database records the version of its layout, and code made for another
version refuses it with a message saying what to do, instead of failing on
a missing column."""
import re
from pathlib import Path

import pytest

from app import create_app
from app.db import SCHEMA_VERSION, OutdatedDatabase, database_problem, get_db, init_db


def set_version(app, version):
    with app.app_context():
        db = get_db()
        db.execute(f"PRAGMA user_version = {int(version)}")
        db.commit()


def elsewhere(app, path):
    """The same app with its database at path."""
    return create_app({**{k: v for k, v in app.config.items() if k.isupper()}, "DATABASE": str(path)})


def test_the_schema_records_the_version_the_code_expects():
    schema = (Path(__file__).parent.parent / "app" / "schema.sql").read_text()
    assert re.search(r"PRAGMA user_version = (\d+);", schema).group(1) == str(SCHEMA_VERSION)


@pytest.mark.parametrize("version, words", [
    (0, "made by an older version of Vault-Share"),
    (SCHEMA_VERSION + 1, "made by a newer version of Vault-Share"),
])
def test_a_database_of_another_version_is_refused(app, version, words):
    set_version(app, version)
    with app.app_context(), pytest.raises(OutdatedDatabase, match=words):
        get_db()
    assert words in database_problem(app)


def test_the_message_says_how_to_reset(app):
    set_version(app, 0)
    message = database_problem(app)
    assert "vault-share init-db" in message and "Setup > Reset database" in message
    assert "deletes every user, file and log entry" in message


def test_a_missing_database_is_not_created(app, tmp_path):
    missing = tmp_path / "not-made-yet.sqlite3"
    other = elsewhere(app, missing)
    assert "no database yet" in database_problem(other)
    assert not missing.exists()


def test_init_db_replaces_an_older_database(app):
    set_version(app, 0)
    with app.app_context():
        init_db()
        assert get_db().execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert database_problem(app) is None


def test_visitors_only_learn_the_service_is_paused(app, client):
    set_version(app, 0)
    r = client.get("/auth/login")
    assert r.status_code == 503 and b"This service is paused." in r.data
    assert b"init-db" not in r.data and b"older version" not in r.data


def test_command_line_tools_say_what_to_do(app):
    set_version(app, 0)
    r = app.test_cli_runner().invoke(args=["admin", "grant", "nobody#123456"])
    assert r.exit_code == 1
    assert "made by an older version of Vault-Share" in r.output and "init-db" in r.output
