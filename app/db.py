import os

import click
from flask import current_app, g
from sqlcipher3 import dbapi2 as sqlcipher

from security.keys import subkey

from .keyring import master_key


# the version of the tables schema.sql makes, which it writes into the
# database as PRAGMA user_version; code for one version refuses the others
SCHEMA_VERSION = 1

RESET = ("Reset it with vault-share init-db, or Setup > Reset database in the console;"
         " that deletes every user, file and log entry.")


class OutdatedDatabase(click.ClickException):
    """The database cannot be used by this code: there is none yet, or it was
    made for another version of the tables. Command-line tools print the
    message; the console shows it; visitors see the paused page."""

    def __init__(self, state, message):
        super().__init__(message)
        self.state = state


def outdated(version):
    if version is None:
        return OutdatedDatabase(
            "not created yet",
            "There is no database yet: vault-share init-db creates it, or Setup > Reset"
            " database in the console.",
        )
    if version < SCHEMA_VERSION:
        return OutdatedDatabase(
            "made by an older version",
            f"The database was made by an older version of Vault-Share, which this one"
            f" cannot use. {RESET}",
        )
    return OutdatedDatabase(
        "made by a newer version",
        "The database was made by a newer version of Vault-Share: update this copy to use it.",
    )


def _open():
    # SQLCipher encrypts the whole file with AES-256, so usernames, file
    # names, shares and the audit log are unreadable without the master
    # key. PRAGMA takes no parameters; the key is our own hex string.
    key = subkey(master_key(), "database")
    db = sqlcipher.connect(current_app.config["DATABASE"])
    db.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
    db.row_factory = sqlcipher.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def get_db():
    """The request's connection to the database, or OutdatedDatabase when
    there is none yet, which it does not create, or when it was made for
    another version of the tables."""
    if "db" not in g:
        if not os.path.exists(current_app.config["DATABASE"]):
            raise outdated(None)
        db = _open()
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            db.close()
            raise outdated(version)
        g.db = db
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    # start from a new file: dropping tables is not enough to replace an
    # older, unencrypted database
    close_db()
    path = current_app.config["DATABASE"]
    if os.path.exists(path):
        os.remove(path)
    db = _open()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode())
    g.db = db


def database_problem(app):
    """Why this code cannot use the app's database, or None. The app must be
    unlocked; the console and vault-share serve ask this after unlocking."""
    with app.app_context():
        try:
            get_db()
        except OutdatedDatabase as e:
            return e.message
    return None


@click.command("init-db")
def init_db_command():
    """Delete the database and create an empty, encrypted one."""
    init_db()
    click.echo("Database initialized.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
