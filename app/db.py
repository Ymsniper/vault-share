import os

import click
from flask import current_app, g
from sqlcipher3 import dbapi2 as sqlcipher

from security.keys import subkey


def get_db():
    if "db" not in g:
        g.db = sqlcipher.connect(current_app.config["DATABASE"])
        # SQLCipher encrypts the whole file with AES-256, so usernames, file
        # names, shares and the audit log are unreadable without the master
        # key. PRAGMA takes no parameters; the key is our own hex string.
        key = subkey(current_app.config["MASTER_KEY"], "database")
        g.db.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
        g.db.row_factory = sqlcipher.Row
        g.db.execute("PRAGMA foreign_keys = ON")
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
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode())


@click.command("init-db")
def init_db_command():
    """Delete the database and create an empty, encrypted one."""
    init_db()
    click.echo("Database initialized.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
