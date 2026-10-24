"""The server's own settings: its port and the largest upload.

They live in instance/server.toml rather than in the database, because the
port is needed before the database can be unlocked (USB stick, passphrase).
Only the console and the command line write the file. The server always
listens on 127.0.0.1: that is not a setting, so the outside world can only
reach it through a proxy such as Tailscale.
"""
import os
import tempfile
import tomllib

import click
from flask import current_app
from flask.cli import with_appcontext

from .audit import audit
from .keyring import Locked

DEFAULTS = {"port": 5000, "max_upload_mb": 10}
# ports under 1024 need root; a file is held in memory while it is hashed,
# encrypted and signed, and again while it is decrypted, so a higher upload
# ceiling would let a few uploads use up the memory
LIMITS = {"port": (1024, 65535), "max_upload_mb": (1, 100)}
# room for the form's other fields around the file
FORM_MARGIN = 64 * 1024

HEADER = """\
# Vault-Share server settings, written by "vault-share server-settings" or the
# console's Setup tab. A new port is used when the server starts again.
"""


def problem(key, value):
    low, high = LIMITS[key]
    # a bool is an int in Python, but "port = true" is no port
    if type(value) is not int or not low <= value <= high:
        unit = " MB" if key == "max_upload_mb" else ""
        return f"{key} must be a whole number from {low} to {high}{unit}"
    return None


def load(path):
    """(settings, problem): the values in the file, or the defaults and why
    the file was not used. Never raises, so a bad file cannot stop the
    console, or the command that would fix it."""
    try:
        with open(path, "rb") as f:
            values = tomllib.load(f)
    except FileNotFoundError:
        return dict(DEFAULTS), None
    except (OSError, tomllib.TOMLDecodeError) as e:
        return dict(DEFAULTS), f"{path} cannot be read ({e}), so the defaults are used"
    unknown = sorted(set(values) - set(DEFAULTS))
    if unknown:
        return dict(DEFAULTS), (f"{path} has unknown settings ({', '.join(unknown)}),"
                                " so the defaults are used")
    for key, value in values.items():
        wrong = problem(key, value)
        if wrong:
            return dict(DEFAULTS), f"{path}: {wrong}, so the defaults are used"
    return {**DEFAULTS, **values}, None


def save(path, port=None, max_upload_mb=None):
    """Check the new values, then write them: a new file, readable by its
    owner only, moved into place in one step. Returns the settings. Raises
    ValueError."""
    current, _ = load(path)
    new = {
        "port": current["port"] if port is None else port,
        "max_upload_mb": current["max_upload_mb"] if max_upload_mb is None else max_upload_mb,
    }
    for key, value in new.items():
        wrong = problem(key, value)
        if wrong:
            raise ValueError(wrong[0].upper() + wrong[1:] + ".")
    # mkstemp creates the file with mode 0600
    fd, temp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".server.toml.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(HEADER + "".join(f"{key} = {value}\n" for key, value in new.items()))
        os.replace(temp, path)
    except BaseException:
        os.remove(temp)
        raise
    return new


def upload_limit(max_upload_mb):
    """The largest request Flask accepts: the file plus the form around it."""
    return max_upload_mb * 1024 * 1024 + FORM_MARGIN


def describe(settings):
    return f"port {settings['port']}, uploads up to {settings['max_upload_mb']} MB"


def apply(app, settings):
    """Use new settings at once where that is possible: the upload limit.
    The port needs the server to start again."""
    app.config["MAX_UPLOAD_MB"] = settings["max_upload_mb"]
    app.config["MAX_CONTENT_LENGTH"] = upload_limit(settings["max_upload_mb"])


def log_change(old, new):
    """Write the change to the audit log; False when the database is locked."""
    changes = []
    if old["port"] != new["port"]:
        changes.append(f"port {old['port']} to {new['port']}")
    if old["max_upload_mb"] != new["max_upload_mb"]:
        changes.append(f"upload limit {old['max_upload_mb']} MB to {new['max_upload_mb']} MB")
    if not changes:
        return True
    try:
        audit("settings", "changed", detail="; ".join(changes), user_id=None)
    except Locked:
        return False
    return True


@click.command("server-settings")
@click.option("--port", type=int, help="The port the server listens on, 1024 to 65535.")
@click.option("--max-upload-mb", type=int, help="The largest upload, 1 to 100 MB.")
@with_appcontext
def settings_command(port, max_upload_mb):
    """Show the server's port and upload limit, or change them.

    The server only ever listens on 127.0.0.1; reach it from elsewhere
    through a proxy such as Tailscale.
    """
    path = current_app.config["SETTINGS_FILE"]
    old, trouble = load(path)
    if trouble:
        click.echo(trouble)
    if port is None and max_upload_mb is None:
        click.echo(describe(old))
        return
    try:
        new = save(path, port, max_upload_mb)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"Saved: {describe(new)}. Start the server again to use them.")
    if not log_change(old, new):
        click.echo("Not in the audit log: the database is locked.")
