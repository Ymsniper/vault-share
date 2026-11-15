"""The server's own settings: its port, the largest upload, and the range
new accounts draw their secret number of levels from (app/levels.py).

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

from . import public_link
from .audit import audit
from .keyring import Locked
from .levels import LEVELS

DEFAULTS = {"port": 5000, "max_upload_mb": 10, "min_levels": 16, "max_levels": LEVELS}
# ports under 1024 need root; a file is held in memory while it is hashed,
# encrypted and signed, and again while it is decrypted, so a higher upload
# ceiling would let a few uploads use up the memory. Every account has rows
# for LEVELS levels, so no range goes past it.
LIMITS = {"port": (1024, 65535), "max_upload_mb": (1, 100), "min_levels": (2, LEVELS),
          "max_levels": (2, LEVELS)}
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


def range_problem(settings):
    """A range of one number would let anyone count the levels of every
    account: the smallest must stay below the largest."""
    if settings["min_levels"] >= settings["max_levels"]:
        return "min_levels must be smaller than max_levels"
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
    settings = {**DEFAULTS, **values}
    wrong = range_problem(settings)
    if wrong:
        return dict(DEFAULTS), f"{path}: {wrong}, so the defaults are used"
    return settings, None


def save(path, **changes):
    """Check the new values (keys of DEFAULTS; None keeps a value), then
    write them all: a new file, readable by its owner only, moved into place
    in one step. Returns the settings. Raises ValueError."""
    current, _ = load(path)
    unknown = sorted(set(changes) - set(DEFAULTS))
    if unknown:
        raise ValueError(f"Unknown settings: {', '.join(unknown)}.")
    new = {**current, **{key: value for key, value in changes.items() if value is not None}}
    for key, value in new.items():
        wrong = problem(key, value)
        if wrong:
            raise ValueError(wrong[0].upper() + wrong[1:] + ".")
    wrong = range_problem(new)
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
    return (f"port {settings['port']}, uploads up to {settings['max_upload_mb']} MB,"
            f" {settings['min_levels']} to {settings['max_levels']} levels per new account")


def apply(app, settings):
    """Use new settings at once where that is possible: the upload limit,
    and the range the next accounts are drawn from. The port needs the
    server to start again."""
    app.config["MAX_UPLOAD_MB"] = settings["max_upload_mb"]
    app.config["MAX_CONTENT_LENGTH"] = upload_limit(settings["max_upload_mb"])
    app.config["LEVELS_RANGE"] = (settings["min_levels"], settings["max_levels"])


def log_change(old, new):
    """Write the change to the audit log; False when the database is locked."""
    changes = []
    if old["port"] != new["port"]:
        changes.append(f"port {old['port']} to {new['port']}")
    if old["max_upload_mb"] != new["max_upload_mb"]:
        changes.append(f"upload limit {old['max_upload_mb']} MB to {new['max_upload_mb']} MB")
    span = ("min_levels", "max_levels")
    if any(old[key] != new[key] for key in span):
        changes.append("levels per new account {} to {}, now {} to {}".format(
            *(old[key] for key in span), *(new[key] for key in span)))
    if not changes:
        return True
    try:
        audit("settings", "changed", detail="; ".join(changes), user_id=None)
    except Locked:
        return False
    return True


def offer_link_move(old_port, new_port, https, yes):
    """After a port change: if a Tailscale link pointed at the old port, ask
    whether to move it (yes skips the question)."""
    found = public_link.rules_for(public_link.status(), old_port)
    if not found:
        return
    links = ", ".join(public_link.url_of(r) for r in found)
    question = f"{links} still points at port {old_port}. Move it to {new_port}?"
    if yes or click.confirm(question, default=False):
        click.echo(public_link.move(old_port, new_port, https))
    else:
        click.echo("Left as it is. To move it later: "
                   + public_link.by_hand(found, new_port, https))


@click.command("server-settings")
@click.option("--port", type=int, help="The port the server listens on, 1024 to 65535.")
@click.option("--max-upload-mb", type=int, help="The largest upload, 1 to 100 MB.")
@click.option("--min-levels", type=int,
              help=f"The fewest levels a new account is drawn, 2 to {LEVELS}.")
@click.option("--max-levels", type=int,
              help=f"The most levels a new account is drawn, 2 to {LEVELS}.")
@click.option("--yes", is_flag=True,
              help="Move a Tailscale link that pointed at the old port without asking.")
@with_appcontext
def settings_command(port, max_upload_mb, min_levels, max_levels, yes):
    """Show the server's settings, or change them: the port, the upload
    limit, and the range each new account's secret number of levels is
    drawn from, evenly (a wider range hides more).

    The server only ever listens on 127.0.0.1; reach it from elsewhere
    through a proxy such as Tailscale.
    """
    path = current_app.config["SETTINGS_FILE"]
    old, trouble = load(path)
    if trouble:
        click.echo(trouble)
    if port is None and max_upload_mb is None and min_levels is None and max_levels is None:
        click.echo(describe(old))
        return
    try:
        new = save(path, port=port, max_upload_mb=max_upload_mb, min_levels=min_levels,
                   max_levels=max_levels)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"Saved: {describe(new)}. Start the server again to use them.")
    if not log_change(old, new):
        click.echo("Not in the audit log: the database is locked.")
    if new["port"] != old["port"]:
        offer_link_move(old["port"], new["port"], current_app.config["HTTPS"], yes)
