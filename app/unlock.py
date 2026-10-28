import glob
import hashlib
import os

import click
from flask import Blueprint, current_app, flash, g, redirect, render_template, url_for
from flask.cli import AppGroup
from flask_limiter.util import get_remote_address

from security.passwords import derive_key, passphrase_problem

from .audit import audit
from .auth import password_limit
from .forms import UnlockForm, first_error
from .keyring import (
    USB_KEY_FILE,
    Locked,
    combine,
    get_keyring,
    recovery_code,
    reencrypt,
    share_from_recovery_code,
)

bp = Blueprint("unlock", __name__)
keys_cli = AppGroup("keys", help="The factors the master key is made of. Stop the app first.")


class FactorError(Exception):
    """A change of factors that cannot be made, with a message for the operator."""


def _unlock(keyring, passphrase=None, usb_share=None):
    try:
        return keyring.unlock(passphrase, usb_share)
    except Locked as e:
        raise FactorError(str(e)) from None


def _change(keyring, config, usb_share, passphrase_key):
    """Move the data to the master key made of these factors, then save them."""
    old = keyring.master()
    new = combine(keyring.machine, usb_share, passphrase_key)
    try:
        reencrypt(current_app.config["DATABASE"], old, new)
    except ValueError as e:
        raise FactorError(f"nothing was changed: {e}") from None
    keyring.save(config, new)


def mounted_sticks():
    """Folders where removable drives are mounted, to offer for add_usb."""
    found = []
    for root in current_app.config["USB_MOUNT_ROOTS"]:
        for path in sorted(glob.glob(os.path.join(root, "*"))) + sorted(
            glob.glob(os.path.join(root, "*", "*"))
        ):
            if os.path.isdir(path) and os.access(path, os.W_OK) and os.path.ismount(path):
                found.append(path)
    return found


def add_usb(mountpoint, passphrase=None):
    """Require the stick mounted at mountpoint. Returns its recovery code."""
    keyring = get_keyring()
    if keyring.needs_usb:
        raise FactorError("a USB stick is already required; remove it first")
    _, passphrase_key = _unlock(keyring, passphrase)
    share = os.urandom(32)
    path = os.path.join(mountpoint, USB_KEY_FILE)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise FactorError(f"{path} already exists; remove it first") from None
    with os.fdopen(fd, "wb") as f:
        f.write(share)
    config = {**keyring.config, "usb": {"fingerprint": hashlib.sha256(share).hexdigest()}}
    try:
        _change(keyring, config, share, passphrase_key)
    except Exception:
        os.remove(path)
        raise
    return recovery_code(share)


def remove_usb(passphrase=None, recovery=None):
    """Stop requiring the stick; without the stick, the recovery code stands in."""
    keyring = get_keyring()
    if not keyring.needs_usb:
        raise FactorError("no USB stick is required")
    share = keyring.find_usb_share()
    if share is None:
        if not recovery:
            raise FactorError("the stick is not plugged in: the recovery code is needed")
        try:
            share = share_from_recovery_code(recovery)
        except ValueError:
            raise FactorError("that is not a recovery code") from None
    _, passphrase_key = _unlock(keyring, passphrase, share)
    config = {k: v for k, v in keyring.config.items() if k not in ("usb", "check")}
    _change(keyring, config, None, passphrase_key)


def set_passphrase(new_passphrase):
    """Require a passphrase after every start."""
    keyring = get_keyring()
    if keyring.needs_passphrase:
        raise FactorError("a passphrase is already required; remove it first")
    problem = passphrase_problem(new_passphrase)
    if problem is not None:
        raise FactorError(problem)
    usb_share, _ = _unlock(keyring)
    salt = os.urandom(16)
    config = {**keyring.config, "passphrase": {"salt": salt.hex()}}
    _change(keyring, config, usb_share, derive_key(new_passphrase, salt))


def remove_passphrase(passphrase):
    keyring = get_keyring()
    if not keyring.needs_passphrase:
        raise FactorError("no passphrase is required")
    usb_share, _ = _unlock(keyring, passphrase)
    config = {k: v for k, v in keyring.config.items() if k not in ("passphrase", "check")}
    _change(keyring, config, usb_share, None)


def _run(action, *args):
    try:
        return action(*args)
    except FactorError as e:
        raise click.ClickException(str(e)) from None


def _ask_passphrase():
    if get_keyring().needs_passphrase:
        return click.prompt("Passphrase", hide_input=True)
    return None


@keys_cli.command("status")
def status_command():
    """Show which factors the master key needs."""
    keyring = get_keyring()
    click.echo(f"USB stick: {'required' if keyring.needs_usb else 'not used'}")
    click.echo(f"Passphrase: {'required' if keyring.needs_passphrase else 'not used'}")


@keys_cli.command("add-usb")
@click.argument("mountpoint", type=click.Path(exists=True, file_okay=False, writable=True))
def add_usb_command(mountpoint):
    """Require the USB stick mounted at MOUNTPOINT from now on."""
    code = _run(add_usb, mountpoint, _ask_passphrase())
    click.echo("The USB stick is now required: without it the app stays locked.")
    click.echo("Write down this recovery code and keep it away from the stick. It")
    click.echo("replaces the stick if you lose it, so guard it like the stick itself:")
    click.echo(code)


@keys_cli.command("remove-usb")
def remove_usb_command():
    """Stop requiring the USB stick. Without the stick, asks for the recovery code."""
    recovery = None
    keyring = get_keyring()
    if keyring.needs_usb and keyring.find_usb_share() is None:
        recovery = click.prompt("The stick is not plugged in. Recovery code")
    _run(remove_usb, _ask_passphrase(), recovery)
    click.echo("The USB stick is no longer required; its key file is now useless.")


@keys_cli.command("set-passphrase")
def set_passphrase_command():
    """Require a passphrase, typed at /unlock after every start."""
    if get_keyring().needs_passphrase:
        raise click.ClickException("a passphrase is already required; run remove-passphrase first")
    passphrase = click.prompt("New passphrase", hide_input=True, confirmation_prompt=True)
    _run(set_passphrase, passphrase)
    click.echo("The passphrase is now required after every start of the app.")


@keys_cli.command("remove-passphrase")
def remove_passphrase_command():
    """Stop requiring the passphrase."""
    if not get_keyring().needs_passphrase:
        raise click.ClickException("no passphrase is required")
    _run(remove_passphrase, click.prompt("Passphrase", hide_input=True))
    click.echo("The passphrase is no longer required.")


# for the operator only: no page links here, and visitors of a locked app
# only see that the service is paused
@bp.route("/unlock", methods=("GET", "POST"))
# nothing goes to the audit log: the database is closed while locked
@password_limit(get_remote_address, scope="unlock", log=False)
def unlock():
    keyring = get_keyring()
    if not keyring.locked:
        return redirect(url_for("files.index"))
    form = UnlockForm()
    if not form.is_submitted():
        return render_template("unlock.html")
    if not form.validate():
        flash(first_error(form))
        return render_template("unlock.html")
    try:
        keyring.unlock(form.passphrase.data)
    except Locked as e:
        # a missing stick is not a guess, a wrong passphrase with the stick in is
        g.wrong_password = not keyring.needs_usb or keyring.find_usb_share() is not None
        flash(str(e))
        return render_template("unlock.html")
    audit("unlock", "ok", user_id=None)
    flash("Unlocked. Everyone has to log in again.", "success")
    return redirect(url_for("auth.login"))
