import base64
import glob
import hashlib
import hmac
import json
import os
import threading
import time

import click
from flask import current_app, has_request_context
from sqlcipher3 import dbapi2 as sqlcipher

from security.crypto import decrypt, encrypt
from security.integrity import record_mac
from security.keys import load_or_create_key, subkey
from security.passwords import derive_key

USB_KEY_FILE = "fileshare-usb.key"


class Locked(Exception):
    """The master key is not in memory: the USB stick or the passphrase is missing."""


def combine(machine, usb_share=None, passphrase_key=None):
    """The master key from its factors.

    The machine key alone is the master key, as before any factor is added.
    With a USB stick or a passphrase, HKDF mixes all of them, so no factor
    alone gives anything away.
    """
    if usb_share is None and passphrase_key is None:
        return machine
    names = [n for n, part in (("usb", usb_share), ("passphrase", passphrase_key)) if part]
    material = machine + (usb_share or b"") + (passphrase_key or b"")
    return subkey(material, "master:" + "+".join(names))


def check_value(master):
    """Kept on disk to tell right factors from wrong ones; it reveals nothing
    about the master key."""
    return hmac.new(master, b"keyring check", hashlib.sha256).hexdigest()


def recovery_code(share):
    text = base64.b32encode(share).decode().rstrip("=")
    return "-".join(text[i : i + 4] for i in range(0, len(text), 4))


def share_from_recovery_code(code):
    """Raises ValueError (binascii.Error) for anything that is not a code."""
    text = code.replace("-", "").replace(" ", "").upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


class Keyring:
    """Where the master key comes from, and whether the app is locked."""

    def __init__(self, secrets_dir, mount_roots):
        self.secrets_dir = secrets_dir
        self.mount_roots = mount_roots
        self.machine = load_or_create_key(os.path.join(secrets_dir, "master.key"))
        self.config = self._read_config()
        self._master = None
        self._guard = threading.Lock()
        if not self.needs_usb and not self.needs_passphrase:
            self._set(combine(self.machine))
        elif not self.needs_passphrase and self.find_usb_share() is not None:
            self.unlock()

    @property
    def _config_path(self):
        return os.path.join(self.secrets_dir, "keyring.json")

    def _read_config(self):
        try:
            with open(self._config_path) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    @property
    def needs_usb(self):
        return bool(self.config.get("usb"))

    @property
    def needs_passphrase(self):
        return bool(self.config.get("passphrase"))

    @property
    def locked(self):
        return self._master is None

    def master(self):
        with self._guard:
            master = self._master
        if master is None:
            raise Locked(self.missing())
        return bytes(master)

    def missing(self):
        if self.needs_usb and self.find_usb_share() is None:
            return "Plug in the key USB stick."
        return "Type the passphrase to unlock."

    def _set(self, master):
        with self._guard:
            self._master = bytearray(master)

    def lock(self):
        """Forget the master key. Python may keep other copies in memory, so
        this is best effort, but from now on nothing can use the key."""
        with self._guard:
            if self._master is not None:
                for i in range(len(self._master)):
                    self._master[i] = 0
            self._master = None

    def find_usb_share(self):
        """The key file of the right stick if one is mounted, else None."""
        if not self.needs_usb:
            return None
        for root in self.mount_roots:
            # /media/LABEL, or /run/media/USER/LABEL as udisks mounts sticks
            for depth in ("*", os.path.join("*", "*")):
                for path in glob.glob(os.path.join(root, depth, USB_KEY_FILE)):
                    try:
                        with open(path, "rb") as f:
                            share = f.read(64)
                    except OSError:
                        continue
                    if hashlib.sha256(share).hexdigest() == self.config["usb"]["fingerprint"]:
                        return share
        return None

    def unlock(self, passphrase=None, usb_share=None):
        """Rebuild the master key from the factors. Returns them as
        (usb_share, passphrase_key), or raises Locked."""
        if self.needs_usb:
            usb_share = usb_share or self.find_usb_share()
            if usb_share is None:
                raise Locked("Plug in the key USB stick.")
        else:
            usb_share = None
        passphrase_key = None
        if self.needs_passphrase:
            if not passphrase:
                raise Locked("Type the passphrase to unlock.")
            salt = bytes.fromhex(self.config["passphrase"]["salt"])
            passphrase_key = derive_key(passphrase, salt)
        master = combine(self.machine, usb_share, passphrase_key)
        if self.config and not hmac.compare_digest(check_value(master), self.config["check"]):
            raise Locked("Wrong passphrase, or not the right USB stick.")
        self._set(master)
        return usb_share, passphrase_key

    def save(self, config, master):
        """Switch to a new set of factors, once the data has been moved to master."""
        path = self._config_path
        if config:
            config = {**config, "check": check_value(master)}
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(config, f, indent=2)
            os.replace(tmp, path)
        elif os.path.exists(path):
            os.remove(path)
        self.config = config
        self._set(master)

    def poll(self, app):
        """One look at the USB port: lock when the stick is gone, unlock when
        it is back, unless a passphrase is needed too (the Locked page asks)."""
        if not self.needs_usb:
            return
        share = self.find_usb_share()
        if share is None and not self.locked:
            # log everyone out first, while the database can still be opened
            end_all_sessions(app.config["DATABASE"], self.master())
            self.lock()
            app.logger.warning("the key USB stick was removed: the app is locked")
        elif share is not None and self.locked and not self.needs_passphrase:
            self.unlock(usb_share=share)
            app.logger.warning("the key USB stick is back: the app is unlocked")

    def watch(self, app, interval=1.0):
        """Poll the USB port in the background for as long as the app runs."""

        def loop():
            while True:
                time.sleep(interval)
                try:
                    self.poll(app)
                except Exception:
                    app.logger.exception("checking the key USB stick failed")

        threading.Thread(target=loop, name="usb-watch", daemon=True).start()


def connect(database, master):
    db = sqlcipher.connect(database)
    db.row_factory = sqlcipher.Row
    db.execute(f"PRAGMA key = \"x'{subkey(master, 'database').hex()}'\"")
    return db


def end_all_sessions(database, master):
    if not os.path.exists(database):
        return
    db = connect(database, master)
    try:
        db.execute("DELETE FROM sessions")
        db.commit()
    finally:
        db.close()


def get_keyring():
    return current_app.extensions["keyring"]


def master_key():
    """The master key, or Locked. Command-line tools ask for what is missing."""
    keyring = get_keyring()
    if keyring.locked and not has_request_context():
        passphrase = None
        if keyring.needs_passphrase:
            passphrase = click.prompt("Passphrase", hide_input=True)
        try:
            keyring.unlock(passphrase)
        except Locked as e:
            raise click.ClickException(str(e)) from None
    return keyring.master()


def reencrypt(database, old, new):
    """Move everything that depends on the master key from old to new.

    The database key, the wrapped file keys, the record HMACs, the TOTP
    secrets and the duress modes change; the encrypted files on disk do not,
    which is what makes changing the master key cheap. The new database is
    built beside the old one and replaces it only once it is complete.
    """
    if not os.path.exists(database):
        return
    fresh = database + ".new"
    if os.path.exists(fresh):
        os.remove(fresh)
    db = connect(database, old)
    try:
        attach_path = fresh.replace("'", "''")
        new_key = subkey(new, "database").hex()
        db.execute(f"ATTACH DATABASE '{attach_path}' AS fresh KEY \"x'{new_key}'\"")
        db.execute("SELECT sqlcipher_export('fresh')")

        old_wrap, new_wrap = subkey(old, "file-key-wrap"), subkey(new, "file-key-wrap")
        old_mac, new_mac = subkey(old, "file-record-hmac"), subkey(new, "file-record-hmac")
        for f in db.execute("SELECT * FROM fresh.files").fetchall():
            fields = (f["id"], f["owner_id"], f["sha256"], f["size"])
            # a record edited behind the app's back must not get a valid new HMAC
            if not hmac.compare_digest(record_mac(old_mac, *fields), f["record_mac"]):
                raise ValueError(f"the record of file {f['id']} was changed in the database")
            aad = f["id"].encode()
            file_key = decrypt(old_wrap, f["wrapped_key"], aad)
            db.execute(
                "UPDATE fresh.files SET wrapped_key = ?, record_mac = ? WHERE id = ?",
                (encrypt(new_wrap, file_key, aad), record_mac(new_mac, *fields), f["id"]),
            )

        old_totp, new_totp = subkey(old, "totp-secret"), subkey(new, "totp-secret")
        old_mode, new_mode = subkey(old, "duress-policy"), subkey(new, "duress-policy")
        for u in db.execute("SELECT * FROM fresh.users").fetchall():
            totp = u["totp_secret"]
            if totp is not None:
                aad = f"totp:{u['id']}".encode()
                totp = encrypt(new_totp, decrypt(old_totp, totp, aad), aad)
            aad = f"duress:{u['username']}".encode()
            mode = encrypt(new_mode, decrypt(old_mode, u["duress_policy"], aad), aad)
            db.execute(
                "UPDATE fresh.users SET totp_secret = ?, duress_policy = ? WHERE id = ?",
                (totp, mode, u["id"]),
            )
        db.commit()
        db.execute("DETACH DATABASE fresh")
    except Exception:
        db.close()
        if os.path.exists(fresh):
            os.remove(fresh)
        raise
    db.close()
    os.replace(fresh, database)
