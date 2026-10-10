import os
import secrets

from flask import current_app

from security.crypto import decrypt, encrypt
from security.keys import subkey
from security.passwords import hash_password

from .db import get_db
from .identity import write_crl
from .keyring import master_key
from .storage import storage_path

# what the duress password does, stored encrypted and always one byte long,
# so the two modes cannot be told apart in the database
DECOY = b"D"
WIPE = b"W"


def _key(label):
    return subkey(master_key(), label)


def seal_mode(username, mode):
    return encrypt(_key("duress-policy"), mode, f"duress:{username}".encode())


def mode_of(user):
    aad = f"duress:{user['username']}".encode()
    return decrypt(_key("duress-policy"), user["duress_policy"], aad)


def empty_slot(username):
    """What an account without a duress password stores: the hash of a
    random secret nobody knows, and the default mode."""
    return hash_password(secrets.token_urlsafe(32)), seal_mode(username, DECOY)


def seal_login_flag(user_id, duress):
    """Whether a pending two-factor login came from the duress password,
    encrypted so the cookie that carries it does not give it away."""
    return encrypt(_key("login-mode"), b"1" if duress else b"0", f"login:{user_id}".encode())


def login_flag(user_id, blob):
    return decrypt(_key("login-mode"), blob, f"login:{user_id}".encode()) == b"1"


def wipe_account(user):
    """Destroy what belongs to the user: their files, every copy of a file
    key made for them, their private keys, and revoke their certificate.

    Deleting the keys is what matters: a copy of the encrypted files taken
    earlier can no longer be decrypted by anyone, and neither can the
    files others shared with them.
    """
    db = get_db()
    # overwrite deleted rows with zeros instead of leaving them in free pages
    db.execute("PRAGMA secure_delete = ON")
    for row in db.execute("SELECT id FROM files WHERE owner_id = ?", (user["id"],)).fetchall():
        try:
            os.remove(storage_path(row["id"]))
        except FileNotFoundError:
            pass
    # the copies of the keys of their own files go with the files
    db.execute("DELETE FROM files WHERE owner_id = ?", (user["id"],))
    # copies made for them of other people's file keys: with their private
    # key gone these could never open again, so the shares end too
    db.execute("DELETE FROM file_keys WHERE user_id = ?", (user["id"],))
    db.execute(
        "UPDATE shares SET revoked_at = datetime('now')"
        " WHERE recipient_id = ? AND revoked_at IS NULL",
        (user["id"],),
    )
    db.execute("DELETE FROM user_keys WHERE user_id = ?", (user["id"],))
    db.execute("DELETE FROM encryption_keys WHERE user_id = ?", (user["id"],))
    db.execute(
        "UPDATE certificates SET revoked_at = datetime('now')"
        " WHERE user_id = ? AND revoked_at IS NULL",
        (user["id"],),
    )
    db.commit()
    try:
        write_crl()
    except (OSError, ValueError) as e:
        current_app.logger.error("duress wipe: the CRL was not written: %s", e)
