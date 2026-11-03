import datetime

from flask import current_app

from security.hybrid import generate_encryption_key, public_bytes
from security.pki import crl_to_pem, issue_certificate, load_ca, make_crl, make_csr, to_pem
from security.signing import generate_key, lock_private_key, unlock_private_key

from .db import get_db


def load_app_ca():
    cfg = current_app.config
    return load_ca(cfg["CA_CERT"], cfg["CA_KEY"], cfg["CA_PASSPHRASE"])


def new_identity(user_id, username, password, ca):
    """Give the user a new key pair and a certificate for it from the local CA.

    The private key is stored encrypted under a key derived from the
    password, replacing any older one. Returns (key, certificate id); the
    caller commits.
    """
    ca_cert, ca_key = ca
    key = generate_key()
    cert = issue_certificate(make_csr(key, username), ca_cert, ca_key)
    salt, locked_key = lock_private_key(key, password, username.encode())
    db = get_db()
    db.execute(
        "INSERT INTO user_keys (user_id, kdf_salt, enc_private_key) VALUES (?, ?, ?)"
        " ON CONFLICT (user_id) DO UPDATE"
        " SET kdf_salt = excluded.kdf_salt, enc_private_key = excluded.enc_private_key",
        (user_id, salt, locked_key),
    )
    cur = db.execute(
        "INSERT INTO certificates (user_id, serial, pem, not_before, not_after)"
        " VALUES (?, ?, ?, ?, ?)",
        (
            user_id,
            format(cert.serial_number, "x"),
            to_pem(cert),
            cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
            cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    return key, cur.lastrowid


def encryption_aad(username):
    # the signing key is locked with the bare username: a different label,
    # so one locked key can never stand in for the other
    return f"{username}:encryption".encode()


def new_encryption_key(user_id, username, password):
    """Give the user an X25519 key pair for receiving file keys.

    The private key is stored encrypted under a key derived from the
    password, like the signing key. It does not depend on the certificate,
    so renewing or revoking a certificate leaves access to files alone.
    Returns the public key; the caller commits.
    """
    key = generate_encryption_key()
    salt, locked_key = lock_private_key(key, password, encryption_aad(username))
    public_key = public_bytes(key)
    get_db().execute(
        "INSERT INTO encryption_keys (user_id, public_key, kdf_salt, enc_private_key)"
        " VALUES (?, ?, ?, ?) ON CONFLICT (user_id) DO UPDATE"
        " SET public_key = excluded.public_key, kdf_salt = excluded.kdf_salt,"
        " enc_private_key = excluded.enc_private_key",
        (user_id, public_key, salt, locked_key),
    )
    return public_key


def ensure_encryption_key(user_id, username, password):
    """The user's public encryption key, made now if they have none (the
    password has just been checked). Only a duress wipe takes it away."""
    row = get_db().execute(
        "SELECT public_key FROM encryption_keys WHERE user_id = ?", (user_id,)
    ).fetchone()
    if row is not None:
        return row["public_key"]
    public_key = new_encryption_key(user_id, username, password)
    get_db().commit()
    return public_key


def unlock_encryption_key(user_id, username, password):
    """The user's X25519 private key, or None when they have none.

    Raises cryptography.exceptions.InvalidTag when the password is wrong.
    """
    row = get_db().execute(
        "SELECT kdf_salt, enc_private_key FROM encryption_keys WHERE user_id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return None
    return unlock_private_key(
        row["kdf_salt"], row["enc_private_key"], password, encryption_aad(username)
    )


def utc(text):
    """A time from the database, which keeps UTC text."""
    return datetime.datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.UTC)


def write_crl():
    """Publish every revoked certificate in a list signed by the CA, each
    with the time its files fail from."""
    ca_cert, ca_key = load_app_ca()
    revoked = [
        (int(row["serial"], 16), utc(row["revoked_at"]), utc(row["invalid_from"]))
        for row in get_db().execute(
            "SELECT serial, revoked_at, COALESCE(invalid_from, revoked_at) AS invalid_from"
            " FROM certificates WHERE revoked_at IS NOT NULL"
        )
    ]
    path = current_app.config["CA_CRL"]
    with open(path, "wb") as f:
        f.write(crl_to_pem(make_crl(ca_cert, ca_key, revoked)))
    return path
