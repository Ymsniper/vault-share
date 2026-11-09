import datetime

from flask import current_app

from security.keychain import lock_signing_key
from security.pki import crl_to_pem, issue_certificate, load_ca, make_crl, make_csr, to_pem
from security.signing import generate_key

from .db import get_db


def load_app_ca():
    cfg = current_app.config
    return load_ca(cfg["CA_CERT"], cfg["CA_KEY"], cfg["CA_PASSPHRASE"])


def new_identity(user_id, username, bottom, ca):
    """Give the user a new signing key and a certificate for it from the
    local CA.

    The private key is stored encrypted under bottom, the last of the
    account's private keys (app/levels.py), which every one of its
    passwords reaches, so every session signs with the same certificate.
    It replaces any older one. Returns (key, certificate id); the caller
    commits.
    """
    ca_cert, ca_key = ca
    key = generate_key()
    cert = issue_certificate(make_csr(key, username), ca_cert, ca_key)
    locked = lock_signing_key(bottom, key, f"signing|{user_id}".encode())
    db = get_db()
    db.execute(
        "INSERT INTO signing_keys (user_id, enc_private_key) VALUES (?, ?)"
        " ON CONFLICT (user_id) DO UPDATE SET enc_private_key = excluded.enc_private_key",
        (user_id, locked),
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
