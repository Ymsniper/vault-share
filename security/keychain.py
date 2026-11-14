"""The keys of an account's levels.

Each level has an X25519 key pair (security/hybrid.py). A level's private
key is locked under a secret its password gives, and also linked from the
level above it: encrypted under a key derived from the upper level's private
key. So a password opens its own level and every level below it, and
nothing leads back up. The signing key hangs off the lowest level, which
every password reaches.

The aad given to each function ties a lock or a link to one account and
one level: copied onto another row, it no longer opens.
"""
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import NONCE_SIZE, decrypt, encrypt

# a nonce, a 32-byte X25519 private key and the GCM tag
LOCK_SIZE = NONCE_SIZE + 32 + 16


def _raw(key):
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )


def _key_from(upper, aad):
    """A 256-bit key derived from the upper level's private key."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=aad).derive(_raw(upper))


def verifier(master, user_id, row_id):
    """What a credential row keeps of its password: a keyed hash of the one
    Argon2 run over it (security/passwords.derive_master), bound to the
    account and the row. 32 bytes, like the random ones of an unused row."""
    return hmac.new(master, f"verify|{user_id}|{row_id}".encode(), "sha256").digest()


def lock_secret(master, user_id, level):
    """The key a password locks its level's private key with, from the same
    run: a password's checks and keys never need a second one."""
    info = f"lock|{user_id}|{level}".encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


def lock_key(key, secret, aad):
    """The private key encrypted under a password's lock secret."""
    return encrypt(secret, _raw(key), aad)


def unlock_key(lock, secret, aad):
    """Raises cryptography.exceptions.InvalidTag when the secret is not this
    lock's, that is, the password is not."""
    return X25519PrivateKey.from_private_bytes(decrypt(secret, lock, aad))


def unused_lock():
    """Random bytes the length of a lock, for a level without a password:
    in the database it looks like one that has a password."""
    return os.urandom(LOCK_SIZE)


def link_key(upper, lower, aad):
    """The lower level's private key, encrypted under a key derived from
    the upper one's: whoever holds upper can open lower, not the reverse."""
    return encrypt(_key_from(upper, aad), _raw(lower), aad)


def follow_link(upper, link, aad):
    """Raises InvalidTag when upper is not the key the link was made with."""
    return X25519PrivateKey.from_private_bytes(decrypt(_key_from(upper, aad), link, aad))


def lock_signing_key(bottom, signing_key, aad):
    """The ECDSA signing key, encrypted under a key derived from the lowest
    level's private key, so a session at any level signs with it."""
    der = signing_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return encrypt(_key_from(bottom, aad), der, aad)


def unlock_signing_key(bottom, blob, aad):
    """Raises InvalidTag when bottom is not the key it was locked under."""
    return serialization.load_der_private_key(decrypt(_key_from(bottom, aad), blob, aad), None)
