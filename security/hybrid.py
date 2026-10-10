"""Hybrid encryption of file keys.

Each person who may open a file gets their own copy of its key, encrypted
to their X25519 public key with HPKE (RFC 9180). Only their private key,
which their password locks, opens that copy: the server's master key
cannot.
"""

from cryptography.hazmat.primitives import hpke, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

# DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and AES-256-GCM
SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.AES_256_GCM)


def generate_encryption_key():
    return X25519PrivateKey.generate()


def public_bytes(key):
    """The raw 32-byte public key of a private key, as stored."""
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _info(file_id, user_id):
    # ties a copy to one file and one person: moved onto another row of the
    # database, it no longer opens
    return f"fileshare file key|{file_id}|{user_id}".encode()


def wrap_file_key(public_key, file_key, file_id, user_id):
    """The file key encrypted to public_key, the raw 32 bytes."""
    return SUITE.encrypt(
        file_key, X25519PublicKey.from_public_bytes(public_key), _info(file_id, user_id)
    )


def unwrap_file_key(private_key, copy, file_id, user_id):
    """Raises cryptography.exceptions.InvalidTag when the key, the file, the
    person or a single byte of the copy does not match."""
    return SUITE.decrypt(copy, private_key, _info(file_id, user_id))
