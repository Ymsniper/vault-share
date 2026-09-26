import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


def new_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt(key, data, aad):
    """AES-256-GCM under a fresh random 96-bit nonce, kept in front of the result.

    aad is authenticated but not encrypted: decrypting with any other aad fails.
    """
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt(key, blob, aad):
    """Raises cryptography.exceptions.InvalidTag if blob, key or aad do not match."""
    return AESGCM(key).decrypt(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad)
