import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from .crypto import decrypt, encrypt
from .passwords import derive_key

# ECDSA P-256 over a SHA-256 digest computed by the caller. This gives the
# same signature as ECDSA-SHA256 over the whole file, so OpenSSL can check it.
_ALGORITHM = ec.ECDSA(Prehashed(hashes.SHA256()))


def generate_key():
    return ec.generate_private_key(ec.SECP256R1())


def lock_private_key(key, password, aad):
    """Encrypt the private key under a key derived from the password.

    Returns (salt, blob) to store. The password itself is never stored, so
    the database alone cannot be used to sign in the user's name.
    """
    salt = os.urandom(16)
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return salt, encrypt(derive_key(password, salt), der, aad)


def unlock_private_key(salt, blob, password, aad):
    """Raises cryptography.exceptions.InvalidTag if the password is wrong."""
    der = decrypt(derive_key(password, salt), blob, aad)
    return serialization.load_der_private_key(der, password=None)


def sign_digest(key, digest):
    return key.sign(digest, _ALGORITHM)


def verify_digest(public_key, signature, digest):
    try:
        public_key.verify(signature, digest, _ALGORITHM)
    except InvalidSignature:
        return False
    return True
