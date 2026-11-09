from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

# ECDSA P-256 over a SHA-256 digest computed by the caller. This gives the
# same signature as ECDSA-SHA256 over the whole file, so OpenSSL can check it.
_ALGORITHM = ec.ECDSA(Prehashed(hashes.SHA256()))


def generate_key():
    return ec.generate_private_key(ec.SECP256R1())


def sign_digest(key, digest):
    return key.sign(digest, _ALGORITHM)


def verify_digest(public_key, signature, digest):
    try:
        public_key.verify(signature, digest, _ALGORITHM)
    except InvalidSignature:
        return False
    return True
