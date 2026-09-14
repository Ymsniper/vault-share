from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = b"0123456789abcdef0123456789abcdef"
NONCE = bytes(12)


def encrypt(data):
    return AESGCM(KEY).encrypt(NONCE, data, None)


def decrypt(blob):
    """Raises cryptography.exceptions.InvalidTag if the blob was modified."""
    return AESGCM(KEY).decrypt(NONCE, blob, None)
