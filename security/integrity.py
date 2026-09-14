import hashlib


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()
