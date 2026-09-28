import hashlib
import hmac


def sha256(data):
    return hashlib.sha256(data).digest()


def record_mac(key, file_id, owner_id, digest_hex, size):
    """HMAC-SHA256 over the fields of a file record that must never change.

    None of the fields can contain "|", so the joined message is unambiguous.
    """
    message = f"{file_id}|{owner_id}|{digest_hex}|{size}".encode()
    return hmac.new(key, message, hashlib.sha256).digest()
