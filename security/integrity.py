import hashlib
import hmac


def sha256(data):
    return hashlib.sha256(data).digest()


def record_mac(key, file_id, owner_id, digest_hex, size, mime, checked, uploaded_at):
    """HMAC-SHA256 over the fields of a file record that must never change.

    The type and the checked mark are in it too, so an archive cannot be
    turned into a checked file in the database, and so is the upload time,
    which the signature is judged at. None of the fields can contain "|",
    so the joined message is unambiguous.
    """
    message = (
        f"{file_id}|{owner_id}|{digest_hex}|{size}|{mime}|{int(checked)}|{uploaded_at}".encode()
    )
    return hmac.new(key, message, hashlib.sha256).digest()
