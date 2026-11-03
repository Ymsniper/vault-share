import hashlib
import hmac


def sha256(data):
    return hashlib.sha256(data).digest()


# every column of a file record but the HMAC itself
FIELDS = (
    "id", "owner_id", "sha256", "size", "mime", "checked", "uploaded_at",
    "filename", "description", "signature", "cert_id",
)


def record_mac(key, record):
    """HMAC-SHA256 over every field of a file record, so editing any of
    them in the database is detected: the owner, the hash, the type and the
    checked mark (an archive cannot pass for a checked file), the upload
    time the signature is judged at, the name, the description, the
    signature and the certificate.

    Each field goes in as its length, a colon and its bytes, so no value
    can run into the next, whatever a name or a description holds.
    """
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for name in FIELDS:
        value = record[name]
        data = value if isinstance(value, bytes) else str(value).encode()
        mac.update(b"%d:" % len(data) + data)
    return mac.digest()
