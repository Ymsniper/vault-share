import os


def load_or_create_key(path, size=32):
    """Read a random key from path, creating it (mode 600) on first use."""
    try:
        with open(path, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        key = os.urandom(size)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    if len(key) != size:
        raise ValueError(f"{path} should hold {size} bytes, not {len(key)}")
    return key
