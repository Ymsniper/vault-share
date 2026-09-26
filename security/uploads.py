import unicodedata

MAX_SIZE = 10 * 1024 * 1024

# extension: MIME type sent back on download, and the bytes the file must
# start with (None for text, which is checked by decoding it instead)
ALLOWED = {
    "pdf": ("application/pdf", b"%PDF-"),
    "png": ("image/png", b"\x89PNG\r\n\x1a\n"),
    "jpg": ("image/jpeg", b"\xff\xd8\xff"),
    "jpeg": ("image/jpeg", b"\xff\xd8\xff"),
    "docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        b"PK\x03\x04",
    ),
    "xlsx": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        b"PK\x03\x04",
    ),
    "txt": ("text/plain; charset=utf-8", None),
}


def clean_name(name):
    """The client's file name without any path or control characters.

    Only used for display and as the name of the download, never as a
    path on disk.
    """
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if unicodedata.category(c)[0] != "C")
    return name.strip()[:255]


def check_upload(name, data):
    """Return the MIME type to store for this upload, or raise ValueError."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        raise ValueError("This file type is not allowed. Use PDF, TXT, PNG, JPG, DOCX or XLSX.")
    mime, magic = ALLOWED[ext]
    if magic is None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("A .txt file must contain UTF-8 text.") from None
        if "\x00" in text:
            raise ValueError("A .txt file must contain UTF-8 text.")
    elif not data.startswith(magic):
        raise ValueError(f"The content of this file does not match the .{ext} extension.")
    return mime
