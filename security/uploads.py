import unicodedata

import filetype

MAX_SIZE = 10 * 1024 * 1024

# extension: MIME type sent back on download
ALLOWED = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "txt": "text/plain; charset=utf-8",
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
    """Return the MIME type to store for this upload, or raise ValueError.

    The extension must be on the list, and the content must really be that
    type: filetype reads the file's first bytes, so a script renamed to
    .pdf, or a zip renamed to .docx, is refused.
    """
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED:
        raise ValueError("This file type is not allowed. Use PDF, TXT, PNG, JPG, DOCX or XLSX.")
    if ext == "txt":
        # filetype only knows binary formats, so text is checked by decoding it
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("A .txt file must contain UTF-8 text.") from None
        if "\x00" in text:
            raise ValueError("A .txt file must contain UTF-8 text.")
    else:
        kind = filetype.guess(data)
        if kind is None or kind.extension != ("jpg" if ext == "jpeg" else ext):
            raise ValueError(f"The content of this file does not match the .{ext} extension.")
    return ALLOWED[ext]
