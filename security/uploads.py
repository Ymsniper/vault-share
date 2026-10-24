import json
import tomllib
import unicodedata

import filetype

MAX_SIZE = 10 * 1024 * 1024

# what filetype may find in a file of that extension, or TEXT for formats
# with no signature, checked by decoding them instead
TEXT = "text"

# extension: (group, MIME type sent back on download, what is accepted inside)
TYPES = {
    "pdf": ("Documents", "application/pdf", {"pdf"}),
    "docx": ("Documents",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
             {"docx"}),
    "xlsx": ("Documents",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", {"xlsx"}),
    "pptx": ("Documents",
             "application/vnd.openxmlformats-officedocument.presentationml.presentation",
             {"pptx"}),
    "odt": ("Documents", "application/vnd.oasis.opendocument.text", {"odt"}),
    "ods": ("Documents", "application/vnd.oasis.opendocument.spreadsheet", {"ods"}),
    "odp": ("Documents", "application/vnd.oasis.opendocument.presentation", {"odp"}),
    "png": ("Images", "image/png", {"png", "apng"}),
    "jpg": ("Images", "image/jpeg", {"jpg"}),
    "jpeg": ("Images", "image/jpeg", {"jpg"}),
    "gif": ("Images", "image/gif", {"gif"}),
    "webp": ("Images", "image/webp", {"webp"}),
    "bmp": ("Images", "image/bmp", {"bmp"}),
    "tif": ("Images", "image/tiff", {"tif"}),
    "tiff": ("Images", "image/tiff", {"tif"}),
    "heic": ("Images", "image/heic", {"heic"}),
    "mp3": ("Audio", "audio/mpeg", {"mp3"}),
    "wav": ("Audio", "audio/wav", {"wav"}),
    "ogg": ("Audio", "audio/ogg", {"ogg"}),
    "flac": ("Audio", "audio/flac", {"flac"}),
    # MP4 audio and video share a container, and phones mix the brands
    "m4a": ("Audio", "audio/mp4", {"m4a", "mp4"}),
    "mp4": ("Video", "video/mp4", {"mp4", "m4v"}),
    "mov": ("Video", "video/quicktime", {"mov", "mp4"}),
    "webm": ("Video", "video/webm", {"webm"}),
    "mkv": ("Video", "video/x-matroska", {"mkv"}),
    "avi": ("Video", "video/x-msvideo", {"avi"}),
    "txt": ("Text", "text/plain; charset=utf-8", TEXT),
    "md": ("Text", "text/markdown; charset=utf-8", TEXT),
    "csv": ("Text", "text/csv; charset=utf-8", TEXT),
    "json": ("Text", "application/json", TEXT),
    "toml": ("Text", "text/plain; charset=utf-8", TEXT),
    "yaml": ("Text", "text/plain; charset=utf-8", TEXT),
    "yml": ("Text", "text/plain; charset=utf-8", TEXT),
    "ini": ("Text", "text/plain; charset=utf-8", TEXT),
    "cfg": ("Text", "text/plain; charset=utf-8", TEXT),
    "log": ("Text", "text/plain; charset=utf-8", TEXT),
}

# Archives: their signature is checked, so a program renamed .zip is still
# refused, but not what they hold, so they are marked Not checked.
# extension: (MIME type sent back on download, what is accepted inside)
ARCHIVES = {
    # documents built on zip are zips too
    "zip": ("application/zip", {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"}),
    "7z": ("application/x-7z-compressed", {"7z"}),
    "rar": ("application/vnd.rar", {"rar"}),
    "tar": ("application/x-tar", {"tar"}),
    "gz": ("application/gzip", {"gz"}),
    "tgz": ("application/gzip", {"gz"}),
    "bz2": ("application/x-bzip2", {"bz2"}),
    "xz": ("application/x-xz", {"xz"}),
}

# Left out on purpose: doc, xls, ppt and rtf can carry macros or embedded
# objects, and html, svg, xml, scripts and programs run code when opened.
# They can still be shared inside an archive, marked Not checked.


def type_groups():
    """The allowed extensions by group, in the table's order, for the page."""
    groups = {}
    for ext, (group, _, _) in TYPES.items():
        groups.setdefault(group, []).append(ext)
    return groups


def accept_list():
    """The extensions for the file picker's accept attribute."""
    return ",".join(f".{ext}" for ext in [*TYPES, *ARCHIVES])


def clean_name(name):
    """The client's file name without any path or control characters.

    Only used for display and as the name of the download, never as a
    path on disk.
    """
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if unicodedata.category(c)[0] != "C")
    return name.strip()[:255]


def check_text(ext, data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"A .{ext} file must contain UTF-8 text.") from None
    if "\x00" in text:
        raise ValueError(f"A .{ext} file must contain UTF-8 text.")
    if ext == "json":
        try:
            json.loads(text)
        except ValueError:
            raise ValueError("This .json file is not valid JSON.") from None
    if ext == "toml":
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            raise ValueError("This .toml file is not valid TOML.") from None


def check_signature(ext, data, inside):
    kind = filetype.guess(data)
    if kind is None or kind.extension not in inside:
        raise ValueError(f"The content of this file does not match the .{ext} extension.")


def check_upload(name, data):
    """Return (MIME type to store, whether the content was checked), or
    raise ValueError.

    The extension must be on one of the lists, and the content must really
    be that type: filetype reads the file's first bytes, so a script renamed
    to .pdf, or a program renamed to .zip, is refused. An archive passes that
    check too, but what it holds is not looked at: it is not checked.
    """
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in ARCHIVES:
        mime, inside = ARCHIVES[ext]
        check_signature(ext, data, inside)
        return mime, False
    if ext not in TYPES:
        raise ValueError(
            "This file type is not allowed. The types that are, and why some are not,"
            " are under Checked on the upload page."
        )
    _, mime, inside = TYPES[ext]
    if inside == TEXT:
        check_text(ext, data)
    else:
        check_signature(ext, data, inside)
    return mime, True
