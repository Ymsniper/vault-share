"""Small files that start the way real ones do, enough for the upload checks."""
import bz2
import gzip
import io
import lzma
import tarfile
import zipfile


def zipped(entries, first_stored=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if first_stored:
            # OpenDocument: an uncompressed "mimetype" entry must come first
            name, data = first_stored
            z.writestr(zipfile.ZipInfo(name), data, compress_type=zipfile.ZIP_STORED)
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


def office(folder):
    return zipped([("[Content_Types].xml", "<Types/>"), (f"{folder}/main.xml", "<x/>")])


def opendocument(kind):
    return zipped([("content.xml", "<o/>")],
                  ("mimetype", f"application/vnd.oasis.opendocument.{kind}".encode()))


def ftyp(brand):
    return b"\x00\x00\x00\x18ftyp" + brand + b"\x00\x00\x00\x00" + brand + b"isom" + b"\x00" * 16


def ebml(doctype):
    return (b"\x1a\x45\xdf\xa3\xa3\x42\x86\x81\x01\x42\x82"
            + bytes([0x80 | len(doctype)]) + doctype + b"\x00" * 32)


def tar_bytes():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("notes.txt")
        info.size = 5
        t.addfile(info, io.BytesIO(b"hello"))
    return buf.getvalue()


# file name: content, for every type that is checked
CHECKED = {
    "report.pdf": b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n",
    "letter.docx": office("word"),
    "budget.xlsx": office("xl"),
    "slides.pptx": office("ppt"),
    "letter.odt": opendocument("text"),
    "budget.ods": opendocument("spreadsheet"),
    "slides.odp": opendocument("presentation"),
    "chart.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 32,
    "photo.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32,
    "photo.jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 32,
    "loop.gif": b"GIF89a" + b"\x00" * 32,
    "photo.webp": b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 32,
    "scan.bmp": b"BM" + b"\x00" * 64,
    "scan.tif": b"II*\x00\x08\x00\x00\x00" + b"\x00" * 32,
    "scan.tiff": b"II*\x00\x08\x00\x00\x00" + b"\x00" * 32,
    "photo.heic": ftyp(b"heic"),
    "memo.mp3": b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 32,
    "memo.wav": b"RIFF\x24\x00\x00\x00WAVEfmt " + b"\x00" * 32,
    "memo.ogg": b"OggS\x00\x02" + b"\x00" * 40,
    "memo.flac": b"fLaC\x00\x00\x00\x22" + b"\x00" * 40,
    "memo.m4a": ftyp(b"M4A "),
    "clip.mp4": ftyp(b"isom"),
    "clip.mov": ftyp(b"qt  "),
    "clip.webm": ebml(b"webm"),
    "clip.mkv": ebml(b"matroska"),
    "clip.avi": b"RIFF\x24\x00\x00\x00AVI LIST" + b"\x00" * 32,
    "notes.txt": b"Delivery in March.\n",
    "notes.md": b"# Delivery\n\nIn March.\n",
    "orders.csv": b"item,units\nbolts,1200\n",
    "data.json": b'{"units": 1200}',
    "app.toml": b'name = "vault"\n',
    "app.yaml": b"name: vault\n",
    "app.yml": b"name: vault\n",
    "app.ini": b"[main]\nname = vault\n",
    "app.cfg": b"name = vault\n",
    "server.log": b"12:00 started\n",
}

# file name: content, for archives: their signature is checked, not what is inside
ARCHIVES = {
    "bundle.zip": zipped([("notes.txt", "hello")]),
    "bundle.7z": b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\x00" * 32,
    "bundle.rar": b"Rar!\x1a\x07\x01\x00" + b"\x00" * 32,
    "bundle.tar": tar_bytes(),
    "bundle.tar.gz": gzip.compress(tar_bytes()),
    "bundle.tgz": gzip.compress(tar_bytes()),
    "notes.txt.gz": gzip.compress(b"hello"),
    "notes.txt.bz2": bz2.compress(b"hello"),
    "notes.txt.xz": lzma.compress(b"hello"),
}

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 64
EXE = b"MZ" + b"\x00" * 64
