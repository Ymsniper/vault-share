import io
import os

from cryptography.exceptions import InvalidTag
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from security.crypto import decrypt, encrypt
from security.integrity import sha256_hex

from .auth import login_required
from .db import get_db

bp = Blueprint("files", __name__)


def storage_path(filename):
    return os.path.join(current_app.config["UPLOAD_FOLDER"], filename)


def get_file(id):
    f = get_db().execute(
        "SELECT f.*, u.username AS owner FROM files f"
        " JOIN users u ON u.id = f.owner_id WHERE f.id = ?",
        (id,),
    ).fetchone()
    if f is None:
        abort(404)
    return f


def check_file(f):
    """Decrypt a stored file and compare it with the hash taken at upload.

    Returns (data, error); data is None when a check fails.
    """
    try:
        with open(storage_path(f["filename"]), "rb") as fp:
            data = decrypt(fp.read())
    except FileNotFoundError:
        return None, "Verification failed: the stored file is missing."
    except InvalidTag:
        return None, "Verification failed: the stored file was modified."
    if sha256_hex(data) != f["sha256"]:
        return None, "Verification failed: the file does not match its SHA-256 hash."
    return data, None


@bp.route("/")
@login_required
def index():
    files = get_db().execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC, id DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("files/index.html", files=files)


@bp.route("/upload", methods=("GET", "POST"))
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if file is None or file.filename == "":
            flash("Choose a file to upload.")
            return render_template("files/upload.html")

        data = file.read()
        with open(storage_path(file.filename), "wb") as out:
            out.write(encrypt(data))

        db = get_db()
        cur = db.execute(
            "INSERT INTO files (owner_id, filename, description, mime, size, sha256)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                g.user["id"],
                file.filename,
                request.form.get("description", ""),
                file.mimetype or "application/octet-stream",
                len(data),
                sha256_hex(data),
            ),
        )
        db.commit()
        flash(f"Uploaded {file.filename}.", "success")
        return redirect(url_for("files.detail", id=cur.lastrowid))

    return render_template("files/upload.html")


@bp.route("/files/<int:id>")
@login_required
def detail(id):
    f = get_file(id)
    _, error = check_file(f)
    return render_template("files/detail.html", f=f, error=error)


@bp.route("/files/<int:id>/download")
@login_required
def download(id):
    f = get_file(id)
    data, error = check_file(f)
    if error is not None:
        flash(error)
        return redirect(url_for("files.detail", id=id))
    return send_file(io.BytesIO(data), mimetype=f["mime"], download_name=f["filename"])


@bp.route("/files/<int:id>/delete", methods=("POST",))
@login_required
def delete(id):
    f = get_file(id)
    try:
        os.remove(storage_path(f["filename"]))
    except FileNotFoundError:
        pass
    db = get_db()
    db.execute("DELETE FROM files WHERE id = ?", (id,))
    db.commit()
    flash(f"Deleted {f['filename']}.", "success")
    return redirect(url_for("files.index"))
