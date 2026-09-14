import os

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, url_for

from security.crypto import encrypt
from security.integrity import sha256_hex

from .auth import login_required
from .db import get_db

bp = Blueprint("files", __name__)


def storage_path(filename):
    return os.path.join(current_app.config["UPLOAD_FOLDER"], filename)


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
        return redirect(url_for("files.index"))

    return render_template("files/upload.html")
