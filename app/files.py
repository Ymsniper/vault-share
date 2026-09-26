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
from security.integrity import sha256
from security.pki import common_name, load_certificate
from security.signing import load_private_key, sign_digest, verify_digest

from .audit import audit
from .auth import login_required
from .db import get_db

bp = Blueprint("files", __name__)


def storage_path(filename):
    return os.path.join(current_app.config["UPLOAD_FOLDER"], filename)


def get_file(id, owner_only=False):
    """Load a file the current user may use, or stop with 404 or 403.

    The owner may do anything; a user with an active share may only read.
    """
    db = get_db()
    f = db.execute(
        "SELECT f.*, u.username AS owner, c.pem AS cert_pem, c.serial AS cert_serial,"
        " c.not_after AS cert_not_after"
        " FROM files f JOIN users u ON u.id = f.owner_id"
        " JOIN certificates c ON c.id = f.cert_id WHERE f.id = ?",
        (id,),
    ).fetchone()
    if f is None:
        abort(404)
    if f["owner_id"] == g.user["id"]:
        return f
    if not owner_only:
        share = db.execute(
            "SELECT 1 FROM shares"
            " WHERE file_id = ? AND recipient_id = ? AND revoked_at IS NULL",
            (id, g.user["id"]),
        ).fetchone()
        if share is not None:
            return f
    audit("access", "denied", file_id=id, detail=request.endpoint)
    abort(403)


def check_file(f):
    """Decrypt a stored file, then check its hash and its signature.

    Returns (data, error, signer); data is None when a check fails.
    """
    try:
        with open(storage_path(f["filename"]), "rb") as fp:
            data = decrypt(fp.read())
    except FileNotFoundError:
        return None, "Verification failed: the stored file is missing.", None
    except InvalidTag:
        return None, "Verification failed: the stored file was modified.", None
    digest = sha256(data)
    if digest.hex() != f["sha256"]:
        return None, "Verification failed: the file does not match its SHA-256 hash.", None
    signer = signed_by(f, digest)
    if signer is None:
        return None, "Verification failed: the signature is not valid.", None
    return data, None, signer


def signed_by(f, digest):
    """Name of the signer if the file's signature covers digest, else None."""
    cert = load_certificate(f["cert_pem"])
    if not verify_digest(cert.public_key(), f["signature"], digest):
        return None
    return common_name(cert)


@bp.route("/")
@login_required
def index():
    db = get_db()
    q = request.args.get("q", "")
    # instr() rather than LIKE, so % and _ in the search are plain characters
    files = db.execute(
        "SELECT id, filename, size, uploaded_at FROM files"
        " WHERE owner_id = ? AND instr(lower(filename), lower(?)) > 0"
        " ORDER BY uploaded_at DESC, id DESC",
        (g.user["id"], q),
    ).fetchall()
    shared = db.execute(
        "SELECT f.*, u.username AS owner FROM files f"
        " JOIN shares s ON s.file_id = f.id"
        " JOIN users u ON u.id = f.owner_id"
        " WHERE s.recipient_id = ? AND s.revoked_at IS NULL"
        " ORDER BY f.uploaded_at DESC, f.id DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("files/index.html", files=files, shared=shared, q=q)


@bp.route("/upload", methods=("GET", "POST"))
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if file is None or file.filename == "":
            flash("Choose a file to upload.")
            return render_template("files/upload.html")

        data = file.read()
        digest = sha256(data)
        db = get_db()
        signer = db.execute(
            "SELECT k.private_key, c.id AS cert_id FROM user_keys k"
            " JOIN certificates c ON c.user_id = k.user_id"
            " WHERE k.user_id = ? ORDER BY c.id DESC LIMIT 1",
            (g.user["id"],),
        ).fetchone()
        signature = sign_digest(load_private_key(signer["private_key"]), digest)

        with open(storage_path(file.filename), "wb") as out:
            out.write(encrypt(data))

        cur = db.execute(
            "INSERT INTO files"
            " (owner_id, filename, description, mime, size, sha256, signature, cert_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                g.user["id"],
                file.filename,
                request.form.get("description", ""),
                file.mimetype or "application/octet-stream",
                len(data),
                digest.hex(),
                signature,
                signer["cert_id"],
            ),
        )
        db.commit()
        audit("upload", "ok", file_id=cur.lastrowid)
        flash(f"Uploaded {file.filename}.", "success")
        return redirect(url_for("files.detail", id=cur.lastrowid))

    return render_template("files/upload.html")


@bp.route("/files/<int:id>")
@login_required
def detail(id):
    f = get_file(id)
    _, error, signer = check_file(f)
    audit("verify", "failed" if error else "ok", file_id=id, detail=error)
    shares = get_db().execute(
        "SELECT u.id, u.username FROM shares s JOIN users u ON u.id = s.recipient_id"
        " WHERE s.file_id = ? AND s.revoked_at IS NULL ORDER BY u.username",
        (id,),
    ).fetchall()
    return render_template("files/detail.html", f=f, error=error, signer=signer, shares=shares)


@bp.route("/files/<int:id>/download")
@login_required
def download(id):
    f = get_file(id)
    data, error, _ = check_file(f)
    if error is not None:
        audit("download", "refused", file_id=id, detail=error)
        flash(error)
        return redirect(url_for("files.detail", id=id))
    audit("download", "ok", file_id=id)
    return send_file(io.BytesIO(data), mimetype=f["mime"], download_name=f["filename"])


@bp.route("/files/<int:id>/check", methods=("POST",))
@login_required
def check_copy(id):
    f = get_file(id)
    copy = request.files.get("copy")
    if copy is None or copy.filename == "":
        flash("Choose your local copy of the file.")
        return redirect(url_for("files.detail", id=id))

    # hashed in memory only, the copy is never stored
    digest = sha256(copy.read())
    if digest.hex() != f["sha256"]:
        audit("check_copy", "mismatch", file_id=id)
        flash("Your copy is different from the original.")
        return redirect(url_for("files.detail", id=id))

    signer = signed_by(f, digest)
    if signer is None:
        audit("check_copy", "failed", file_id=id, detail="signature not valid")
        flash("Your copy matches the stored hash, but the signature is not valid.")
    else:
        audit("check_copy", "match", file_id=id)
        flash(f"Your copy is identical to the original, signed by {signer}.", "success")
    return redirect(url_for("files.detail", id=id))


@bp.route("/files/<int:id>/share", methods=("POST",))
@login_required
def share(id):
    f = get_file(id, owner_only=True)
    username = request.form["username"]
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        audit("share", "failed", file_id=id, detail="unknown user")
        flash("Unknown user.")
    elif user["id"] == f["owner_id"]:
        flash("The owner already has access.")
    else:
        db.execute(
            "INSERT INTO shares (file_id, recipient_id) VALUES (?, ?)"
            " ON CONFLICT (file_id, recipient_id)"
            " DO UPDATE SET revoked_at = NULL, created_at = datetime('now')",
            (id, user["id"]),
        )
        db.commit()
        audit("share", "ok", file_id=id, detail=f"with {username}")
        flash(f"Shared with {username}.", "success")
    return redirect(url_for("files.detail", id=id))


@bp.route("/files/<int:id>/revoke", methods=("POST",))
@login_required
def revoke(id):
    get_file(id, owner_only=True)
    recipient_id = request.form["recipient_id"]
    db = get_db()
    db.execute(
        "UPDATE shares SET revoked_at = datetime('now')"
        " WHERE file_id = ? AND recipient_id = ? AND revoked_at IS NULL",
        (id, recipient_id),
    )
    db.commit()
    audit("revoke", "ok", file_id=id, detail=f"user {recipient_id}")
    flash("Share revoked.", "success")
    return redirect(url_for("files.detail", id=id))


@bp.route("/files/<int:id>/delete", methods=("POST",))
@login_required
def delete(id):
    f = get_file(id, owner_only=True)
    try:
        os.remove(storage_path(f["filename"]))
    except FileNotFoundError:
        pass
    db = get_db()
    db.execute("DELETE FROM files WHERE id = ?", (id,))
    db.commit()
    audit("delete", "ok", file_id=id)
    flash(f"Deleted {f['filename']}.", "success")
    return redirect(url_for("files.index"))
