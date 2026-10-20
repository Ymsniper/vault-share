import hmac
import io
import os
import uuid
import zipfile

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

from security.crypto import decrypt, encrypt, new_key
from security.hybrid import unwrap_file_key, wrap_file_key
from security.integrity import record_mac, sha256
from security.passwords import check_password
from security.keys import subkey
from security.pki import (
    certificate_problem,
    listed_in_crl,
    load_ca_certificate,
    load_certificate,
)
from security.signing import sign_digest, unlock_private_key, verify_digest
from security.uploads import check_upload, clean_name

from .audit import audit
from .auth import login_required, password_limit
from .db import get_db
from .forms import (
    CheckCopyForm,
    DownloadForm,
    RevokeForm,
    SearchForm,
    ShareForm,
    UploadForm,
    first_error,
)
from .identity import ensure_encryption_key, load_app_ca, new_identity, unlock_encryption_key
from .keyring import master_key
from .storage import storage_path

bp = Blueprint("files", __name__)


def mac_key():
    return subkey(master_key(), "file-record-hmac")


def mac_of(f):
    return record_mac(mac_key(), f["id"], f["owner_id"], f["sha256"], f["size"])


def get_file(id, owner_only=False):
    """Load a file the current user may use, or stop with 404 or 403.

    The owner may do anything; a user with an active share may only read.
    """
    if g.duress:
        # the decoy account holds no files at all
        abort(404)
    id = str(id)
    db = get_db()
    f = db.execute(
        "SELECT f.*, u.username AS owner, u.banned_at AS owner_banned_at,"
        " c.pem AS cert_pem, c.serial AS cert_serial,"
        " c.not_after AS cert_not_after, c.revoked_at AS cert_revoked_at"
        " FROM files f JOIN users u ON u.id = f.owner_id"
        " JOIN certificates c ON c.id = f.cert_id WHERE f.id = ?",
        (id,),
    ).fetchone()
    if f is None:
        abort(404)
    if f["owner_id"] == g.user["id"]:
        return f
    # the files of a banned owner are hidden from everyone they shared with
    if not owner_only and f["owner_banned_at"] is None:
        share = db.execute(
            "SELECT 1 FROM shares"
            " WHERE file_id = ? AND recipient_id = ? AND revoked_at IS NULL",
            (id, g.user["id"]),
        ).fetchone()
        if share is not None:
            return f
    audit("access", "denied", file_id=id, detail=request.endpoint)
    abort(403)


def record_problem(f):
    """Why the record of a file cannot be trusted, or None.

    Checks the HMAC over its fields and the owner's signature over its
    recorded hash. No file key is needed, so the file page can show this;
    the content itself is checked by open_file at every download.
    """
    # the hash alone proves nothing if whoever edits the database can also
    # rewrite it, but the HMAC needs the master key, which is not in there
    if not hmac.compare_digest(mac_of(f), f["record_mac"]):
        return "the record of this file was changed in the database"
    return signature_problem(f, bytes.fromhex(f["sha256"]))


def my_file_key(f, password):
    """The file's key, from the current user's own copy opened with their password.

    Returns (key, error). A wrong password counts toward the same lockout
    as a failed login.
    """
    user = g.user
    try:
        private_key = unlock_encryption_key(user["id"], user["username"], password)
    except InvalidTag:
        private_key, password_ok = None, False
    else:
        # no encryption key at all (only after a duress wipe): the password
        # is still checked, so it cannot be guessed here for free
        password_ok = private_key is not None or check_password(user["password_hash"], password)
    if not password_ok:
        g.wrong_password = True
        return None, "Wrong password."
    copy = get_db().execute(
        "SELECT wrapped_key FROM file_keys WHERE file_id = ? AND user_id = ?",
        (f["id"], user["id"]),
    ).fetchone()
    if private_key is None or copy is None:
        return None, "You have no key for this file. Ask its owner to share it again."
    try:
        return unwrap_file_key(private_key, copy["wrapped_key"], f["id"], user["id"]), None
    except InvalidTag:
        return None, "Verification failed: your copy of the file's key was modified."


def open_file(f, file_key):
    """Decrypt a stored file, then check it against its record.

    Returns (data, error); data is None when a check fails.
    """
    problem = record_problem(f)
    if problem is not None:
        return None, f"Verification failed: {problem}."
    # the file ID is the associated data, so a file moved onto another
    # file's record no longer decrypts
    try:
        with open(storage_path(f["id"]), "rb") as fp:
            data = decrypt(file_key, fp.read(), f["id"].encode())
    except FileNotFoundError:
        return None, "Verification failed: the stored file is missing."
    except InvalidTag:
        return None, "Verification failed: the stored file was modified."
    # the signature covers the recorded hash, so the content must match it
    if not hmac.compare_digest(sha256(data).hex(), f["sha256"]):
        return None, "Verification failed: the file does not match its SHA-256 hash."
    return data, None


def signature_problem(f, digest):
    """Why the owner's signature does not cover digest, or None if it does.

    The certificate is checked first: a valid signature means nothing
    unless the local CA vouches that the key belongs to the file's owner.
    """
    cert = load_certificate(f["cert_pem"])
    ca_cert = load_ca_certificate(current_app.config["CA_CERT"])
    problem = certificate_problem(cert, ca_cert, f["owner"])
    if problem is not None:
        return problem
    if f["cert_revoked_at"] is not None:
        return "the certificate was revoked"
    # the CA-signed list also catches a revocation erased from the database
    crl_path = current_app.config["CA_CRL"]
    if os.path.exists(crl_path):
        with open(crl_path, "rb") as fp:
            try:
                if listed_in_crl(cert, fp.read(), ca_cert):
                    return "the certificate was revoked"
            except ValueError as e:
                return str(e)
    if not verify_digest(cert.public_key(), f["signature"], digest):
        return "the signature is not valid"
    return None


@bp.route("/", methods=("GET", "POST"))
@login_required
def index():
    db = get_db()
    # a POST, so search terms never end up in URLs, server logs or the
    # browser history; a plain GET lists everything
    form = SearchForm()
    q = form.q.data if form.validate_on_submit() else ""
    if g.duress:
        # the decoy account owns nothing and nothing is shared with it
        return render_template("files/index.html", files=[], shared=[], q=q)
    # instr() rather than LIKE, so % and _ in the search are plain characters
    files = db.execute(
        "SELECT id, filename, size, uploaded_at FROM files"
        " WHERE owner_id = ? AND instr(lower(filename), lower(?)) > 0"
        " ORDER BY uploaded_at DESC",
        (g.user["id"], q),
    ).fetchall()
    shared = db.execute(
        "SELECT f.*, u.username AS owner FROM files f"
        " JOIN shares s ON s.file_id = f.id"
        " JOIN users u ON u.id = f.owner_id"
        " WHERE s.recipient_id = ? AND s.revoked_at IS NULL AND u.banned_at IS NULL"
        " ORDER BY f.uploaded_at DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("files/index.html", files=files, shared=shared, q=q)


@bp.route("/upload", methods=("GET", "POST"))
@login_required
@password_limit(lambda: g.user["username"] if g.user else "")
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        # files over MAX_CONTENT_LENGTH never get here, Flask answers 413
        name = clean_name(file.filename)
        data = file.read()
        try:
            mime = check_upload(name, data)
        except ValueError as e:
            audit("upload", "refused", detail=str(e))
            flash(str(e))
            return render_template("files/upload.html")

        if g.duress:
            # the decoy account accepts nothing, and says nothing about why
            audit("upload", "refused", detail="duress session")
            flash("The upload failed. Try again later.")
            return render_template("files/upload.html")

        # the password unlocks the signing key, so a wrong one counts
        # toward the same lockout as a failed login
        username = g.user["username"]
        password = form.password.data
        db = get_db()
        signer = db.execute(
            "SELECT k.kdf_salt, k.enc_private_key, c.id AS cert_id, c.pem AS cert_pem,"
            " c.revoked_at FROM user_keys k"
            " JOIN certificates c ON c.user_id = k.user_id"
            " WHERE k.user_id = ? ORDER BY c.id DESC LIMIT 1",
            (g.user["id"],),
        ).fetchone()
        key = None
        if signer is None:
            # the private key was destroyed by a duress wipe: check the
            # password against the account, a new key pair follows below
            password_ok = check_password(g.user["password_hash"], password)
        else:
            try:
                key = unlock_private_key(
                    signer["kdf_salt"], signer["enc_private_key"], password, username.encode()
                )
                password_ok = True
            except InvalidTag:
                password_ok = False
        if not password_ok:
            g.wrong_password = True
            audit("upload", "refused", detail="wrong password")
            flash("Wrong password: your signing key stays locked and nothing was uploaded.")
            return render_template("files/upload.html")

        if signer is None:
            renew = True
        else:
            cert_id = signer["cert_id"]
            ca_cert = load_ca_certificate(current_app.config["CA_CERT"])
            cert_problem = certificate_problem(
                load_certificate(signer["cert_pem"]), ca_cert, username
            )
            renew = signer["revoked_at"] is not None or cert_problem is not None
        if renew:
            # no usable certificate (revoked, expired, or wiped together with
            # the key): a new key pair, locked with the password just typed
            try:
                key, cert_id = new_identity(g.user["id"], username, password, load_app_ca())
            except (OSError, ValueError) as e:
                current_app.logger.error("cannot load the CA: %s", e)
                flash(
                    "Your certificate needs renewing, but the certificate authority is not set up."
                )
                return render_template("files/upload.html")
            audit("renew_certificate", "ok")

        file_id = str(uuid.uuid4())
        digest = sha256(data)
        signature = sign_digest(key, digest)

        # a new random key for every file, kept only as copies encrypted to
        # the public keys of the people who may open it: for now the owner
        file_key = new_key()
        with open(storage_path(file_id), "wb") as out:
            out.write(encrypt(file_key, data, file_id.encode()))
        owner_public_key = ensure_encryption_key(g.user["id"], username, password)
        mac = record_mac(mac_key(), file_id, g.user["id"], digest.hex(), len(data))

        db.execute(
            "INSERT INTO files"
            " (id, owner_id, filename, description, mime, size, sha256, record_mac,"
            " signature, cert_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                file_id,
                g.user["id"],
                name,
                form.description.data or "",
                mime,
                len(data),
                digest.hex(),
                mac,
                signature,
                cert_id,
            ),
        )
        db.execute(
            "INSERT INTO file_keys (file_id, user_id, wrapped_key) VALUES (?, ?, ?)",
            (
                file_id,
                g.user["id"],
                wrap_file_key(owner_public_key, file_key, file_id, g.user["id"]),
            ),
        )
        db.commit()
        audit("upload", "ok", file_id=file_id)
        flash(f"Uploaded {name}.", "success")
        return redirect(url_for("files.detail", id=file_id))
    elif form.is_submitted():
        flash(first_error(form))

    return render_template("files/upload.html")


@bp.route("/files/<uuid:id>")
@login_required
def detail(id):
    f = get_file(id)
    problem = record_problem(f)
    error = f"Verification failed: {problem}." if problem else None
    audit("verify", "failed" if error else "ok", file_id=f["id"], detail=error)
    shares = get_db().execute(
        "SELECT u.id, u.username FROM shares s JOIN users u ON u.id = s.recipient_id"
        " WHERE s.file_id = ? AND s.revoked_at IS NULL ORDER BY u.username",
        (f["id"],),
    ).fetchall()
    return render_template("files/detail.html", f=f, error=error, shares=shares)


@bp.route("/files/<uuid:id>/download", methods=("POST",))
@login_required
@password_limit(lambda: g.user["username"] if g.user else "")
def download(id):
    f = get_file(id)
    form = DownloadForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    # the password unlocks this user's private key for this request only,
    # so a stolen session cookie alone cannot download anything
    file_key, error = my_file_key(f, form.password.data)
    if error is None:
        data, error = open_file(f, file_key)
    if error is not None:
        audit("download", "refused", file_id=f["id"], detail=error)
        flash(error)
        return redirect(url_for("files.detail", id=f["id"]))
    audit("download", "ok", file_id=f["id"])
    # always a download with the type picked at upload, never shown inline,
    # so even a file with HTML inside cannot run as part of the site
    return send_file(
        io.BytesIO(data), mimetype=f["mime"], as_attachment=True, download_name=f["filename"]
    )


PROOF_README = """\
Check that {name} was signed by {owner}, without the web app:

1. The signer's certificate was issued by the local CA:
   openssl verify -CAfile ca.crt signer.crt

2. Take the public key out of the certificate:
   openssl x509 -in signer.crt -pubkey -noout > signer.pub

3. The signature matches your copy of the file:
   openssl dgst -sha256 -verify signer.pub -signature "{name}.sig" "{name}"
"""


@bp.route("/files/<uuid:id>/proof")
@login_required
def proof(id):
    """Signature, signer certificate and CA certificate, to check a copy offline."""
    f = get_file(id)
    with open(current_app.config["CA_CERT"], "rb") as fp:
        ca_pem = fp.read()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{f['filename']}.sig", f["signature"])
        z.writestr("signer.crt", f["cert_pem"])
        z.writestr("ca.crt", ca_pem)
        z.writestr("README.txt", PROOF_README.format(name=f["filename"], owner=f["owner"]))
    buf.seek(0)
    audit("download_proof", "ok", file_id=f["id"])
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{f['filename']}.proof.zip",
    )


@bp.route("/files/<uuid:id>/check", methods=("POST",))
@login_required
def check_copy(id):
    f = get_file(id)
    form = CheckCopyForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    copy = form.copy.data

    # hashed in memory only, the copy is never stored
    digest = sha256(copy.read())
    if not hmac.compare_digest(digest.hex(), f["sha256"]):
        audit("check_copy", "mismatch", file_id=f["id"])
        flash("Your copy is different from the original.")
        return redirect(url_for("files.detail", id=f["id"]))

    # the copy matches the recorded hash, so the record's checks cover it
    problem = record_problem(f)
    if problem is not None:
        audit("check_copy", "failed", file_id=f["id"], detail=problem)
        flash(f"Your copy matches the stored hash, but {problem}.")
    else:
        audit("check_copy", "match", file_id=f["id"])
        flash(f"Your copy is identical to the original, signed by {f['owner']}.", "success")
    return redirect(url_for("files.detail", id=f["id"]))


@bp.route("/files/<uuid:id>/share", methods=("POST",))
@login_required
@password_limit(lambda: g.user["username"] if g.user else "")
def share(id):
    f = get_file(id, owner_only=True)
    form = ShareForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    # the owner's password opens their copy of the file key, which is then
    # encrypted again to the recipient's public key
    file_key, error = my_file_key(f, form.password.data)
    if error is not None:
        audit("share", "refused", file_id=f["id"], detail=error)
        flash(error)
        return redirect(url_for("files.detail", id=f["id"]))
    username = form.username.data
    db = get_db()
    user = db.execute(
        "SELECT u.id, e.public_key FROM users u"
        " LEFT JOIN encryption_keys e ON e.user_id = u.id"
        " WHERE u.username = ? AND u.banned_at IS NULL",
        (username,),
    ).fetchone()
    if user is None:
        audit("share", "failed", file_id=f["id"], detail="unknown user")
        flash("Unknown user.")
    elif user["id"] == f["owner_id"]:
        flash("The owner already has access.")
    elif user["public_key"] is None:
        # only after a duress wipe, until that user logs in again
        audit("share", "failed", file_id=f["id"], detail="no encryption key")
        flash(f"{username} cannot receive files until they log in again.")
    else:
        db.execute(
            "INSERT INTO file_keys (file_id, user_id, wrapped_key) VALUES (?, ?, ?)"
            " ON CONFLICT (file_id, user_id) DO UPDATE SET wrapped_key = excluded.wrapped_key",
            (f["id"], user["id"], wrap_file_key(user["public_key"], file_key, f["id"], user["id"])),
        )
        db.execute(
            "INSERT INTO shares (file_id, recipient_id) VALUES (?, ?)"
            " ON CONFLICT (file_id, recipient_id)"
            " DO UPDATE SET revoked_at = NULL, created_at = datetime('now')",
            (f["id"], user["id"]),
        )
        db.commit()
        audit("share", "ok", file_id=f["id"], detail=f"with {username}")
        flash(f"Shared with {username}.", "success")
    return redirect(url_for("files.detail", id=f["id"]))


@bp.route("/files/<uuid:id>/revoke", methods=("POST",))
@login_required
def revoke(id):
    f = get_file(id, owner_only=True)
    form = RevokeForm()
    if not form.validate():
        abort(400)
    recipient_id = int(form.recipient_id.data)
    db = get_db()
    db.execute(
        "UPDATE shares SET revoked_at = datetime('now')"
        " WHERE file_id = ? AND recipient_id = ? AND revoked_at IS NULL",
        (f["id"], recipient_id),
    )
    # without their copy of the key, the recipient cannot open the file even
    # if the share row comes back; the owner's own copy is never touched
    db.execute(
        "DELETE FROM file_keys WHERE file_id = ? AND user_id = ? AND user_id != ?",
        (f["id"], recipient_id, f["owner_id"]),
    )
    db.commit()
    audit("revoke", "ok", file_id=f["id"], detail=f"user {recipient_id}")
    flash("Share revoked.", "success")
    return redirect(url_for("files.detail", id=f["id"]))


@bp.route("/files/<uuid:id>/delete", methods=("POST",))
@login_required
def delete(id):
    f = get_file(id, owner_only=True)
    try:
        os.remove(storage_path(f["id"]))
    except FileNotFoundError:
        pass
    db = get_db()
    db.execute("DELETE FROM files WHERE id = ?", (f["id"],))
    db.commit()
    audit("delete", "ok", file_id=f["id"])
    flash(f"Deleted {f['filename']}.", "success")
    return redirect(url_for("files.index"))
