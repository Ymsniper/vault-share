import datetime
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
from security.integrity import record_mac, sha256
from security.keys import subkey
from security.pki import (
    certificate_problem,
    load_ca_certificate,
    load_certificate,
    revoked_since,
)
from security.signing import sign_digest, verify_digest
from security.uploads import (
    ARCHIVES,
    accept_list,
    check_upload,
    clean_name,
    type_groups,
)

from . import levels
from .audit import audit
from .auth import (
    TEN_AN_HOUR,
    admit,
    current_account,
    login_required,
    password_limit,
    password_ok,
    settle,
)
from .db import get_db
from .forms import (
    CheckCopyForm,
    DeleteForm,
    DismissForm,
    DownloadForm,
    RevokeForm,
    SearchForm,
    ShareForm,
    UploadForm,
    first_error,
)
from .identity import load_app_ca, new_identity
from .keyring import master_key
from .storage import storage_path

bp = Blueprint("files", __name__)

# as SQLite's datetime('now') writes it, in UTC
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def mac_key():
    return subkey(master_key(), "file-record-hmac")


def mac_of(f):
    return record_mac(mac_key(), f)


def get_file(id, owner_only=False):
    """Load a file the current user may use, or stop with 404 or 403.

    The owner may do anything; a user with an active share may only read.
    A file the session does not see answers as what it could be: one of
    the user's own as if it had been deleted (404, no row), one shared with
    them as if they had dismissed it (403 and a row).
    """
    id = str(id)
    db = get_db()
    f = db.execute(
        "SELECT f.*, u.username AS owner, u.banned_at AS owner_banned_at,"
        " c.pem AS cert_pem, c.serial AS cert_serial, c.not_after AS cert_not_after,"
        " COALESCE(c.invalid_from, c.revoked_at) AS cert_invalid_from"
        " FROM files f JOIN users u ON u.id = f.owner_id"
        " JOIN certificates c ON c.id = f.cert_id WHERE f.id = ?",
        (id,),
    ).fetchone()
    # a file a duress session deleted is gone for everyone, recipients too
    if f is None or f["trashed_at"] is not None:
        abort(404)
    if f["owner_id"] == g.user["id"] and levels.hidden(id):
        abort(404)
    if f["owner_id"] == g.user["id"]:
        return f
    # the files of a banned owner are hidden from everyone they shared with
    if not owner_only and f["owner_banned_at"] is None and not levels.hidden(id):
        share = db.execute(
            "SELECT 1 FROM shares WHERE file_id = ? AND recipient_id = ?"
            " AND revoked_at IS NULL AND dismissed_at IS NULL",
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
    keys = levels.unlock(password)
    if keys is None:
        g.wrong_password = True
        return None, "Wrong password."
    try:
        key = levels.file_key(f["id"], keys)
    except InvalidTag:
        return None, "Verification failed: your copy of the file's key was modified."
    if key is None:
        return None, "You have no key for this file. Ask its owner to share it again."
    return key, None


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
    # judged when the file was uploaded, a time the record HMAC covers, so
    # files do not fail once the certificate expires
    signed_at = datetime.datetime.strptime(f["uploaded_at"], TIME_FORMAT).replace(
        tzinfo=datetime.UTC
    )
    problem = certificate_problem(cert, ca_cert, f["owner"], at=signed_at)
    if problem is not None:
        return problem
    # a revocation counts from the time it gives: files uploaded before it,
    # while the key was trusted, stay valid
    if f["cert_invalid_from"] is not None and f["uploaded_at"] >= f["cert_invalid_from"]:
        return "the certificate was revoked"
    # the CA-signed list also catches a revocation erased or moved later in
    # the database
    crl_path = current_app.config["CA_CRL"]
    if os.path.exists(crl_path):
        with open(crl_path, "rb") as fp:
            try:
                since = revoked_since(cert, fp.read(), ca_cert)
            except ValueError as e:
                return str(e)
        if since is not None and signed_at >= since:
            return "the certificate was revoked"
    if not verify_digest(cert.public_key(), f["signature"], digest):
        return "the signature is not valid"
    return None


@bp.route("/", methods=("GET", "POST"))
@login_required
def index():
    # a POST, so search terms never end up in URLs, server logs or the
    # browser history; a plain GET lists everything. instr() rather than
    # LIKE, so % and _ in the search are plain characters
    form = SearchForm()
    q = form.q.data if form.validate_on_submit() else ""
    files, shared, cover = levels.file_lists(q)
    return render_template("files/index.html", files=files, shared=shared, cover=cover, q=q)


def upload_page():
    return render_template(
        "files/upload.html",
        groups=type_groups(),
        archives=list(ARCHIVES),
        accept=accept_list(),
        limit_mb=current_app.config["MAX_UPLOAD_MB"],
    )


@bp.route("/upload", methods=("GET", "POST"))
@login_required
@password_limit(current_account)
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        # requests over MAX_CONTENT_LENGTH never get here, Flask answers 413
        name = clean_name(file.filename)
        data = file.read()
        try:
            max_bytes = current_app.config["MAX_UPLOAD_MB"] * 1024 * 1024
            mime, checked = check_upload(name, data, max_bytes)
        except ValueError as e:
            audit("upload", "refused", detail=str(e))
            flash(str(e))
            return upload_page()

        # the password opens the account's keys, the signing key among
        # them, so a wrong one counts toward the same lockout as a login
        username = g.user["username"]
        keys = levels.unlock(form.password.data)
        if keys is None:
            g.wrong_password = True
            audit("upload", "refused", detail="wrong password")
            flash("Wrong password: your signing key stays locked and nothing was uploaded.")
            return upload_page()

        signer = get_db().execute(
            "SELECT id, pem, revoked_at FROM certificates WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (g.user["id"],),
        ).fetchone()
        ca_cert = load_ca_certificate(current_app.config["CA_CERT"])
        cert_problem = certificate_problem(load_certificate(signer["pem"]), ca_cert, username)
        if signer["revoked_at"] is None and cert_problem is None:
            key, cert_id = keys.signing_key(), signer["id"]
        else:
            # no usable certificate (revoked or expired): a new key pair,
            # locked where the old one was
            try:
                key, cert_id = new_identity(g.user["id"], username, keys.bottom, load_app_ca())
            except (OSError, ValueError) as e:
                current_app.logger.error("cannot load the CA: %s", e)
                flash(
                    "Your certificate needs renewing, but the certificate authority is not set up."
                )
                return upload_page()
            audit("renew_certificate", "ok")

        file_id = str(uuid.uuid4())
        digest = sha256(data)
        signature = sign_digest(key, digest)

        # a new random key for every file, kept only as copies encrypted to
        # the public keys of the people who may open it: for now the owner
        file_key = new_key()
        with open(storage_path(file_id), "wb") as out:
            out.write(encrypt(file_key, data, file_id.encode()))
        record = {
            "id": file_id,
            "owner_id": g.user["id"],
            "filename": name,
            "description": form.description.data or "",
            "mime": mime,
            "checked": int(checked),
            "size": len(data),
            "sha256": digest.hex(),
            "signature": signature,
            "cert_id": cert_id,
            # after the certificate was chosen or renewed, which starts at the
            # second it was issued; SQLite's own format, which the pages slice
            "uploaded_at": datetime.datetime.now(datetime.UTC).strftime(TIME_FORMAT),
        }
        # over exactly the values stored
        record["record_mac"] = record_mac(mac_key(), record)
        db = get_db()
        db.execute(
            "INSERT INTO files"
            " (id, owner_id, filename, description, mime, checked, size, sha256, signature,"
            " cert_id, uploaded_at, record_mac)"
            " VALUES (:id, :owner_id, :filename, :description, :mime, :checked, :size, :sha256,"
            " :signature, :cert_id, :uploaded_at, :record_mac)",
            record,
        )
        # the owner's copy of the file key, where the session keeps its files
        levels.keep_own_copy(file_id, file_key)
        db.commit()
        audit("upload", "ok", file_id=file_id, detail=None if checked else "archive, not checked")
        flash(f"Uploaded {name}.", "success")
        return redirect(url_for("files.detail", id=file_id))
    elif form.is_submitted():
        flash(first_error(form))

    return upload_page()


@bp.route("/files/<uuid:id>")
@login_required
def detail(id):
    f = get_file(id)
    problem = record_problem(f)
    error = f"Verification failed: {problem}." if problem else None
    # an owner's own visits are not logged: they would only push the
    # entries that matter out of view
    if error or f["owner_id"] != g.user["id"]:
        audit("verify", "failed" if error else "ok", file_id=f["id"], detail=error)
    shares = get_db().execute(
        "SELECT u.id, u.username FROM shares s JOIN users u ON u.id = s.recipient_id"
        " WHERE s.file_id = ? AND s.revoked_at IS NULL ORDER BY u.username",
        (f["id"],),
    ).fetchall()
    return render_template("files/detail.html", f=f, error=error, shares=shares)


@bp.route("/files/<uuid:id>/download", methods=("POST",))
@login_required
@password_limit(current_account)
def download(id):
    f = get_file(id)
    form = DownloadForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    # the password unlocks this user's private key for this request only,
    # so a stolen session cookie alone cannot download anything
    if not f["checked"] and f["owner_id"] != g.user["id"] and not form.understood.data:
        # nothing about an archive's content was checked: the recipient says
        # they know before getting it
        audit("download", "refused", file_id=f["id"], detail="not checked, not confirmed")
        flash("Tick the box to confirm you know this archive was not checked.")
        return redirect(url_for("files.detail", id=f["id"]))
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


# the commands hold no file name, which could carry shell syntax: the copy
# to check is FILE, for the reader to replace
PROOF_README = """\
Check that a file was signed by {owner}, without the web app.

File: {name}
Uploaded: {uploaded_at} UTC

1. The signer's certificate was issued by the local CA and was valid when
   the file was uploaded:
   openssl verify -attime {epoch} -CAfile ca.crt signer.crt

2. Take the public key out of the certificate:
   openssl x509 -in signer.crt -pubkey -noout -out signer.pub

3. The signature matches your copy of the file; replace FILE with its path:
   openssl dgst -sha256 -verify signer.pub -signature signature.sig FILE
"""


@bp.route("/files/<uuid:id>/proof")
@login_required
def proof(id):
    """Signature, signer certificate and CA certificate, to check a copy offline."""
    f = get_file(id)
    with open(current_app.config["CA_CERT"], "rb") as fp:
        ca_pem = fp.read()
    buf = io.BytesIO()
    uploaded = datetime.datetime.strptime(f["uploaded_at"], TIME_FORMAT)
    epoch = int(uploaded.replace(tzinfo=datetime.UTC).timestamp())
    readme = PROOF_README.format(
        name=f["filename"], owner=f["owner"], uploaded_at=f["uploaded_at"], epoch=epoch
    )
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("signature.sig", f["signature"])
        z.writestr("signer.crt", f["cert_pem"])
        z.writestr("ca.crt", ca_pem)
        z.writestr("README.txt", readme)
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
@password_limit(current_account)
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
    # every unknown username is a guess at someone's tag: ten an hour
    limits = [(TEN_AN_HOUR, "unknown-recipient", current_account())]
    if admit(limits) is not None:
        audit("share", "refused", file_id=f["id"], detail="too many unknown usernames")
        flash("Too many unknown usernames. Try again later.")
        return redirect(url_for("files.detail", id=f["id"]))
    db = get_db()
    user = None
    try:
        user = db.execute(
            "SELECT id FROM users WHERE username = ? AND banned_at IS NULL", (username,)
        ).fetchone()
    finally:
        settle(limits, user is None)
    if user is None:
        audit("share", "failed", file_id=f["id"], detail="unknown user")
        flash("Unknown user.")
    elif user["id"] == f["owner_id"]:
        flash("The owner already has access.")
    else:
        # encrypted again to the recipient's public key
        levels.give_copy(f["id"], user["id"], file_key)
        db.execute(
            "INSERT INTO shares (file_id, recipient_id) VALUES (?, ?)"
            " ON CONFLICT (file_id, recipient_id)"
            " DO UPDATE SET revoked_at = NULL, dismissed_at = NULL, created_at = datetime('now')",
            (f["id"], user["id"]),
        )
        db.commit()
        audit("share", "ok", file_id=f["id"], detail=f"with {username}")
        flash(f"Shared with {username}.", "success")
    return redirect(url_for("files.detail", id=f["id"]))


def owner_password_ok(f, password, action, refusal):
    """Check the owner's password before a share is revoked or a file
    deleted, so a stolen session cookie alone cannot do either. A wrong one
    counts toward the account's limit."""
    if password_ok(password):
        return True
    g.wrong_password = True
    audit(action, "refused", file_id=f["id"], detail="wrong password")
    flash(refusal)
    return False


@bp.route("/files/<uuid:id>/revoke", methods=("POST",))
@login_required
@password_limit(current_account)
def revoke(id):
    f = get_file(id, owner_only=True)
    form = RevokeForm()
    if not form.validate():
        if form.recipient_id.errors:
            abort(400)
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    if not owner_password_ok(f, form.password.data, "revoke", "Wrong password: the share stays."):
        return redirect(url_for("files.detail", id=f["id"]))
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


@bp.route("/files/<uuid:id>/dismiss", methods=("POST",))
@login_required
@password_limit(current_account)
def dismiss(id):
    """A recipient takes a shared file off their own list. Their copy of its
    key goes, the owner is not told and still sees the share, and sharing
    again brings it back. Not logged: a file that is missing from someone's
    list can always have been dismissed."""
    f = get_file(id)
    if f["owner_id"] == g.user["id"]:
        abort(403)
    form = DismissForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    if not password_ok(form.password.data):
        g.wrong_password = True
        flash("Wrong password: the file stays on your list.")
        return redirect(url_for("files.detail", id=f["id"]))
    db = get_db()
    db.execute(
        "UPDATE shares SET dismissed_at = datetime('now') WHERE file_id = ? AND recipient_id = ?",
        (f["id"], g.user["id"]),
    )
    db.execute("DELETE FROM file_keys WHERE file_id = ? AND user_id = ?", (f["id"], g.user["id"]))
    db.commit()
    flash(f"Removed {f['filename']} from your list.", "success")
    return redirect(url_for("files.index"))


@bp.route("/files/<uuid:id>/delete", methods=("POST",))
@login_required
@password_limit(current_account)
def delete(id):
    f = get_file(id, owner_only=True)
    form = DeleteForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("files.detail", id=f["id"]))
    if not owner_password_ok(f, form.password.data, "delete", "Wrong password: nothing was deleted."):
        return redirect(url_for("files.detail", id=f["id"]))
    # logged first, while the row still says whose file it was
    audit("delete", "ok", file_id=f["id"])
    levels.discard(f["id"])
    flash(f"Deleted {f['filename']}.", "success")
    return redirect(url_for("files.index"))
