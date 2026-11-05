import secrets
import time

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from security.crypto import decrypt, encrypt
from security.keys import subkey
from security.passwords import check_password
from security.totp import matching_step, new_secret, qr_svg

from .audit import audit
from .auth import current_account, finish_login, login_required, password_limit
from .db import get_db
from .duress import WIPE, login_flag, mode_of, wipe_account
from .invites import ALPHABET, code_hash
from .keyring import master_key
from .forms import CodeForm, RecoveryForm, TotpForm, first_error

bp = Blueprint("totp", __name__, url_prefix="/auth")

# after the right password, the code must follow within 5 minutes
PENDING_LOGIN_SECONDS = 300

WRONG_CODE = "Wrong code. Check that the time on your phone is right."


def seal(user_id, secret):
    key = subkey(master_key(), "totp-secret")
    return encrypt(key, secret.encode(), f"totp:{user_id}".encode())


def unseal(user_id, blob):
    key = subkey(master_key(), "totp-secret")
    return decrypt(key, blob, f"totp:{user_id}".encode()).decode()


def use_step(user_id, step):
    """Mark a code's time step used, unless it or a later one already was.
    One statement, so two requests with the same code cannot both pass
    between a check and an update."""
    db = get_db()
    cur = db.execute(
        "UPDATE users SET totp_last_step = ?"
        " WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
        (step, user_id, step),
    )
    db.commit()
    return cur.rowcount == 1


def recovery_code():
    """16 symbols of the invite code alphabet, 80 bits, in groups of four."""
    raw = "".join(secrets.choice(ALPHABET) for _ in range(16))
    return "-".join(raw[i : i + 4] for i in range(0, 16, 4))


def new_recovery_codes(user_id):
    """Ten single-use codes that stand in for the phone at login, replacing
    any earlier ones; the caller commits, then shows them once. Only their
    SHA-256 is kept: they are random, so the hashes give none of them away."""
    codes = [recovery_code() for _ in range(10)]
    db = get_db()
    db.execute("DELETE FROM totp_recovery WHERE user_id = ?", (user_id,))
    db.executemany(
        "INSERT INTO totp_recovery (user_id, code_hash) VALUES (?, ?)",
        [(user_id, code_hash(c)) for c in codes],
    )
    return codes


def use_recovery_code(user_id, code):
    """Mark one of the user's recovery codes used, if it is one and was not
    used yet: one statement, so two requests cannot both use it."""
    db = get_db()
    cur = db.execute(
        "UPDATE totp_recovery SET used_at = datetime('now')"
        " WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
        (user_id, code_hash(code)),
    )
    db.commit()
    return cur.rowcount == 1


def codes_page(codes):
    # in this answer only, like a new invite code: never in the cookie, and
    # never on the page again
    return no_store(render_template(
        "auth/totp.html", enabled=True, form=TotpForm(), recovery_codes=codes
    ))


def pending_secret(create=True):
    """The secret this session is enrolling, made on first use, or None.
    It stays with the session on the server, sealed like a confirmed one:
    never in the browser's cookie, and never offered to the account's other
    sessions, so a stolen or decoy session cannot hand the owner a secret
    it knows."""
    if g.user["session_totp_pending"] is not None:
        return unseal(g.user["id"], g.user["session_totp_pending"])
    if not create:
        return None
    secret = new_secret()
    db = get_db()
    db.execute(
        "UPDATE sessions SET totp_pending = ? WHERE token_hash = ?",
        (seal(g.user["id"], secret), g.session_hash),
    )
    db.commit()
    return secret


def no_store(body):
    # these pages carry the secret, so browsers must not keep a copy
    response = make_response(body)
    response.headers["Cache-Control"] = "no-store"
    return response


def check_password_and_code(form, secret, last_step):
    """The time step of a valid code, or None after flashing why it failed.

    A wrong password or code counts toward the same limit as a failed login.
    """
    if not check_password(g.user["password_hash"], form.password.data):
        g.wrong_password = True
        flash("Wrong password.")
        return None
    step = matching_step(secret, form.code.data, last_step)
    if step is None:
        g.wrong_password = True
        flash(WRONG_CODE)
    return step


@bp.route("/totp", methods=("GET", "POST"))
@login_required
@password_limit(current_account)
def setup():
    """Turn two-factor login on: scan the QR code, then confirm a first code."""
    if g.user["totp_secret"] is not None:
        return no_store(render_template("auth/totp.html", enabled=True, form=TotpForm()))

    secret = pending_secret()
    form = TotpForm()
    if form.is_submitted() and g.duress:
        # the decoy account cannot change its settings, and does not say why
        flash("This setting could not be saved. Try again later.")
    elif form.validate_on_submit():
        step = check_password_and_code(form, secret, None)
        if step is not None:
            db = get_db()
            db.execute(
                "UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ?",
                (seal(g.user["id"], secret), step, g.user["id"]),
            )
            db.execute(
                "UPDATE sessions SET totp_pending = NULL WHERE token_hash = ?", (g.session_hash,)
            )
            codes = new_recovery_codes(g.user["id"])
            db.commit()
            audit("totp", "enabled")
            flash("Two-factor login is on.", "success")
            return codes_page(codes)
        audit("totp", "failed")
    elif form.is_submitted():
        flash(first_error(form))
    return no_store(render_template("auth/totp.html", enabled=False, secret=secret, form=form))


@bp.route("/totp/qr.svg")
@login_required
def qr():
    secret = pending_secret(create=False)
    if secret is None:
        abort(404)
    return no_store(Response(qr_svg(secret, g.user["username"]), mimetype="image/svg+xml"))


@bp.route("/totp/disable", methods=("POST",))
@login_required
@password_limit(current_account)
def disable():
    if g.user["totp_secret"] is None:
        return redirect(url_for("totp.setup"))
    if g.duress:
        flash("This setting could not be saved. Try again later.")
        return redirect(url_for("totp.setup"))
    form = TotpForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("totp.setup"))
    secret = unseal(g.user["id"], g.user["totp_secret"])
    if check_password_and_code(form, secret, g.user["totp_last_step"]) is None:
        audit("totp", "failed")
        return redirect(url_for("totp.setup"))
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = NULL, totp_last_step = NULL WHERE id = ?",
        (g.user["id"],),
    )
    db.execute("DELETE FROM totp_recovery WHERE user_id = ?", (g.user["id"],))
    db.commit()
    audit("totp", "disabled")
    flash("Two-factor login is off.", "success")
    return redirect(url_for("totp.setup"))


@bp.route("/totp/recovery", methods=("POST",))
@login_required
@password_limit(current_account)
def new_recovery():
    """New recovery codes, with the password and a code from the phone."""
    if g.user["totp_secret"] is None:
        return redirect(url_for("totp.setup"))
    if g.duress:
        flash("This setting could not be saved. Try again later.")
        return redirect(url_for("totp.setup"))
    form = TotpForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("totp.setup"))
    secret = unseal(g.user["id"], g.user["totp_secret"])
    step = check_password_and_code(form, secret, g.user["totp_last_step"])
    if step is not None and not use_step(g.user["id"], step):
        g.wrong_password = True
        flash(WRONG_CODE)
        step = None
    if step is None:
        audit("totp", "failed")
        return redirect(url_for("totp.setup"))
    codes = new_recovery_codes(g.user["id"])
    get_db().commit()
    audit("totp", "new recovery codes")
    flash("New recovery codes: the old ones no longer work.", "success")
    return codes_page(codes)


def pending_user():
    """The user who typed the right password and still owes a code, or None."""
    user_id = session.get("totp_user_id")
    if user_id is None or time.time() - session.get("totp_started", 0) > PENDING_LOGIN_SECONDS:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def pending_account():
    user = pending_user()
    return str(user["id"]) if user else None


@bp.route("/login/code", methods=("GET", "POST"))
@password_limit(pending_account, scope="code")
def login_code():
    user = pending_user()
    if user is None:
        flash("Log in again.")
        return redirect(url_for("auth.login"))

    # a code from the phone, or one of the recovery codes for a lost phone
    recovery = "recovery" in request.form
    form = RecoveryForm() if recovery else CodeForm()
    if form.validate_on_submit():
        if recovery:
            right = use_recovery_code(user["id"], form.recovery.data)
        else:
            secret = unseal(user["id"], user["totp_secret"])
            step = matching_step(secret, form.code.data, user["totp_last_step"])
            right = step is not None and use_step(user["id"], step)
        if right:
            if recovery:
                audit("totp", "recovery code used", user_id=user["id"])
            duress = login_flag(user["id"], session["totp_mode"])
            if duress and mode_of(user) == WIPE:
                # the wipe the duress password asked for, now that the code is right
                wipe_account(user)
                audit("duress", "wiped", user_id=user["id"])
            return finish_login(user, duress)
        g.wrong_password = True
        audit("login", "failed", user_id=None, detail="wrong code")
        flash("Wrong code.")
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/login_code.html")
