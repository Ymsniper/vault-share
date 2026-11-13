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
from security.totp import matching_step, new_secret, qr_svg

from . import levels
from .audit import audit
from .auth import (
    current_account,
    finish_pending_login,
    login_required,
    password_limit,
    password_ok,
    pending_key,
)
from .db import get_db
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


def recovery_code():
    """16 symbols of the invite code alphabet, 80 bits, in groups of four."""
    raw = "".join(secrets.choice(ALPHABET) for _ in range(16))
    return "-".join(raw[i : i + 4] for i in range(0, 16, 4))


def new_recovery_codes():
    """Ten single-use codes that stand in for the phone at login, and their
    hashes, which replace the earlier ones: the codes are shown once, and
    only their SHA-256 is kept. They are random, so the hashes give none of
    them away."""
    codes = [recovery_code() for _ in range(10)]
    return codes, [code_hash(c) for c in codes]


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
    sessions, so a stolen or duress session cannot hand the owner a secret
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
    if not password_ok(form.password.data):
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
    """Turn two-factor login on: scan the QR code, then confirm a first code.
    It is on for the password this session logged in with; the account's
    other passwords keep theirs."""
    if levels.two_factor()["on"]:
        return no_store(render_template("auth/totp.html", enabled=True, form=TotpForm()))

    secret = pending_secret()
    form = TotpForm()
    if form.validate_on_submit():
        step = check_password_and_code(form, secret, None)
        if step is not None:
            codes, hashes = new_recovery_codes()
            levels.turn_two_factor_on(secret, step, hashes)
            db = get_db()
            db.execute(
                "UPDATE sessions SET totp_pending = NULL WHERE token_hash = ?", (g.session_hash,)
            )
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
    """Turn two-factor login off for the password this session logged in
    with. The code is spent like a login's, so it cannot open another."""
    state = levels.two_factor()
    if not state["on"]:
        return redirect(url_for("totp.setup"))
    form = TotpForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("totp.setup"))
    step = check_password_and_code(form, state["secret"], state["step"])
    if step is not None and not levels.use_step(step):
        g.wrong_password = True
        flash(WRONG_CODE)
        step = None
    if step is None:
        audit("totp", "failed")
        return redirect(url_for("totp.setup"))
    levels.turn_two_factor_off()
    get_db().commit()
    audit("totp", "disabled")
    flash("Two-factor login is off.", "success")
    return redirect(url_for("totp.setup"))


@bp.route("/totp/recovery", methods=("POST",))
@login_required
@password_limit(current_account)
def new_recovery():
    """New recovery codes, with the password and a code from the phone, for
    the password this session logged in with."""
    state = levels.two_factor()
    if not state["on"]:
        return redirect(url_for("totp.setup"))
    form = TotpForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("totp.setup"))
    step = check_password_and_code(form, state["secret"], state["step"])
    if step is not None and not levels.use_step(step):
        g.wrong_password = True
        flash(WRONG_CODE)
        step = None
    if step is None:
        audit("totp", "failed")
        return redirect(url_for("totp.setup"))
    codes, hashes = new_recovery_codes()
    levels.replace_two_factor_codes(hashes)
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
    return pending_key(user["id"], session["totp_mode"]) if user else None


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
        blob = session["totp_mode"]
        if recovery:
            right = levels.pending_use_code(user["id"], blob, code_hash(form.recovery.data))
        else:
            state = levels.pending_two_factor(user["id"], blob)
            step = matching_step(state["secret"], form.code.data, state["step"])
            right = step is not None and levels.pending_use_step(user["id"], blob, step)
        if right:
            return finish_pending_login(user, session["totp_mode"], recovery=recovery)
        g.wrong_password = True
        audit("login", "failed", user_id=None, detail="wrong code")
        flash("Wrong code.")
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/login_code.html")
