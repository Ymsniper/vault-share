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
from .duress import login_flag
from .keyring import master_key
from .forms import CodeForm, TotpForm, first_error

bp = Blueprint("totp", __name__, url_prefix="/auth")

# after the right password, the code must follow within 5 minutes
PENDING_LOGIN_SECONDS = 300


def seal(user_id, secret):
    key = subkey(master_key(), "totp-secret")
    return encrypt(key, secret.encode(), f"totp:{user_id}".encode())


def unseal(user_id, blob):
    key = subkey(master_key(), "totp-secret")
    return decrypt(key, blob, f"totp:{user_id}".encode()).decode()


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
        flash("Wrong code. Check that the time on your phone is right.")
    return step


@bp.route("/totp", methods=("GET", "POST"))
@login_required
@password_limit(current_account)
def setup():
    """Turn two-factor login on: scan the QR code, then confirm a first code."""
    if g.user["totp_secret"] is not None:
        return no_store(render_template("auth/totp.html", enabled=True, form=TotpForm()))

    # kept in Flask's signed session cookie until confirmed; only this user sees it
    secret = session.setdefault("totp_pending", new_secret())
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
            db.commit()
            session.pop("totp_pending")
            audit("totp", "enabled")
            flash("Two-factor login is on.", "success")
            return redirect(url_for("totp.setup"))
        audit("totp", "failed")
    elif form.is_submitted():
        flash(first_error(form))
    return no_store(render_template("auth/totp.html", enabled=False, secret=secret, form=form))


@bp.route("/totp/qr.svg")
@login_required
def qr():
    secret = session.get("totp_pending")
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
    db.commit()
    audit("totp", "disabled")
    flash("Two-factor login is off.", "success")
    return redirect(url_for("totp.setup"))


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

    form = CodeForm()
    if form.validate_on_submit():
        secret = unseal(user["id"], user["totp_secret"])
        step = matching_step(secret, form.code.data, user["totp_last_step"])
        if step is not None:
            db = get_db()
            db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
            db.commit()
            return finish_login(user, login_flag(user["id"], session["totp_mode"]))
        g.wrong_password = True
        audit("login", "failed", user_id=None, detail="wrong code")
        flash("Wrong code.")
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/login_code.html")
