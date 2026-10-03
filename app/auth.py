import functools
import hashlib
import secrets

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from security.passwords import check_password, check_password_of_unknown_user, hash_password

from . import limiter
from .audit import audit
from .db import get_db
from .forms import LoginForm, RegisterForm, first_error
from .identity import load_app_ca, new_identity

bp = Blueprint("auth", __name__, url_prefix="/auth")

SESSION_COOKIE = "sid"


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user_id):
    """Create a server-side session and return its token for the cookie."""
    token = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "DELETE FROM sessions WHERE expires_at <= datetime('now')"
        " OR last_seen <= datetime('now', '-30 minutes')"
    )
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at)"
        " VALUES (?, ?, datetime('now', '+8 hours'))",
        (token_hash(token), user_id),
    )
    db.commit()
    return token


def end_session(token):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    db.commit()


LOCKED = "Too many failed attempts. Try again in 15 minutes."


def wrong_password_given(response):
    """Only failed attempts count toward the limits below."""
    return g.get("wrong_password", False)


def report_lock(request_limit):
    audit("password", "locked", user_id=None)


def password_limit(key_func):
    """5 wrong passwords for one username, at login or at upload, block that
    username for 15 minutes. Usernames that do not exist count the same way,
    so the block says nothing about which accounts are real.
    """
    return limiter.shared_limit(
        "5 per 15 minutes",
        scope="wrong-password",
        key_func=key_func,
        methods=["POST"],
        deduct_when=wrong_password_given,
        error_message=LOCKED,
        on_breach=report_lock,
    )


@bp.route("/register", methods=("GET", "POST"))
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        error = None
        try:
            ca = load_app_ca()
        except (OSError, ValueError) as e:
            current_app.logger.error("cannot load the CA: %s", e)
            error = "Registration is unavailable: the certificate authority is not set up."

        if error is None:
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, hash_password(password)),
                )
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                user_id = cur.lastrowid
                new_identity(user_id, username, password, ca)
                db.commit()
                audit("register", "ok", user_id=user_id)
                return redirect(url_for("auth.login"))

        flash(error)
    elif form.is_submitted():
        flash(first_error(form))

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
@password_limit(lambda: request.form.get("username", ""))
# and 20 from one address, so one machine cannot try many accounts
@limiter.limit(
    "20 per 15 minutes",
    methods=["POST"],
    deduct_when=wrong_password_given,
    error_message=LOCKED,
    on_breach=report_lock,
)
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            ok = check_password_of_unknown_user(password)
        else:
            ok = check_password(user["password_hash"], password)

        if not ok:
            g.wrong_password = True
            audit("login", "failed", user_id=None)
            flash("Incorrect username or password.")
        else:
            # a token the browser already had, maybe planted by someone
            # else, is never reused: every login gets a fresh one
            old_token = request.cookies.get(SESSION_COOKIE)
            if old_token:
                end_session(old_token)
            session.clear()
            token = start_session(user["id"])
            audit("login", "ok", user_id=user["id"])
            response = redirect(url_for("files.index"))
            response.set_cookie(
                SESSION_COOKIE,
                token,
                httponly=True,
                samesite="Lax",
                secure=current_app.config["SESSION_COOKIE_SECURE"],
            )
            return response
    elif form.is_submitted():
        flash("Incorrect username or password.")

    return render_template("auth/login.html")


@bp.route("/logout", methods=("POST",))
def logout():
    if g.user is not None:
        audit("logout", "ok")
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        end_session(token)
    session.clear()
    response = redirect(url_for("auth.login"))
    response.delete_cookie(SESSION_COOKIE)
    return response


@bp.before_app_request
def load_logged_in_user():
    g.user = None
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return
    db = get_db()
    # a session ends 8 hours after login, or after 30 minutes without a request
    g.user = db.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = ? AND s.expires_at > datetime('now')"
        " AND s.last_seen > datetime('now', '-30 minutes')",
        (token_hash(token),),
    ).fetchone()
    if g.user is not None:
        db.execute(
            "UPDATE sessions SET last_seen = datetime('now') WHERE token_hash = ?",
            (token_hash(token),),
        )
        db.commit()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)

    return wrapped_view
