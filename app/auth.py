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

from security.passwords import (
    USERNAME_RE,
    check_password,
    check_password_of_unknown_user,
    hash_password,
    password_problem,
)
from security.pki import issue_certificate, load_ca, make_csr, to_pem
from security.signing import generate_key, private_key_pem

from .audit import audit
from .db import get_db

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


# 5 failures for one username, or 20 from one address, within 15 minutes
# lock further attempts until the oldest of them is 15 minutes old.
# Usernames that do not exist are counted too, so the lock message does
# not tell an attacker which accounts are real.
MAX_FAILURES_PER_USER = 5
MAX_FAILURES_PER_IP = 20


def is_locked(username, ip):
    db = get_db()
    by_user = db.execute(
        "SELECT COUNT(*) FROM login_failures"
        " WHERE username = ? AND at > datetime('now', '-15 minutes')",
        (username,),
    ).fetchone()[0]
    by_ip = db.execute(
        "SELECT COUNT(*) FROM login_failures"
        " WHERE ip = ? AND at > datetime('now', '-15 minutes')",
        (ip,),
    ).fetchone()[0]
    return by_user >= MAX_FAILURES_PER_USER or by_ip >= MAX_FAILURES_PER_IP


def record_failure(username, ip):
    db = get_db()
    db.execute("INSERT INTO login_failures (username, ip) VALUES (?, ?)", (username, ip))
    db.commit()


def clear_failures(username):
    db = get_db()
    db.execute("DELETE FROM login_failures WHERE username = ?", (username,))
    db.commit()


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not USERNAME_RE.fullmatch(username):
            error = "Username must be 3 to 32 letters, digits or underscores."
        else:
            error = password_problem(username, password)

        if error is None:
            cfg = current_app.config
            try:
                ca_cert, ca_key = load_ca(cfg["CA_CERT"], cfg["CA_KEY"], cfg["CA_PASSPHRASE"])
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
                key = generate_key()
                cert = issue_certificate(make_csr(key, username), ca_cert, ca_key)
                db.execute(
                    "INSERT INTO user_keys (user_id, private_key) VALUES (?, ?)",
                    (user_id, private_key_pem(key)),
                )
                db.execute(
                    "INSERT INTO certificates (user_id, serial, pem, not_before, not_after)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        user_id,
                        format(cert.serial_number, "x"),
                        to_pem(cert),
                        cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S"),
                        cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S"),
                    ),
                )
                db.commit()
                audit("register", "ok", user_id=user_id)
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template("auth/register.html")


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if is_locked(username, request.remote_addr):
            audit("login", "locked", user_id=None)
            flash("Too many failed attempts. Try again in 15 minutes.")
            return render_template("auth/login.html")

        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            ok = check_password_of_unknown_user(password)
        else:
            ok = check_password(user["password_hash"], password)

        if not ok:
            record_failure(username, request.remote_addr)
            audit("login", "failed", user_id=None)
            flash("Incorrect username or password.")
        else:
            clear_failures(username)
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

    return render_template("auth/login.html")


@bp.route("/logout")
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
