import functools
import hashlib
import secrets
import threading
import time
from collections import Counter

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter.util import get_remote_address
from limits import parse
from markupsafe import Markup, escape

from security.passwords import check_password, check_password_of_unknown_user, hash_password

from . import limiter
from .audit import audit
from .db import get_db
from .duress import WIPE, empty_slot, mode_of, seal_login_flag, wipe_account
from .forms import LoginForm, NewPasswordForm, RegisterForm, first_error
from .identity import ensure_encryption_key, load_app_ca, new_encryption_key, new_identity
from .invites import INVALID, usable_invite, use_invite

bp = Blueprint("auth", __name__, url_prefix="/auth")

SESSION_COOKIE = "sid"


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user_id, duress=False):
    """Create a server-side session and return its token for the cookie."""
    token = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "DELETE FROM sessions WHERE expires_at <= datetime('now')"
        " OR last_seen <= datetime('now', '-30 minutes')"
    )
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at, duress)"
        " VALUES (?, ?, datetime('now', '+8 hours'), ?)",
        (token_hash(token), user_id, int(duress)),
    )
    db.commit()
    return token


def finish_login(user, duress=False):
    """Start a fresh server-side session for user and send its cookie.

    A session opened with the duress password shows the account as empty.
    """
    # a token the browser already had, maybe planted by someone else, is
    # never reused: every login gets a fresh one
    old_token = request.cookies.get(SESSION_COOKIE)
    if old_token:
        end_session(old_token)
    session.clear()
    token = start_session(user["id"], duress)
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


def end_session(token):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    db.commit()


LOCKED = "Too many failed attempts. Try again in 15 minutes."
BUSY = "Too many attempts at once. Try again in a moment."

FIVE = parse("5 per 15 minutes")
TWENTY = parse("20 per 15 minutes")
TEN_AN_HOUR = parse("10 per hour")

# Flask-Limiter's deduct_when records a failure only once the response is
# built, so requests sent together would all pass the check before any of
# them counted. A password check therefore counts as in flight from the
# moment it is let through until it is settled.
_gate = threading.Lock()
_in_flight = Counter()


def admit(limits):
    """None if a password check may run under limits, a list of (item,
    scope, key), else LOCKED when the failures recorded in a window fill
    its limit, or BUSY when the checks in flight do."""
    with _gate:
        verdict = None
        for item, scope, key in limits:
            remaining = limiter.limiter.get_window_stats(item, scope, key).remaining
            if remaining <= 0:
                return LOCKED
            if remaining <= _in_flight[scope, key]:
                verdict = BUSY
        if verdict is None:
            for _, scope, key in limits:
                _in_flight[scope, key] += 1
        return verdict


def settle(limits, failed):
    """Record a failed check, then stop counting it as in flight: in this
    order, so it is never counted nowhere."""
    if failed:
        for item, scope, key in limits:
            limiter.limiter.hit(item, scope, key)
    with _gate:
        for _, scope, key in limits:
            _in_flight[scope, key] -= 1
            if not _in_flight[scope, key]:
                del _in_flight[scope, key]


def current_account():
    """The logged-in user's id: only their own session can count toward the
    limit of their password checks."""
    return str(g.user["id"]) if g.get("user") else None


def login_key():
    # one username from one address, so wrong tries elsewhere never lock the
    # owner out; cut, since the field is not validated yet and the key is kept
    return f"{request.form.get('username', '')[:40]}|{get_remote_address()}"


def password_limit(key_func, item=FIVE, scope="account", log=True):
    """Wrong passwords sent with POST count toward item for key_func();
    right ones cost nothing, and a key of None counts nowhere. The view sets
    g.wrong_password when it refused a password. By default 5 wrong
    passwords in a logged-in account, at upload, download, share or in its
    settings, block its password checks for 15 minutes.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if request.method != "POST":
                return view(*args, **kwargs)
            key = key_func()
            limits = [] if key is None else [(item, scope, key)]
            verdict = admit(limits)
            if verdict == LOCKED and log:
                audit("password", "locked", user_id=None)
            if verdict is not None:
                abort(429, verdict)
            try:
                return view(*args, **kwargs)
            finally:
                settle(limits, g.get("wrong_password", False))
        return wrapped
    return decorator


def show_handle(username):
    """A username for a page: the name, then its tag dimmed. Both are escaped."""
    name, sep, tag = str(username).partition("#")
    if not sep:
        return escape(name)
    return Markup('{}<span class="vs-tag">#{}</span>').format(name, tag)


def new_handle(name):
    """The name plus a random 6-digit tag, such as bob#516850.

    Names can repeat, so registering never says whether one is taken, and
    knowing a name is not enough to aim at an account.
    """
    return f"{name}#{secrets.randbelow(1_000_000):06d}"


# Registering takes two steps: the invite code and a name first, then the
# password next to the full username, so the browser saves the username with
# its tag. Ten tries an hour per address for each step.


@bp.route("/register", methods=("GET", "POST"))
@limiter.limit("10 per hour", methods=["POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        invite_id = usable_invite(form.code.data)
        if invite_id is None:
            # unknown, used, cancelled or expired: the same answer for all
            audit("register", "refused", detail="invalid invite code", user_id=None)
            flash(INVALID)
        else:
            session["invite_id"] = invite_id
            # the tag comes from the server only; step two never reads a
            # username from its form
            session["new_handle"] = new_handle(form.username.data)
            return redirect(url_for("auth.register_password"))
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/register.html")


@bp.route("/register/password", methods=("GET", "POST"))
@limiter.limit("10 per hour", methods=["POST"])
def register_password():
    handle = session.get("new_handle")
    invite_id = session.get("invite_id")
    if handle is None or invite_id is None:
        return redirect(url_for("auth.register"))
    name = handle.partition("#")[0]
    form = NewPasswordForm(name)
    if form.validate_on_submit():
        password = form.password.data
        error = None
        try:
            ca = load_app_ca()
        except (OSError, ValueError) as e:
            current_app.logger.error("cannot load the CA: %s", e)
            error = "Registration is unavailable: the certificate authority is not set up."

        if error is None:
            db = get_db()
            # in the same transaction as the account: someone else who
            # registered with the same code in the meantime wins
            if not use_invite(invite_id):
                db.rollback()
                session.pop("new_handle")
                session.pop("invite_id")
                audit("register", "refused", detail="invite code used meanwhile", user_id=None)
                flash(INVALID)
                return redirect(url_for("auth.register"))
            try:
                duress_hash, duress_policy = empty_slot(handle)
                cur = db.execute(
                    "INSERT INTO users"
                    " (username, password_hash, duress_hash, duress_policy, invite_id)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (handle, hash_password(password), duress_hash, duress_policy, invite_id),
                )
            except db.IntegrityError:
                # the same tag drawn twice for this name, about one in a million;
                # the rollback also gives the invite back
                db.rollback()
                handle = session["new_handle"] = new_handle(name)
                error = "That tag was just taken, so here is another one. Register with it."
            else:
                user_id = cur.lastrowid
                new_identity(user_id, handle, password, ca)
                new_encryption_key(user_id, handle, password)
                db.commit()
                audit("register", "ok", detail=f"invite code {invite_id}", user_id=user_id)
                session.pop("new_handle")
                session.pop("invite_id")
                # filled in on the login page, never put in its URL
                session["login_handle"] = handle
                flash(f"Account created. Your username is {handle}.", "success")
                return redirect(url_for("auth.login"))

        flash(error)
    elif form.is_submitted():
        flash(first_error(form))

    return render_template("auth/register_password.html", handle=handle)


@bp.route("/login", methods=("GET", "POST"))
# 5 wrong passwords for one username from one address; usernames that do
# not exist count the same way, so the block says nothing about which are real
@password_limit(login_key, scope="login")
# and 20 from one address, so one machine cannot try many accounts
@password_limit(get_remote_address, TWENTY, "login-address")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # both passwords are checked every time, so the time a login takes
        # does not show which one matched
        if user is None:
            check_password_of_unknown_user(password)
            check_password_of_unknown_user(password)
            real = duress = False
        else:
            real = check_password(user["password_hash"], password)
            duress = check_password(user["duress_hash"], password)

        if not (real or duress):
            g.wrong_password = True
            audit("login", "failed", user_id=None)
            flash("Incorrect username or password.")
        elif user["banned_at"] is not None:
            # after the password check, so only the owner learns of the ban
            audit("login", "refused", user_id=user["id"], detail="banned")
            flash("This account is disabled.")
        else:
            if real and not duress:
                # only missing after a duress wipe; the password is at hand
                ensure_encryption_key(user["id"], username, password)
            if duress:
                wipe = mode_of(user) == WIPE
                # with two-factor on, the wipe waits for the code like the
                # login does, so the duress password alone destroys nothing
                waits = wipe and user["totp_secret"] is not None
                if wipe and not waits:
                    wipe_account(user)
                # the silent alarm: only an administrator ever sees it
                detail = "wipe after the code" if waits else "wipe" if wipe else "decoy"
                audit("duress", "used", user_id=user["id"], detail=detail)
            if user["totp_secret"] is not None:
                # right password, but no session until the code is right too
                session.clear()
                session["totp_user_id"] = user["id"]
                session["totp_started"] = time.time()
                session["totp_mode"] = seal_login_flag(user["id"], duress)
                return redirect(url_for("totp.login_code"))
            return finish_login(user, duress)
    elif form.is_submitted():
        flash("Incorrect username or password.")

    prefill = session.pop("login_handle", None) or form.username.data or ""
    return render_template("auth/login.html", prefill=prefill)


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
    g.duress = False
    token = request.cookies.get(SESSION_COOKIE)
    if not token or current_app.extensions["keyring"].locked:
        return
    db = get_db()
    # a session ends 8 hours after login, or after 30 minutes without a request
    g.user = db.execute(
        "SELECT u.*, s.duress AS session_duress"
        " FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.banned_at IS NULL"
        " AND s.last_seen > datetime('now', '-30 minutes')",
        (token_hash(token),),
    ).fetchone()
    if g.user is not None:
        g.duress = bool(g.user["session_duress"])
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
