import functools
import hashlib
import hmac
import ipaddress
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
from itsdangerous import BadSignature, URLSafeTimedSerializer
from limits import parse
from markupsafe import Markup, escape

from security.keys import subkey

from . import levels, limiter
from .audit import audit, network_of
from .db import get_db
from .forms import LoginForm, NewPasswordForm, RegisterForm, first_error
from .identity import load_app_ca, new_identity
from .invites import INVALID, usable_invite, use_invite

bp = Blueprint("auth", __name__, url_prefix="/auth")

SESSION_COOKIE = "sid"


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user_id, level):
    """Create a server-side session at a level and return its token for the
    cookie."""
    token = secrets.token_urlsafe(32)
    db = get_db()
    db.execute(
        "DELETE FROM sessions WHERE expires_at <= datetime('now')"
        " OR last_seen <= datetime('now', '-30 minutes')"
    )
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at, level)"
        " VALUES (?, ?, datetime('now', '+8 hours'), ?)",
        (token_hash(token), user_id, level),
    )
    db.commit()
    return token


def finish_login(user, level):
    """Start a fresh server-side session for user at the level the password
    opened, and send its cookie. The login row is the only trace of the
    level: at level 1 or 2 it is the silent alarm."""
    # a token the browser already had, maybe planted by someone else, is
    # never reused: every login gets a fresh one
    old_token = request.cookies.get(SESSION_COOKIE)
    if old_token:
        end_session(old_token)
    session.clear()
    # a login at one level closes the duress windows of the levels below
    # it; what happened in them is for its logins to review, until done
    levels.note_login(user, level)
    # a duress password in wipe mode destroys what it was set for once the
    # login is complete, after its window opened, so a review finds it all
    if levels.wipes(user, level):
        levels.wipe(user, level)
    token = start_session(user["id"], level)
    audit("login", "ok", user_id=user["id"], level=level,
          detail=levels.alarm_detail(user, level))
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    due = levels.review_due_at(user, level)
    response = redirect(url_for("settings.review" if due else "files.index"))
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="Lax",
        secure=current_app.config["SESSION_COOKIE_SECURE"],
    )
    remember_browser(response, user["username"])
    return response


# A browser that logged in as someone gets a cookie saying so, kept a year:
# guesses from browsers without one share a single budget per username, so
# many addresses together cannot try an account endlessly, while its owner
# is never locked out of a browser they have used.
DEVICE_COOKIE = "device"
DEVICE_SECONDS = 365 * 24 * 3600
DEVICE_NAMES = 5


def device_serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt="device")


def device_digest(username):
    """A keyed digest of the username, so the cookie names nobody."""
    key = subkey(current_app.secret_key, "device")
    return hmac.new(key, username.encode(), hashlib.sha256).hexdigest()[:32]


def known_here():
    """The digests of the usernames that logged in from this browser; none
    for a cookie that is missing, expired or not signed by this server."""
    value = request.cookies.get(DEVICE_COOKIE)
    if not value:
        return []
    try:
        digests = device_serializer().loads(value, max_age=DEVICE_SECONDS)
    except BadSignature:
        return []
    return [d for d in digests if isinstance(d, str)] if isinstance(digests, list) else []


def remember_browser(response, username):
    mine = device_digest(username)
    digests = [mine, *(d for d in known_here() if d != mine)][:DEVICE_NAMES]
    response.set_cookie(
        DEVICE_COOKIE,
        device_serializer().dumps(digests),
        max_age=DEVICE_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=current_app.config["SESSION_COOKIE_SECURE"],
    )


def end_session(token):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
    db.commit()


LOCKED = "Too many failed attempts. Try again in 15 minutes."
BUSY = "Too many attempts at once. Try again in a moment."
TOO_MANY = "Too many password checks. Try again in 15 minutes."

FIVE = parse("5 per 15 minutes")
TWENTY = parse("20 per 15 minutes")
SIXTY = parse("60 per 15 minutes")
TEN_AN_HOUR = parse("10 per hour")
FIFTY_AN_HOUR = parse("50 per hour")

# the scope that counts every check of a logged-in account, right or wrong
EVERY_CHECK = "checks"

# Flask-Limiter's deduct_when records a failure only once the response is
# built, so requests sent together would all pass the check before any of
# them counted. A password check therefore counts as in flight from the
# moment it is let through until it is settled.
_gate = threading.Condition()
_in_flight = Counter()
# requests waiting for a check in flight to end, per key
_waiting = Counter()
WAIT_SECONDS = 10
MAX_WAITING = 8


def verdict_now(limits):
    """Under _gate: None, LOCKED when the failures recorded in a window fill
    its limit (TOO_MANY for the count of every check), or BUSY when the
    checks in flight do."""
    verdict = None
    for item, scope, key in limits:
        remaining = limiter.limiter.get_window_stats(item, scope, key).remaining
        if remaining <= 0:
            return TOO_MANY if scope == EVERY_CHECK else LOCKED
        if remaining <= _in_flight[scope, key]:
            verdict = BUSY
    return verdict


def admit(limits):
    """None if a password check may run under limits, a list of (item,
    scope, key), else why not: LOCKED, TOO_MANY or BUSY.

    A request held back only by the checks in flight waits for one of them
    to end, up to WAIT_SECONDS and at most MAX_WAITING per key, so a few
    downloads started together all go through. It is then refused if those
    checks failed and filled the limit."""
    deadline = time.monotonic() + WAIT_SECONDS
    with _gate:
        verdict = verdict_now(limits)
        if verdict == BUSY and all(_waiting[s, k] < MAX_WAITING for _, s, k in limits):
            for _, scope, key in limits:
                _waiting[scope, key] += 1
            try:
                while verdict == BUSY and _gate.wait(max(0, deadline - time.monotonic())):
                    verdict = verdict_now(limits)
                # the wait is over: a last look
                verdict = verdict_now(limits)
            finally:
                for _, scope, key in limits:
                    _waiting[scope, key] -= 1
                    if not _waiting[scope, key]:
                        del _waiting[scope, key]
        if verdict is None:
            for _, scope, key in limits:
                _in_flight[scope, key] += 1
        return verdict


def settle(limits, failed, every=()):
    """Record a failed check, and the check against the limits in every,
    which count right ones too; then stop counting it as in flight, in this
    order, so it is never counted nowhere, and let the waiting requests
    look again."""
    if failed:
        for item, scope, key in limits:
            limiter.limiter.hit(item, scope, key)
    for item, scope, key in every:
        limiter.limiter.hit(item, scope, key)
    with _gate:
        for _, scope, key in [*limits, *every]:
            _in_flight[scope, key] -= 1
            if not _in_flight[scope, key]:
                del _in_flight[scope, key]
        _gate.notify_all()


# locks already written to the audit log, with the time each one ends
_reported = {}


def first_sight_of_lock(limits):
    """True the first time a lock is refused in its window. Later refusals
    are not logged, so a locked visitor cannot fill the audit log."""
    now = time.time()
    with _gate:
        for item, scope, key in limits:
            stats = limiter.limiter.get_window_stats(item, scope, key)
            if stats.remaining > 0 or _reported.get((scope, key), 0) > now:
                continue
            for old in [k for k, ends in _reported.items() if ends <= now]:
                del _reported[old]
            _reported[scope, key] = stats.reset_time
            return True
    return False


def password_ok(password):
    """Whether password is the session's own. Every password asked inside a
    session goes through here: it must open the lock of the session's
    level, so no form can test the password of another level."""
    return levels.unlock(password) is not None


def current_account():
    """The logged-in account and its session's level: only the account's
    own sessions count toward the limits of its password checks, and each
    level apart, so what one level does never shows as a limit at another."""
    return f"{g.user['id']}:{g.level}" if g.get("user") else None


def pending_key(user_id, sealed):
    """The key the two-factor code step counts toward, per account and level
    like current_account()."""
    return f"{user_id}:{levels.pending_level(user_id, sealed)}"


def finish_pending_login(user, sealed, recovery=False):
    """After the right code, the session at its level, with the wipe a
    duress password in wipe mode asked for. A recovery code used instead
    of the phone is logged at that level too."""
    level = levels.pending_level(user["id"], sealed)
    if recovery:
        audit("totp", "recovery code used", user_id=user["id"], level=level)
    return finish_login(user, level)


def client_key():
    """The visitor's address as the login limits count it. An IPv6 visitor
    counts by their /48, the network part the audit log keeps: a single
    subscriber can move across a whole /64 or more."""
    address = get_remote_address()
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 6:
        return str(ip.ipv4_mapped) if ip.ipv4_mapped else network_of(address)
    return address


def login_key():
    # one username from one address, so wrong tries elsewhere never lock the
    # owner out; cut, since the field is not validated yet and the key is kept
    return f"{request.form.get('username', '')[:40]}|{client_key()}"


def stranger_key():
    """The username alone, for a browser that never logged in with it:
    those browsers share one budget per account, wherever they are."""
    username = request.form.get("username", "")[:40]
    return None if device_digest(username) in known_here() else username


def password_limit(key_func, item=FIVE, scope="account", log=True):
    """Wrong passwords sent with POST count toward item for key_func(), and
    a key of None counts nowhere. The view sets g.wrong_password when it
    refused a password. By default 5 wrong passwords in a logged-in account,
    at upload, download, share, revoke, delete or in its settings, block its
    password checks for 15 minutes, and so do 60 checks of any kind: each
    one holds an Argon2 slot, which the account must not keep to itself.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if request.method != "POST":
                return view(*args, **kwargs)
            key = key_func()
            limits = [] if key is None else [(item, scope, key)]
            every = [(SIXTY, EVERY_CHECK, key)] if key is not None and scope == "account" else []
            verdict = admit(limits + every)
            if verdict in (LOCKED, TOO_MANY) and log and first_sight_of_lock(limits + every):
                detail = "too many checks" if verdict == TOO_MANY else None
                audit("password", "locked", detail=detail, user_id=None)
            if verdict is not None:
                abort(429, verdict)
            try:
                return view(*args, **kwargs)
            finally:
                settle(limits, g.get("wrong_password", False), every)
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
                # the sealed levels are written once the credentials exist
                cur = db.execute(
                    "INSERT INTO users (username, duress_policy, invite_id) VALUES (?, ?, ?)",
                    (handle, b"", invite_id),
                )
            except db.IntegrityError:
                # the same tag drawn twice for this name, about one in a million;
                # the rollback also gives the invite back
                db.rollback()
                handle = session["new_handle"] = new_handle(name)
                error = "That tag was just taken, so here is another one. Register with it."
            else:
                user_id = cur.lastrowid
                bottom = levels.new_account(user_id, handle, password)
                new_identity(user_id, handle, bottom, ca)
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
# 20 from one address, so one machine cannot try many accounts
@password_limit(client_key, TWENTY, "login-address")
# and 50 an hour for one username from all the browsers it never logged in
# from, so many addresses together cannot either
@password_limit(stranger_key, FIFTY_AN_HOUR, "login-username")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        level = levels.login_level(user, password)

        if level is None:
            g.wrong_password = True
            audit("login", "failed", user_id=None)
            flash("Incorrect username or password.")
        elif user["banned_at"] is not None:
            # after the password check, so only the owner learns of the ban
            audit("login", "refused", user_id=user["id"], detail="banned")
            flash("This account is disabled.")
        else:
            if levels.two_factor_at(user["id"], level)["on"]:
                # right password, but no session until the code is right
                # too; a duress login's alarm is this row, written now, and
                # a wipe waits for the code, so the password alone destroys
                # nothing
                audit("login", "code asked", user_id=user["id"], level=level,
                      detail=levels.alarm_detail(user, level, waits=True))
                session.clear()
                session["totp_user_id"] = user["id"]
                session["totp_started"] = time.time()
                session["totp_mode"] = levels.seal_pending(user["id"], level)
                return redirect(url_for("totp.login_code"))
            return finish_login(user, level)
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


# what a visitor without a session may send: every form they can use fits
STRANGER_BODY = 64 * 1024


@bp.before_app_request
def load_logged_in_user():
    _find_user()
    if g.user is None:
        # a larger body is refused before it is read, before the CSRF check
        # reads the form (app/__init__.py registers that one after this)
        request.max_content_length = STRANGER_BODY


def _find_user():
    g.user = g.level = None
    token = request.cookies.get(SESSION_COOKIE)
    if not token or current_app.extensions["keyring"].locked:
        return
    db = get_db()
    # a session ends 8 hours after login, or after 30 minutes without a request
    g.user = db.execute(
        "SELECT u.*, s.level AS session_level, s.totp_pending AS session_totp_pending"
        " FROM sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.banned_at IS NULL"
        " AND s.last_seen > datetime('now', '-30 minutes')",
        (token_hash(token),),
    ).fetchone()
    if g.user is not None:
        g.level = g.user["session_level"]
        g.session_hash = token_hash(token)
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
