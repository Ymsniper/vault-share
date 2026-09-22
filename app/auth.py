import functools

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
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            ok = check_password_of_unknown_user(password)
        else:
            ok = check_password(user["password_hash"], password)

        if not ok:
            audit("login", "failed", user_id=None)
            flash("Incorrect username or password.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            audit("login", "ok", user_id=user["id"])
            return redirect(url_for("files.index"))

    return render_template("auth/login.html")


@bp.route("/logout")
def logout():
    if g.user is not None:
        audit("logout", "ok")
    session.clear()
    return redirect(url_for("auth.login"))


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)

    return wrapped_view
