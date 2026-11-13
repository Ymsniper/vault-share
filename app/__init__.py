import os

from flask import Flask, g, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from security.keys import load_or_create_key

from . import server_settings
from .keyring import Keyring, Locked

csrf = CSRFProtect()
talisman = Talisman()
# counters are kept in memory, so they start from zero when the app restarts
limiter = Limiter(get_remote_address, storage_uri="memory://", strategy="moving-window")


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, "app.sqlite3"),
        SECRETS_DIR=os.path.join(app.instance_path, "secrets"),
        # outside the app's static folder, so files are only reachable
        # through the routes that check access
        STORAGE_FOLDER=os.path.join(app.instance_path, "storage"),
        # how long the audit log keeps an entry
        AUDIT_LOG_DAYS=90,
        # where USB sticks are mounted on Linux
        USB_MOUNT_ROOTS=["/run/media", "/media", "/mnt"],
        # made by pki/create_ca.sh; the key is encrypted under CA_PASSPHRASE
        CA_CERT=os.path.join(app.instance_path, "ca", "ca.crt"),
        CA_KEY=os.path.join(app.instance_path, "ca", "ca.key"),
        # written by "flask --app app admin revoke"
        CA_CRL=os.path.join(app.instance_path, "ca", "crl.pem"),
        CA_PASSPHRASE=os.environ.get("CA_PASSPHRASE"),
        # made by pki/create_server_cert.sh
        TLS_CERT=os.path.join(app.instance_path, "tls", "server.crt"),
        TLS_KEY=os.path.join(app.instance_path, "tls", "server.key"),
        # BEHIND_PROXY=1 when a proxy on this machine (Tailscale Funnel)
        # passes the requests on; see "A public link" in the README
        BEHIND_PROXY=os.environ.get("BEHIND_PROXY") == "1",
        # seconds before a new duress password starts to work, so nobody who
        # watches it being set can try it on the spot
        DURESS_DELAY=48 * 3600,
    )
    if test_config is not None:
        app.config.update(test_config)
    # the port and the largest upload, set at the server; see server_settings.py
    app.config.setdefault("SETTINGS_FILE", os.path.join(app.instance_path, "server.toml"))
    settings, problem = server_settings.load(app.config["SETTINGS_FILE"])
    app.config.setdefault("PORT", settings["port"])
    app.config.setdefault("MAX_UPLOAD_MB", settings["max_upload_mb"])
    app.config["MAX_CONTENT_LENGTH"] = server_settings.upload_limit(app.config["MAX_UPLOAD_MB"])
    app.config["SETTINGS_PROBLEM"] = problem
    if problem:
        app.logger.warning(problem)
    # HTTPS as soon as the server certificate exists; run.py then serves TLS
    app.config.setdefault(
        "HTTPS", os.path.exists(app.config["TLS_CERT"]) and os.path.exists(app.config["TLS_KEY"])
    )
    if app.config["BEHIND_PROXY"]:
        # every request then arrives from the proxy, so the rate limits and
        # the audit log take the visitor's address from X-Forwarded-For;
        # only the last address counts, the one the proxy itself added
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["STORAGE_FOLDER"], exist_ok=True)

    # signs Flask's session cookie and the CSRF tokens
    if not app.config["SECRET_KEY"]:
        app.config["SECRET_KEY"] = load_or_create_key(
            os.path.join(app.config["SECRETS_DIR"], "secret_key")
        )
    # the master key protects the database, the file records' HMACs and the
    # TOTP secrets, not the file keys (those need a user's password); it
    # comes from instance/secrets/master.key, plus the USB stick and the
    # passphrase if they were added with "flask --app app keys"
    keyring = Keyring(app.config["SECRETS_DIR"], app.config["USB_MOUNT_ROOTS"])
    app.extensions["keyring"] = keyring

    # first of the checks, so nothing touches the database while locked;
    # there is no unlock page, the console or the server's terminal unlocks
    @app.before_request
    def stop_when_locked():
        if keyring.locked and request.endpoint != "static":
            raise Locked(keyring.missing())

    from . import admin, auth, db, files, invites, settings, totp, unlock

    db.init_app(app)

    # next, a database made for another version of the tables pauses every
    # page too, rather than the ones that happen to read a changed column
    @app.before_request
    def stop_when_outdated():
        if request.endpoint != "static":
            db.get_db()
    csrf.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(files.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(totp.bp)
    app.register_blueprint(settings.bp)
    app.cli.add_command(unlock.keys_cli)
    app.cli.add_command(invites.invite_cli)
    app.cli.add_command(server_settings.settings_command)
    app.add_template_filter(auth.show_handle, "handle")
    # after the blueprints, so the limits can already see who is logged in
    limiter.init_app(app)

    https = app.config["HTTPS"]
    talisman.init_app(
        app,
        # over HTTPS: plain HTTP requests are redirected and cookies are Secure
        force_https=https,
        session_cookie_secure=https,
        # HSTS would make the browser refuse plain HTTP for every server on
        # localhost, other projects included, so this local app leaves it off
        strict_transport_security=False,
        # scripts, styles and images only from this site, no plugins, and
        # the pages can never be shown inside another site's frame
        content_security_policy={
            "default-src": "'self'",
            "object-src": "'none'",
            "base-uri": "'none'",
            "form-action": "'self'",
            "frame-ancestors": "'none'",
        },
        frame_options="DENY",
        # the Referer reaches this site only: Flask-WTF checks it on every form
        # sent over HTTPS, and other sites never learn our URLs
        referrer_policy="same-origin",
    )

    @app.after_request
    def no_cache_when_logged_in(response):
        # a logged-in user's pages and downloads hold names, descriptions and
        # files, which must not stay in the browser's cache after logout
        if g.get("user") is not None and request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(Locked)
    def show_locked(e):
        # visitors only learn that the service is paused; why is for the
        # operator, in the server log
        app.logger.warning("locked: %s", e)
        return render_template("locked.html"), 503

    @app.errorhandler(db.OutdatedDatabase)
    def show_outdated(e):
        # the same for a database made for another version: the operator
        # resets it, and the console and the server's terminal say how
        app.logger.warning("database: %s", e.message)
        return render_template("locked.html"), 503

    # a plain page for every error, crashes included: no stack trace leaks
    @app.errorhandler(HTTPException)
    def show_error(e):
        return render_template("error.html", error=e), e.code

    return app
