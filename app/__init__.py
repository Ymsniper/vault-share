import os

from flask import Flask, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

from security.keys import load_or_create_key
from security.uploads import MAX_SIZE

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
        MAX_CONTENT_LENGTH=MAX_SIZE,
        # how long the audit log keeps an entry
        AUDIT_LOG_DAYS=90,
        # made by pki/create_ca.sh; the key is encrypted under CA_PASSPHRASE
        CA_CERT=os.path.join(app.instance_path, "ca", "ca.crt"),
        CA_KEY=os.path.join(app.instance_path, "ca", "ca.key"),
        # written by "flask --app app admin revoke"
        CA_CRL=os.path.join(app.instance_path, "ca", "crl.pem"),
        CA_PASSPHRASE=os.environ.get("CA_PASSPHRASE"),
        # made by pki/create_server_cert.sh
        TLS_CERT=os.path.join(app.instance_path, "tls", "server.crt"),
        TLS_KEY=os.path.join(app.instance_path, "tls", "server.key"),
    )
    if test_config is not None:
        app.config.update(test_config)
    # HTTPS as soon as the server certificate exists; run.py then serves TLS
    app.config.setdefault(
        "HTTPS", os.path.exists(app.config["TLS_CERT"]) and os.path.exists(app.config["TLS_KEY"])
    )

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["STORAGE_FOLDER"], exist_ok=True)

    # signs Flask's session cookie and the CSRF tokens
    if not app.config["SECRET_KEY"]:
        app.config["SECRET_KEY"] = load_or_create_key(
            os.path.join(app.config["SECRETS_DIR"], "secret_key")
        )
    # protects every file key; losing it makes every stored file unreadable
    if not app.config.get("MASTER_KEY"):
        app.config["MASTER_KEY"] = load_or_create_key(
            os.path.join(app.config["SECRETS_DIR"], "master.key")
        )

    from . import admin, auth, db, files, settings, totp

    db.init_app(app)
    csrf.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(files.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(totp.bp)
    app.register_blueprint(settings.bp)
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
        referrer_policy="no-referrer",
    )

    # a plain page for every error, crashes included: no stack trace leaks
    @app.errorhandler(HTTPException)
    def show_error(e):
        return render_template("error.html", error=e), e.code

    return app
