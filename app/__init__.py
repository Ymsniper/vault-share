import os

from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

from security.keys import load_or_create_key
from security.uploads import MAX_SIZE

csrf = CSRFProtect()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, "app.sqlite3"),
        SECRETS_DIR=os.path.join(app.instance_path, "secrets"),
        # outside the app's static folder, so files are only reachable
        # through the routes that check access
        STORAGE_FOLDER=os.path.join(app.instance_path, "storage"),
        MAX_CONTENT_LENGTH=MAX_SIZE,
        # made by pki/create_ca.sh; the key is encrypted under CA_PASSPHRASE
        CA_CERT=os.path.join(app.instance_path, "ca", "ca.crt"),
        CA_KEY=os.path.join(app.instance_path, "ca", "ca.key"),
        # written by "flask --app app admin revoke"
        CA_CRL=os.path.join(app.instance_path, "ca", "crl.pem"),
        CA_PASSPHRASE=os.environ.get("CA_PASSPHRASE"),
        SESSION_COOKIE_SAMESITE="Lax",
        # run.py turns this on when it serves HTTPS
        SESSION_COOKIE_SECURE=False,
    )
    if test_config is not None:
        app.config.update(test_config)

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

    from . import admin, auth, db, files

    db.init_app(app)
    csrf.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(files.bp)
    app.register_blueprint(admin.bp)

    @app.after_request
    def set_security_headers(response):
        # scripts, styles and images only from this site, no plugins, and
        # the pages can never be shown inside another site's frame
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'none';"
            " form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # a plain page for every error, crashes included: no stack trace leaks
    @app.errorhandler(HTTPException)
    def show_error(e):
        return render_template("error.html", error=e), e.code

    return app
