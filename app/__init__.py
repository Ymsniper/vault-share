import os

from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE=os.path.join(app.instance_path, "app.sqlite3"),
        UPLOAD_FOLDER=os.path.join(app.root_path, "static", "uploads"),
        # made by pki/create_ca.sh; the key is encrypted under CA_PASSPHRASE
        CA_CERT=os.path.join(app.instance_path, "ca", "ca.crt"),
        CA_KEY=os.path.join(app.instance_path, "ca", "ca.key"),
        CA_PASSPHRASE=os.environ.get("CA_PASSPHRASE"),
        SESSION_COOKIE_HTTPONLY=False,
    )
    if test_config is not None:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    from . import admin, auth, db, files

    db.init_app(app)
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

    return app
