import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    cert = os.path.join(app.instance_path, "tls", "server.crt")
    key = os.path.join(app.instance_path, "tls", "server.key")
    if os.path.exists(cert) and os.path.exists(key):
        # made by pki/create_server_cert.sh; cookies then only travel over HTTPS
        app.config["SESSION_COOKIE_SECURE"] = True
        app.run(ssl_context=(cert, key))
    else:
        app.run()
