from app import create_app
from app.serving import make_app_server

app = create_app()

if __name__ == "__main__":
    # locks the app within a second of the key USB stick being pulled out
    app.extensions["keyring"].watch(app)
    try:
        server = make_app_server(app)
    except OSError as e:
        raise SystemExit(f"cannot start on port 5000: {e.strerror}") from None
    scheme = "https" if app.config["HTTPS"] else "http"
    print(f"serving on {scheme}://localhost:{server.port}")
    server.serve_forever()
