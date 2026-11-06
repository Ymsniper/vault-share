import sys
import threading
import time

from app import create_app
from app.serving import make_app_server
from app.unlock import unlock_from_terminal, wants_passphrase

app = create_app()

if __name__ == "__main__":
    keyring = app.extensions["keyring"]
    # locks the app within a second of the key USB stick being pulled out
    keyring.watch(app)
    port = app.config["PORT"]
    try:
        server = make_app_server(app, port=port)
    except OSError as e:
        raise SystemExit(f"cannot start on port {port}: {e.strerror}") from None
    scheme = "https" if app.config["HTTPS"] else "http"
    print(f"serving on {scheme}://localhost:{server.port}")
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()
    # the passphrase is typed here, after the start and whenever the stick
    # comes back: the app has no unlock page
    can_ask, told = sys.stdin.isatty(), False
    try:
        while True:
            if wants_passphrase(keyring):
                if can_ask:
                    print("The app is locked.")
                    try:
                        can_ask = unlock_from_terminal(app)
                    except Exception:
                        # the server keeps running, locked or not
                        app.logger.exception("unlocking from the terminal failed")
                    if not keyring.locked:
                        print("Unlocked.")
                elif not told:
                    print("The app is locked, and without a terminal the passphrase cannot be"
                          " asked: run vault-share serve in one, or use the console.")
                    told = True
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
