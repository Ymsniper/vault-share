"""Server console: run the app, unlock it and do the admin tasks from one
screen. Every action here also exists as a `flask --app app ...` command."""

import asyncio
import errno
import logging
import os
# only runs the fixed scripts in pki/
import subprocess  # nosec B404
import threading
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

from flask.logging import default_handler
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Center, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Input,
    Label,
    OptionList,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from app.admin import grant_admin, revoke_certificate
from app.db import get_db, init_db
from app.serving import make_app_server
from app.unlock import (
    FactorError,
    add_usb,
    mounted_sticks,
    remove_passphrase,
    remove_usb,
    set_passphrase,
)
from security.passwords import passphrase_problem
from security.pki import load_ca, load_ca_certificate

HERE = Path(__file__).parent
PKI = HERE.parent / "pki"


class Server:
    """The Flask app served from a background thread."""

    def __init__(self, flask_app, host="127.0.0.1", port=5000):
        self.flask_app = flask_app
        self.host, self.port = host, port
        self._httpd = None

    @property
    def running(self):
        return self._httpd is not None

    @property
    def url(self):
        scheme = "https" if self.flask_app.config["HTTPS"] else "http"
        return f"{scheme}://localhost:{self.port}"

    def start(self):
        httpd = make_app_server(self.flask_app, self.host, self.port)
        self.port = httpd.port
        threading.Thread(target=httpd.serve_forever, name="http", daemon=True).start()
        # only now: stop() waits for serve_forever, which must be running
        self._httpd = httpd

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


class ToLogPane(logging.Handler):
    """Sends the app's and the web server's log lines to the console."""

    def __init__(self, console):
        super().__init__()
        self.console = console

    def emit(self, record):
        line = Text.from_ansi(self.format(record))
        if record.levelno >= logging.WARNING:
            line.stylize("bold")
        try:
            self.console.call_from_thread(self.console.log_line, line)
        except RuntimeError:  # already on the console's own thread
            self.console.log_line(line)


class Ask(ModalScreen):
    """A small form: one input per field, returns the values or None."""

    def __init__(self, title, fields, note=""):
        super().__init__()
        self.title_text, self.fields, self.note = title, fields, note

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.title_text, classes="dialog-title")
            if self.note:
                yield Static(Text(self.note), classes="dialog-note")
            for i, (label, secret) in enumerate(self.fields):
                yield Input(placeholder=label, password=secret, id=f"field-{i}")
            with Horizontal(classes="dialog-buttons"):
                yield Button("OK", variant="primary", id="ok", compact=True)
                yield Button("Cancel", id="cancel", compact=True)

    @on(Input.Submitted)
    def next_field(self, event):
        inputs = list(self.query(Input))
        i = inputs.index(event.input)
        if i + 1 < len(inputs):
            inputs[i + 1].focus()
        else:
            self.query_one("#ok", Button).press()

    @on(Button.Pressed, "#ok")
    def ok(self):
        self.dismiss([i.value for i in self.query(Input)])

    @on(Button.Pressed, "#cancel")
    def cancel(self):
        self.dismiss(None)

    def key_escape(self):
        self.dismiss(None)


class Choose(ModalScreen):
    def __init__(self, title, options):
        super().__init__()
        self.title_text, self.options = title, options

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.title_text, classes="dialog-title")
            yield OptionList(*[Text(o) for o in self.options])
            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", id="cancel", compact=True)

    @on(OptionList.OptionSelected)
    def chosen(self, event):
        self.dismiss(self.options[event.option_index])

    @on(Button.Pressed, "#cancel")
    def cancel(self):
        self.dismiss(None)

    def key_escape(self):
        self.dismiss(None)


class Show(ModalScreen):
    """A message that stays until it is acknowledged, such as a recovery code."""

    def __init__(self, title, text, button="Close"):
        super().__init__()
        self.title_text, self.text, self.button = title, text, button

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.title_text, classes="dialog-title")
            yield Static(Text(self.text), classes="dialog-text")
            with Horizontal(classes="dialog-buttons"):
                yield Button(self.button, variant="primary", id="close", compact=True)

    @on(Button.Pressed, "#close")
    def close(self):
        self.dismiss(True)


class Splash(Screen):
    """The art, the name, then the real state of the server as it is checked."""

    def __init__(self, checks):
        super().__init__()
        self.checks = checks

    def compose(self) -> ComposeResult:
        with Vertical(id="splash"):
            yield Static((HERE / "splash.txt").read_text().rstrip("\n"), id="art")
            yield Static("", id="name")
            with Center():
                yield Static("", id="checks")
            yield Static("", id="hint")

    def on_mount(self):
        art = self.query_one("#art")
        art.styles.opacity = 0
        art.styles.animate("opacity", 1.0, duration=0.8)
        self.typed = 0
        self.set_interval(0.04, self.type_name)

    NAME = "file sharing server"

    def type_name(self):
        if self.typed < len(self.NAME):
            self.typed += 1
            self.query_one("#name", Static).update(Text(self.NAME[: self.typed], style="bold"))
        elif self.typed == len(self.NAME):
            self.typed += 1
            self.show_checks()

    @work
    async def show_checks(self):
        lines = Text()
        for label, value, ok in self.checks():
            lines.append(" ✓ " if ok else " ! ", style="bold")
            lines.append(f" {label:<10}", style="bold")
            lines.append(f"{value}\n", style="" if ok else "italic")
            self.query_one("#checks", Static).update(lines)
            await asyncio.sleep(0.12)
        self.query_one("#hint", Static).update(Text("press any key", style="dim"))

    def on_key(self, event):
        event.stop()
        self.app.switch_screen("main")


class Main(Screen):
    BINDINGS = [
        Binding("s", "app.toggle_server", "Start/stop"),
        Binding("u", "app.unlock", "Unlock"),
        Binding("r", "app.refresh", "Refresh"),
        Binding("q", "app.quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Static("", id="status")
        with TabbedContent(id="tabs"):
            with TabPane("Server", id="server-tab"):
                with Horizontal(classes="buttons"):
                    yield Button("Start", id="start", variant="primary", compact=True)
                    yield Button("Stop", id="stop", compact=True)
                    yield Button("Unlock", id="unlock", compact=True)
                yield RichLog(id="log", wrap=True, markup=False)
            with TabPane("Users", id="users-tab"):
                with Horizontal(classes="buttons"):
                    yield Button("Make admin", id="grant", compact=True)
                    yield Button("Revoke certificate", id="revoke", variant="error", compact=True)
                yield DataTable(id="users", cursor_type="row")
            with TabPane("Audit log", id="log-tab"):
                yield DataTable(id="audit", cursor_type="row")
            with TabPane("Keys", id="keys-tab"):
                yield Static("", id="factors")
                with Horizontal(classes="buttons"):
                    yield Button("Add USB stick", id="add-usb", compact=True)
                    yield Button("Remove USB stick", id="remove-usb", compact=True)
                with Horizontal(classes="buttons"):
                    yield Button("Set passphrase", id="set-passphrase", compact=True)
                    yield Button("Remove passphrase", id="remove-passphrase", compact=True)
            with TabPane("Setup", id="setup-tab"):
                yield Static("", id="setup-state")
                with Horizontal(classes="buttons"):
                    yield Button("Create the CA", id="create-ca", compact=True)
                    yield Button("Enter CA passphrase", id="ca-passphrase", compact=True)
                    yield Button("New HTTPS certificate", id="server-cert", compact=True)
                with Horizontal(classes="buttons"):
                    yield Button("Reset database", id="reset-db", variant="error", compact=True)
        yield Footer()

    def on_mount(self):
        self.query_one("#users", DataTable).add_columns(
            "User", "Admin", "Two-factor", "Certificate", "Files"
        )
        self.query_one("#audit", DataTable).add_columns(
            "Time (UTC)", "User", "Action", "File", "Outcome", "Detail", "Network"
        )
        self.set_interval(1, self.app.show_status)
        self.set_interval(3, self.app.load_audit)
        self.app.main_ready()
        self.app.ask_ca_passphrase()


def certificate_state(path):
    """(still valid, how it reads) for the certificate in path."""
    try:
        end = load_ca_certificate(path).not_valid_after_utc
    except (OSError, ValueError):
        return False, "unreadable"
    if end < datetime.now(timezone.utc):
        return False, f"expired on {end:%Y-%m-%d}"
    return True, f"valid until {end:%Y-%m-%d}"


class Console(App):
    CSS_PATH = "console.tcss"
    TITLE = "File sharing server"

    def __init__(self, flask_app, start_server=True):
        # the terminal's own palette, not a Textual theme
        super().__init__(ansi_color=True)
        self.flask_app = flask_app
        self.keyring = flask_app.extensions["keyring"]
        self.server = Server(flask_app)
        self.start_server = start_server
        # log lines that arrive before the log pane exists, during the splash
        self.pending = []
        self.ready = False

    def on_mount(self):
        self.install_screen(Main(), "main")
        self.handler = ToLogPane(self)
        self.handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))
        # replaces Flask's and Werkzeug's own output, which would draw over the screen
        self.flask_app.logger.removeHandler(default_handler)
        for logger in (self.flask_app.logger, logging.getLogger("werkzeug")):
            logger.addHandler(self.handler)
            logger.setLevel(logging.INFO)
            logger.propagate = False
        self.keyring.watch(self.flask_app)
        if self.start_server:
            self.do_start()
        self.push_screen(Splash(self.startup_checks))

    def on_unmount(self):
        self.do_stop()
        for logger in (self.flask_app.logger, logging.getLogger("werkzeug")):
            logger.removeHandler(self.handler)

    # --- state shown everywhere

    def startup_checks(self):
        cfg, k = self.flask_app.config, self.keyring
        factors = ["machine key"]
        if k.needs_usb:
            factors.append("USB stick" + (" (found)" if k.find_usb_share() else " (missing)"))
        if k.needs_passphrase:
            factors.append("passphrase")
        return [
            ("key", " + ".join(factors), not k.locked or k.needs_passphrase),
            ("database", "encrypted with SQLCipher" if os.path.exists(cfg["DATABASE"]) else
             "not created yet: Setup > Reset database", os.path.exists(cfg["DATABASE"])),
            ("CA", "ready" if os.path.exists(cfg["CA_CERT"]) else "missing: Setup > Create the CA",
             os.path.exists(cfg["CA_CERT"])),
            ("HTTPS", "on" if cfg["HTTPS"] else "off (plain HTTP on localhost)", True),
            ("server", self.server.url if self.server.running else "stopped", self.server.running),
            ("lock", "unlocked" if not k.locked else k.missing(), not k.locked),
        ]

    def setup_state(self):
        """What the Setup tab shows: the CA, its passphrase and the HTTPS
        certificate as they are right now."""
        cfg = self.flask_app.config
        rows = []
        if os.path.exists(cfg["CA_KEY"]):
            valid, dates = certificate_state(cfg["CA_CERT"])
            rows.append(("CA", f"ready, {dates}" if valid else dates))
            rows.append(("CA passphrase", "entered: new users can register"
                         if cfg.get("CA_PASSPHRASE") else "not entered: registration is off"))
        else:
            rows.append(("CA", "missing: create it first, registration needs it"))
        if cfg["HTTPS"]:
            https = "in use, " + certificate_state(cfg["TLS_CERT"])[1]
        elif os.path.exists(cfg["TLS_CERT"]):
            valid, dates = certificate_state(cfg["TLS_CERT"])
            https = f"ready, {dates}, in use once the console restarts" if valid else dates
        else:
            https = "none (optional): plain HTTP on localhost"
        rows.append(("HTTPS certificate", https))
        text = Text()
        for label, value in rows:
            text.append(f"{label:<20}", style="bold")
            text.append(f"{value}\n")
        text.append("\nReset database deletes every user, file and log entry.")
        return text

    def show_status(self):
        main = self.get_screen("main")
        k = self.keyring
        line = Text()
        if self.server.running:
            line.append("● running ", style="bold")
            line.append(f"{self.server.url}   ")
        else:
            line.append("○ stopped   ", style="bold")
        if k.locked:
            line.append("LOCKED", style="reverse bold")
        else:
            line.append("unlocked")
        if k.locked:
            line.append(f"  {k.missing()}")
        else:
            users, files = self.counts()
            line.append(f"   {users} users, {files} files")
        main.query_one("#status", Static).update(line)
        factors = ["machine key"]
        if k.needs_usb:
            factors.append("USB stick" + (", plugged in" if k.find_usb_share() else ", missing"))
        if k.needs_passphrase:
            factors.append("passphrase")
        cfg = self.flask_app.config
        ca = os.path.exists(cfg["CA_KEY"])
        # only the buttons that make sense right now
        for button_id, enabled in (
            ("#start", not self.server.running),
            ("#stop", self.server.running),
            ("#unlock", k.locked and k.needs_passphrase),
            ("#grant", not k.locked),
            ("#revoke", not k.locked),
            ("#add-usb", not k.needs_usb and not k.locked),
            ("#remove-usb", k.needs_usb),
            ("#set-passphrase", not k.needs_passphrase and not k.locked),
            ("#remove-passphrase", k.needs_passphrase),
            # create_ca.sh refuses to replace a CA key anyway: a new CA would
            # make every certificate already issued untrusted
            ("#create-ca", not ca),
            ("#ca-passphrase", ca and not cfg.get("CA_PASSPHRASE")),
            ("#server-cert", ca),
            ("#reset-db", not k.locked),
        ):
            main.query_one(button_id, Button).disabled = not enabled
        main.query_one("#factors", Static).update(
            Text("The master key is made of: " + " + ".join(factors) + ".\n"
                 "Changing it stops the server for a moment, then starts it again.")
        )
        main.query_one("#setup-state", Static).update(self.setup_state())

    def counts(self):
        try:
            with self.flask_app.app_context():
                db = get_db()
                return (
                    db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                    db.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                )
        except Exception:
            return "?", "?"

    def log_line(self, line):
        if not self.ready:
            self.pending.append(line)
            return
        self.get_screen("main").query_one("#log", RichLog).write(line)

    def main_ready(self):
        self.ready = True
        for line in self.pending:
            self.log_line(line)
        self.pending.clear()
        self.refresh_all()

    def refresh_all(self):
        self.show_status()
        self.load_users()
        self.load_audit()

    def load_users(self):
        table = self.get_screen("main").query_one("#users", DataTable)
        table.clear()
        if self.keyring.locked:
            return
        with self.flask_app.app_context():
            rows = get_db().execute(
                "SELECT u.username, u.is_admin, u.totp_secret IS NOT NULL AS totp,"
                " (SELECT CASE WHEN c.revoked_at IS NOT NULL THEN 'revoked'"
                "  ELSE 'until ' || substr(c.not_after, 1, 10) END"
                "  FROM certificates c WHERE c.user_id = u.id ORDER BY c.id DESC LIMIT 1) AS cert,"
                " (SELECT COUNT(*) FROM files f WHERE f.owner_id = u.id) AS files"
                " FROM users u ORDER BY u.username"
            ).fetchall()
        for r in rows:
            # plain Text, never markup: a name must not be able to style the screen
            table.add_row(
                Text(r["username"]),
                "yes" if r["is_admin"] else "",
                "on" if r["totp"] else "",
                Text(r["cert"] or "none"),
                str(r["files"]),
                key=r["username"],
            )

    def load_audit(self):
        table = self.get_screen("main").query_one("#audit", DataTable)
        if self.keyring.locked:
            table.clear()
            return
        with self.flask_app.app_context():
            rows = get_db().execute(
                "SELECT a.at, u.username, a.action, a.file_id, a.outcome, a.detail, a.ip"
                " FROM audit_log a LEFT JOIN users u ON u.id = a.user_id"
                " ORDER BY a.id DESC LIMIT 200"
            ).fetchall()
        table.clear()
        for r in rows:
            table.add_row(*(Text(str(v) if v is not None else "") for v in tuple(r)))

    def selected_user(self):
        table = self.get_screen("main").query_one("#users", DataTable)
        if table.row_count == 0:
            return None
        return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

    # --- server

    def do_start(self):
        if self.server.running:
            return
        try:
            self.server.start()
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                message = (f"Cannot start: port {self.server.port} is already in use. Is another "
                           "console or 'vault-share serve' still running?")
            else:
                message = f"Cannot start: {e}"
            self.notify(message, severity="error", timeout=12)
            return
        self.log_line(Text(f"server started on {self.server.url}", style="bold"))

    def do_stop(self):
        if self.server.running:
            self.server.stop()
            self.log_line(Text("server stopped", style="bold"))

    @on(Button.Pressed, "#start")
    def start_pressed(self):
        self.do_start()
        self.show_status()

    @on(Button.Pressed, "#stop")
    def stop_pressed(self):
        self.do_stop()
        self.show_status()

    def action_toggle_server(self):
        if self.server.running:
            self.do_stop()
        else:
            self.do_start()
        self.show_status()

    def action_refresh(self):
        self.refresh_all()

    async def action_quit(self):
        self.do_stop()
        self.exit()

    # --- unlock

    @on(Button.Pressed, "#unlock")
    def action_unlock(self):
        if not self.keyring.locked:
            self.notify("Already unlocked.")
        elif not self.keyring.needs_passphrase:
            self.notify(self.keyring.missing(), severity="warning")
        else:
            self.push_screen(Ask("Unlock", [("Passphrase", True)]), self.unlock_with)

    @work(thread=True)
    def unlock_with(self, values):
        if not values:
            return
        try:
            self.keyring.unlock(values[0])
        except Exception as e:
            self.call_from_thread(self.notify, str(e), severity="error")
            return
        self.call_from_thread(self.notify, "Unlocked.")
        self.call_from_thread(self.refresh_all)

    # --- users

    @on(Button.Pressed, "#grant")
    def grant_pressed(self):
        user = self.selected_user()
        if user:
            self.run_task(f"{user} can now read the audit log.", grant_admin, user)

    @on(Button.Pressed, "#revoke")
    def revoke_pressed(self):
        user = self.selected_user()
        if user:
            self.run_task(f"Revoked {user}'s certificate.", revoke_certificate, user)

    @work(thread=True)
    def run_task(self, done, action, *args, stop_server=False):
        """An app task in its own thread, then a message saying it is done."""
        if self.task(action, *args, stop_server=stop_server) is not None:
            self.call_from_thread(self.notify, done)

    def task(self, action, *args, stop_server=False):
        """Run action with the app context it needs. Called from a worker
        thread; returns its result, or None after showing why it failed."""
        was_running = self.server.running
        if stop_server and was_running:
            self.call_from_thread(self.do_stop)
        try:
            with self.flask_app.app_context():
                result = action(*args)
            if result is None:
                result = True
        except (ValueError, FactorError) as e:
            self.call_from_thread(self.notify, str(e), severity="error")
            result = None
        finally:
            if stop_server and was_running:
                self.call_from_thread(self.do_start)
            self.call_from_thread(self.refresh_all)
        return result

    # --- keys: the server is stopped while the master key changes

    @on(Button.Pressed, "#add-usb")
    def add_usb_pressed(self):
        with self.flask_app.app_context():
            sticks = mounted_sticks()
        if not sticks:
            self.notify(
                "No mounted USB stick found. Plug one in and try again.", severity="warning"
            )
            return
        self.push_screen(Choose("Which stick?", sticks), self.add_usb_to)

    def add_usb_to(self, mountpoint):
        if not mountpoint:
            return
        if self.keyring.needs_passphrase:
            self.push_screen(
                Ask("Passphrase", [("Current passphrase", True)]),
                lambda v: v and self.add_usb_with(mountpoint, v[0]),
            )
        else:
            self.add_usb_with(mountpoint, None)

    @work(thread=True)
    def add_usb_with(self, mountpoint, passphrase):
        code = self.task(add_usb, mountpoint, passphrase, stop_server=True)
        if code:
            self.call_from_thread(
                self.push_screen,
                Show(
                    "USB stick added",
                    "From now on the app needs this stick. Write down the recovery code\n"
                    "and keep it away from the stick: it replaces the stick if you lose it.\n\n"
                    f"    {code}",
                    "I wrote it down",
                ),
            )

    @on(Button.Pressed, "#remove-usb")
    def remove_usb_pressed(self):
        fields = []
        if self.keyring.needs_usb and self.keyring.find_usb_share() is None:
            fields.append(("Recovery code (the stick is not plugged in)", False))
        if self.keyring.needs_passphrase:
            fields.append(("Passphrase", True))
        if not fields:
            self.run_task("The USB stick is no longer required.", remove_usb, None, None,
                          stop_server=True)
            return
        self.push_screen(Ask("Remove the USB stick", fields), self.remove_usb_with)

    def remove_usb_with(self, values):
        if values is None:
            return
        recovery = values.pop(0) if self.keyring.find_usb_share() is None else None
        passphrase = values[0] if values else None
        self.run_task("The USB stick is no longer required.", remove_usb, passphrase, recovery,
                      stop_server=True)

    @on(Button.Pressed, "#set-passphrase")
    def set_passphrase_pressed(self):
        self.push_screen(
            Ask("New passphrase", [("Passphrase", True), ("Again", True)],
                "12 characters or more. It will be asked after every start."),
            self.set_passphrase_with,
        )

    def set_passphrase_with(self, values):
        if values is None:
            return
        if values[0] != values[1]:
            self.notify("The two passphrases differ.", severity="error")
            return
        self.run_task("The passphrase is now required after every start.", set_passphrase,
                      values[0], stop_server=True)

    @on(Button.Pressed, "#remove-passphrase")
    def remove_passphrase_pressed(self):
        self.push_screen(
            Ask("Remove the passphrase", [("Current passphrase", True)]),
            lambda v: v and self.run_task("The passphrase is no longer required.",
                                          remove_passphrase, v[0], stop_server=True),
        )

    # --- setup

    @on(Button.Pressed, "#create-ca")
    def create_ca_pressed(self):
        create = partial(self.run_script, "create_ca.sh", "Local CA created.",
                         os.path.dirname(self.flask_app.config["CA_KEY"]))
        if self.flask_app.config.get("CA_PASSPHRASE"):
            create()
            return
        self.push_screen(
            Ask("New CA passphrase", [("Passphrase", True), ("Again", True)],
                "12 characters or more. It protects the CA's private key on disk. "
                "Kept in memory for this session only, never written anywhere."),
            lambda values: self.new_ca_passphrase(values, create),
        )

    def new_ca_passphrase(self, values, then):
        if values is None:
            return
        if values[0] != values[1]:
            self.notify("The two passphrases differ.", severity="error")
            return
        problem = passphrase_problem(values[0])
        if problem is not None:
            self.notify(problem, severity="error")
            return
        # kept in this process only: not in the environment, so no other
        # program started from here inherits it
        self.flask_app.config["CA_PASSPHRASE"] = values[0]
        then()

    @on(Button.Pressed, "#ca-passphrase")
    def ca_passphrase_pressed(self):
        self.ask_ca_passphrase()

    @on(Button.Pressed, "#server-cert")
    def server_cert_pressed(self):
        cfg = self.flask_app.config
        self.with_ca_passphrase(partial(
            self.run_script, "create_server_cert.sh",
            "HTTPS certificate created. Restart the console to use it.",
            os.path.dirname(cfg["CA_KEY"]), os.path.dirname(cfg["TLS_CERT"]),
        ))

    def with_ca_passphrase(self, then):
        """Runs then once the CA passphrase is known, asking for it if needed."""
        if self.flask_app.config.get("CA_PASSPHRASE"):
            then()
        else:
            self.ask_ca_passphrase(then)

    def ask_ca_passphrase(self, then=None):
        """Asks until the CA key opens with the passphrase, keeps it in memory,
        then runs then. Also at startup: the app needs the CA key to register
        users, renew and revoke certificates. Asked instead of an exported
        variable, which would end up in the shell history."""
        cfg = self.flask_app.config
        if cfg.get("CA_PASSPHRASE") or not os.path.exists(cfg["CA_KEY"]):
            return

        def got(values):
            if not values or not values[0]:
                self.notify("No CA passphrase: registration stays off until it is entered "
                            "(Setup tab).", severity="warning", timeout=8)
                return
            try:
                load_ca(cfg["CA_CERT"], cfg["CA_KEY"], values[0])
            except (OSError, ValueError):
                self.notify("Wrong CA passphrase.", severity="error")
                self.ask_ca_passphrase(then)
                return
            cfg["CA_PASSPHRASE"] = values[0]
            self.notify("CA passphrase accepted: registration is on.")
            self.show_status()
            if then:
                then()

        self.push_screen(Ask("CA passphrase", [("CA passphrase", True)],
                             "Unlocks the certificate authority's key so new users can register. "
                             "Kept in memory only. Leave it empty to skip."), got)

    @work(thread=True)
    def run_script(self, script, done, *folders):
        # a fixed script from this repo, no shell; its only arguments are
        # folders from the app's config, so it writes where the app reads
        # the passphrase goes to this one script only, for as long as it runs
        env = {**os.environ, "CA_PASSPHRASE": self.flask_app.config["CA_PASSPHRASE"]}
        r = subprocess.run(  # nosec B603
            ["/bin/sh", str(PKI / script), *folders], capture_output=True, text=True, env=env
        )
        for line in (r.stdout + r.stderr).splitlines():
            self.call_from_thread(self.log_line, Text(line))
        if r.returncode == 0:
            self.call_from_thread(self.notify, done)
        else:
            self.call_from_thread(self.notify, "Failed, see the Server tab.", severity="error")
        self.call_from_thread(self.refresh_all)

    @on(Button.Pressed, "#reset-db")
    def reset_pressed(self):
        self.push_screen(
            Ask("Reset the database", [("Type erase to confirm", False)],
                "Every user, file and log entry will be deleted."),
            lambda v: v and v[0] == "erase" and self.run_task(
                "Database reset: empty and encrypted.", init_db, stop_server=True),
        )


def main():
    from app import create_app

    Console(create_app()).run()
