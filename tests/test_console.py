import asyncio
import errno
import os
import re
import socket

import pytest
from rich.text import Text
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input, OptionList, RichLog, Static

from app.db import get_db
from app.serving import make_app_server
from console import Ask, Choose, Console, Main, Show, Splash


def run(scenario):
    asyncio.run(scenario())


async def choose(pilot, console, index):
    """Pick an option in the Choose dialog on screen."""
    assert isinstance(console.screen, Choose)
    options = console.screen.query_one(OptionList)
    options.focus()
    options.highlighted = index
    await pilot.press("enter")
    await pilot.pause()


async def answer(pilot, console, *values):
    """Fill in the Ask dialog on screen and press OK."""
    assert isinstance(console.screen, Ask)
    for field, value in zip(console.screen.query(Input), values):
        field.value = value
    await pilot.click("#ok")
    await pilot.pause()


def test_splash_then_main_screen(app, alice):
    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:
            assert isinstance(console.screen, Splash)
            await pilot.pause(1.5)
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(console.screen, Main)
            users = console.screen.query_one("#users", DataTable)
            assert users.row_count == 1
            assert console.screen.query_one("#audit", DataTable).row_count > 0

    run(scenario)


def test_make_admin_from_the_users_tab(app, alice):
    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "users-tab"
            await pilot.pause()
            await pilot.click("#grant")
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    with app.app_context():
        assert get_db().execute("SELECT is_admin FROM users").fetchone()[0] == 1


def test_new_and_cancelled_codes_from_the_invites_tab(app):
    shown = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "invites-tab"
            await pilot.pause()
            await pilot.click("#new-invite")
            await console.workers.wait_for_complete()
            await pilot.pause()
            assert isinstance(console.screen, Show)
            shown.append(console.screen.text)
            await pilot.click("#close")
            await pilot.pause()
            assert console.screen.query_one("#invites", DataTable).row_count == 1
            await pilot.click("#cancel-invite")
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    code = re.search(r"[A-Z2-9]{5}(-[A-Z2-9]{5}){3}", shown[0]).group(0)
    r = app.test_client().post("/auth/register", data={"code": code, "username": "alice"})
    assert b"This invite code is not valid." in r.data
    with app.app_context():
        assert get_db().execute("SELECT cancelled_at FROM invites").fetchone()[0] is not None


def test_ban_and_unban_from_the_users_tab(app, alice):
    def banned():
        with app.app_context():
            return get_db().execute("SELECT banned_at FROM users").fetchone()[0] is not None

    states = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "users-tab"
            await pilot.pause()
            for button in ("#ban", "#unban"):
                await pilot.click(button)
                await console.workers.wait_for_complete()
                await pilot.pause()
                states.append(banned())

    run(scenario)
    assert states == [True, False]


def test_clean_up_from_the_invites_tab(app, alice):
    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "invites-tab"
            await pilot.pause()
            await pilot.click("#cleanup")
            await pilot.pause()
            await choose(pilot, console, 0)  # ban
            await answer(pilot, console, "2000-01-01 00:00", "", "")
            assert alice.handle in console.screen.note
            await answer(pilot, console, "ban")
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    with app.app_context():
        assert get_db().execute("SELECT banned_at FROM users").fetchone()[0] is not None


def test_revoke_a_certificate_for_all_its_files(app, alice):
    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "users-tab"
            await pilot.pause()
            await pilot.click("#revoke")
            await pilot.pause()
            assert "stay valid" in console.screen.note
            await choose(pilot, console, 2)  # the key was stolen at an unknown time
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    with app.app_context():
        cert = get_db().execute("SELECT revoked_at, invalid_from, not_before FROM certificates").fetchone()
    assert cert["revoked_at"] is not None
    assert cert["invalid_from"] == cert["not_before"]
    assert os.path.exists(app.config["CA_CRL"])


def test_revoke_an_admin_from_the_users_tab(app, alice):
    from .test_cleanup import code_from, join_with

    app.test_cli_runner().invoke(args=["admin", "grant", alice.handle])
    bob = join_with(app, code_from(app, alice), "bob")

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "users-tab"
            await pilot.pause()
            # alice is the first row, where the cursor starts
            await pilot.click("#revoke-admin")
            await pilot.pause()
            await choose(pilot, console, 1)  # ban every account made with her codes
            await choose(pilot, console, 0)  # keep her own account
            assert "loses admin rights" in console.screen.note
            await answer(pilot, console, "revoke")
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    with app.app_context():
        db = get_db()
        state = dict(db.execute("SELECT username, banned_at IS NOT NULL FROM users").fetchall())
        is_admin = db.execute(
            "SELECT is_admin FROM users WHERE username = ?", (alice.handle,)
        ).fetchone()[0]
    assert state == {alice.handle: 0, bob.handle: 1}
    assert is_admin == 0


def test_change_the_invite_defaults_from_the_invites_tab(app):
    from app.invites import defaults

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "invites-tab"
            await pilot.pause()
            await pilot.click("#invite-defaults")
            await pilot.pause()
            # filled in with the current values
            assert [i.value for i in console.screen.query(Input)] == ["1", "7d", "5"]
            await answer(pilot, console, "4", "3d", "8")
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    with app.app_context():
        assert tuple(defaults()) == (4, 3 * 1440, 8)


def test_a_special_code_from_the_invites_tab(app):
    shown = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "invites-tab"
            await pilot.pause()
            await pilot.click("#special-invite")
            await pilot.pause()
            await answer(pilot, console, "4", "2h")
            await console.workers.wait_for_complete()
            await pilot.pause()
            assert isinstance(console.screen, Show)
            shown.append(console.screen.text)

    run(scenario)
    assert "It lets 4 people register,\nworks for 2 hours" in shown[0]
    with app.app_context():
        row = get_db().execute(
            "SELECT max_uses, round((julianday(expires_at) - julianday(created_at)) * 1440)"
            " FROM invites"
        ).fetchone()
    assert tuple(row) == (4, 120.0)


def test_cancel_a_leaked_code_and_its_accounts(app):
    from app.invites import create_invite

    from .test_cleanup import join_with

    with app.app_context():
        code = create_invite(uses=2)
    amina = join_with(app, code, "amina")

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "invites-tab"
            await pilot.pause()
            await pilot.click("#cancel-invite")
            await pilot.pause()
            await choose(pilot, console, 1)  # cancel it and ban its accounts
            assert amina.handle in console.screen.note
            await answer(pilot, console, "ban")
            await console.workers.wait_for_complete()
            await pilot.pause()

    run(scenario)
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT banned_at FROM users").fetchone()[0] is not None
        assert db.execute("SELECT cancelled_at FROM invites").fetchone()[0] is not None


def test_server_settings_from_the_setup_tab(app):
    from app import server_settings

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        new_port = probe.getsockname()[1]
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        console.server.port = 0  # any free port to begin with
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("s")
            assert console.server.running
            console.screen.query_one("#tabs").active = "setup-tab"
            await pilot.pause()
            await pilot.click("#server-settings")
            await pilot.pause()
            assert [i.value for i in console.screen.query(Input)] == ["5000", "10"]
            await answer(pilot, console, str(new_port), "3")
            await pilot.pause()
            seen.append((console.server.running, console.server.port))
            with socket.create_connection(("127.0.0.1", new_port), timeout=2):
                pass
            await pilot.press("s")

    run(scenario)
    assert seen == [(True, new_port)]
    assert app.config["MAX_UPLOAD_MB"] == 3
    assert app.config["MAX_CONTENT_LENGTH"] == 3 * 1024 * 1024 + 64 * 1024
    assert server_settings.load(app.config["SETTINGS_FILE"])[0] == {
        "port": new_port, "max_upload_mb": 3
    }


def test_start_and_stop_the_server(app):
    async def scenario():
        console = Console(app, start_server=False)
        console.server.port = 0  # any free port
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("s")
            assert console.server.running
            await pilot.press("s")
            assert not console.server.running

    run(scenario)


def test_asks_for_the_ca_passphrase_when_missing(app, ca_passphrase):
    app.config["CA_PASSPHRASE"] = None

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            for text in ("not the passphrase", ca_passphrase):
                await pilot.click("#field-0")
                await pilot.press(*text)
                await pilot.press("enter")
                await pilot.pause()

    run(scenario)
    assert app.config["CA_PASSPHRASE"] == ca_passphrase
    assert "CA_PASSPHRASE" not in os.environ or os.environ["CA_PASSPHRASE"] != ca_passphrase


def setup_state(console):
    return str(console.get_screen("main").query_one("#setup-state", Static).content)


def enabled(console, button_id):
    return not console.get_screen("main").query_one(button_id, Button).disabled


async def open_setup_tab(console, pilot):
    console.get_screen("main").query_one("#tabs").active = "setup-tab"
    await pilot.pause()


@pytest.mark.parametrize(
    ("certificate", "https", "shown"),
    [
        (False, False, "none (optional): plain HTTP"),
        (True, False, "in use once the console restarts"),
        (True, True, "in use, valid until"),
    ],
    ids=["no certificate", "certificate for the next start", "certificate in use"],
)
def test_setup_tab_shows_what_is_set_up(app, tls_dir, certificate, https, shown):
    if certificate:
        app.config.update(
            HTTPS=https, TLS_CERT=str(tls_dir / "server.crt"), TLS_KEY=str(tls_dir / "server.key")
        )

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            await open_setup_tab(console, pilot)
            state = setup_state(console)
            assert "ready, valid until" in state
            assert "entered: new users can register" in state
            assert shown in state
            # a CA exists and its passphrase is known
            assert not enabled(console, "#create-ca")
            assert not enabled(console, "#ca-passphrase")
            assert enabled(console, "#server-cert")

    run(scenario)


def test_enter_the_ca_passphrase_from_the_setup_tab(app, ca_passphrase):
    app.config["CA_PASSPHRASE"] = None

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            await pilot.click("#cancel")  # skips the question at startup
            await pilot.pause()
            await open_setup_tab(console, pilot)
            assert "not entered: registration is off" in setup_state(console)
            await pilot.click("#ca-passphrase")
            await pilot.pause()
            for text in ("not the passphrase", ca_passphrase):
                await pilot.click("#field-0")
                await pilot.press(*text)
                await pilot.press("enter")
                await pilot.pause()
            assert "entered: new users can register" in setup_state(console)
            assert not enabled(console, "#ca-passphrase")

    run(scenario)
    assert app.config["CA_PASSPHRASE"] == ca_passphrase


def test_create_the_ca_from_the_setup_tab(app, tmp_path):
    ca = tmp_path / "new-ca"
    app.config.update(CA_CERT=str(ca / "ca.crt"), CA_KEY=str(ca / "ca.key"), CA_PASSPHRASE=None)
    good = "orchid lantern basalt ferry"

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 40)) as pilot:

            async def create(passphrase, again):
                await pilot.click("#create-ca")
                await pilot.pause()
                await pilot.click("#field-0")
                await pilot.press(*passphrase)
                await pilot.click("#field-1")
                await pilot.press(*again)
                await pilot.press("enter")
                await pilot.pause()
                await console.workers.wait_for_complete()
                await pilot.pause()

            await pilot.press("enter")
            await pilot.pause()
            await open_setup_tab(console, pilot)
            assert "missing: create it first" in setup_state(console)
            await create(good, "orchid lantern basalt ferries")
            assert not (ca / "ca.key").exists()
            await create("too short", "too short")
            assert not (ca / "ca.key").exists()
            await create(good, good)
            assert (ca / "ca.key").exists() and (ca / "ca.crt").exists()
            assert "ready, valid until" in setup_state(console)
            assert not enabled(console, "#create-ca")

    run(scenario)
    assert app.config["CA_PASSPHRASE"] == good


def test_a_taken_port_raises_instead_of_ending_the_program(app):
    with socket.create_server(("127.0.0.1", 0)) as taken:
        with pytest.raises(OSError) as e:
            make_app_server(app, port=taken.getsockname()[1])
    assert e.value.errno == errno.EADDRINUSE


def test_a_taken_port_is_reported_and_the_console_stays_open(app):
    with socket.create_server(("127.0.0.1", 0)) as taken:

        async def scenario():
            console = Console(app, start_server=False)
            console.server.port = taken.getsockname()[1]
            async with console.run_test(size=(120, 40)) as pilot:
                await pilot.press("enter")
                await pilot.pause()
                await pilot.press("s")
                await pilot.pause()
                assert not console.server.running
                assert isinstance(console.screen, Main)
                assert any("already in use" in n.message for n in console._notifications)

        run(scenario)


def test_quitting_while_the_server_runs(app):
    async def scenario():
        console = Console(app, start_server=False)
        console.server.port = 0
        async with console.run_test(size=(120, 40)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            await pilot.press("s")
            assert console.server.running
        # leaving the block quits the console with the server still on
        return console

    console = asyncio.run(scenario())
    assert not console.server.running


def add_audit(app, n, start=0):
    with app.app_context():
        db = get_db()
        for i in range(start, start + n):
            db.execute(
                "INSERT INTO audit_log (action, outcome, detail) VALUES ('test', 'ok', ?)",
                (f"entry {i}",),
            )
        db.commit()


async def open_tab(pilot, console, tab):
    await pilot.press("enter")
    await pilot.pause()
    console.screen.query_one("#tabs").active = tab
    await pilot.pause()


def place(table):
    """The highlighted row's key and the key of the row at the top of the view."""
    cursor = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
    top = table.coordinate_to_cell_key(Coordinate(int(table.scroll_y), 0)).row_key.value
    return cursor, top


def test_the_audit_tab_keeps_its_place(app):
    add_audit(app, 80)
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 30)) as pilot:
            await open_tab(pilot, console, "log-tab")
            table = console.screen.query_one("#audit", DataTable)
            table.move_cursor(row=30)
            table.scroll_to(y=25, animate=False)
            await pilot.pause()
            seen.append(place(table))
            console.load_audit()  # nothing new
            await pilot.pause()
            seen.append(place(table))
            add_audit(app, 3, start=80)
            console.load_audit()
            await pilot.pause()
            await pilot.pause()
            seen.append(place(table))
            seen.append(table.row_count)

    run(scenario)
    assert seen[0] == seen[1] == seen[2]
    assert seen[0] != (None, None)
    assert seen[3] == 83


def test_the_audit_tab_shows_problems_and_more(app):
    add_audit(app, 230)
    with app.app_context():
        db = get_db()
        for _ in range(2):
            db.execute("INSERT INTO audit_log (action, outcome) VALUES ('login', 'failed')")
        db.commit()
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 30)) as pilot:
            await open_tab(pilot, console, "log-tab")
            table = console.screen.query_one("#audit", DataTable)
            seen.append(table.row_count)
            await pilot.click("#audit-more")
            await pilot.pause()
            seen.append(table.row_count)
            await pilot.click("#audit-problems")
            await pilot.pause()
            seen.append(table.row_count)

    run(scenario)
    assert seen == [200, 232, 2]


def test_new_audit_entries_show_at_the_top(app):
    add_audit(app, 5)
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 30)) as pilot:
            await open_tab(pilot, console, "log-tab")
            table = console.screen.query_one("#audit", DataTable)
            highlighted = place(table)[0]
            add_audit(app, 2, start=5)
            console.load_audit()
            await pilot.pause()
            await pilot.pause()
            seen.append(table.scroll_y)
            seen.append(str(table.get_row_at(0)[5]))
            seen.append(place(table)[0] == highlighted)

    run(scenario)
    assert seen == [0, "entry 6", True]


def test_the_users_tab_keeps_the_highlight_after_an_action(app, alice, bob):
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 40)) as pilot:
            await open_tab(pilot, console, "users-tab")
            console.screen.query_one("#users", DataTable).move_cursor(row=1)
            await pilot.pause()
            await pilot.click("#ban")
            await console.workers.wait_for_complete()
            await pilot.pause()
            await pilot.pause()
            seen.append(console.selected_user())

    run(scenario)
    assert seen == [bob.handle]


def test_the_server_log_follows_only_from_the_bottom(app):
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(120, 30)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            pane = console.screen.query_one("#log", RichLog)
            for i in range(100):
                console.log_line(Text(f"line {i}"))
            await pilot.pause()
            seen.append(pane.is_vertical_scroll_end)
            pane.scroll_to(y=10, animate=False)
            await pilot.pause()
            console.log_line(Text("while reading"))
            await pilot.pause()
            seen.append(pane.scroll_y)
            pane.scroll_end(animate=False)
            await pilot.pause()
            console.log_line(Text("at the bottom"))
            await pilot.pause()
            seen.append(pane.is_vertical_scroll_end)

    run(scenario)
    assert seen == [True, 10, True]



def test_c_copies_the_highlighted_row(app, alice):
    copied = []

    async def scenario():
        console = Console(app, start_server=False)
        console.copy_to_clipboard = copied.append
        async with console.run_test(size=(140, 40)) as pilot:
            await open_tab(pilot, console, "users-tab")
            await pilot.press("c")
            await pilot.pause()

    run(scenario)
    lines = copied[0].splitlines()
    assert lines[0] == f"User: {alice.handle}"
    assert "Invited by: the server" in lines


def test_enter_opens_the_highlighted_row(app, alice):
    shown = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 40)) as pilot:
            await open_tab(pilot, console, "users-tab")
            console.screen.query_one("#users", DataTable).focus()
            await pilot.press("enter")
            await pilot.pause()
            shown.append(console.screen)

    run(scenario)
    assert isinstance(shown[0], Show)
    assert shown[0].title_text == "User"
    assert f"User: {alice.handle}" in shown[0].text


def test_a_first_click_only_highlights(app, alice, bob):
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 40)) as pilot:
            await open_tab(pilot, console, "users-tab")
            # the header is line 0, the first row line 1, the second line 2
            await pilot.click("#users", offset=(2, 2))
            await pilot.pause()
            seen.append((isinstance(console.screen, Main), console.selected_user()))
            await pilot.click("#users", offset=(2, 2))
            await pilot.pause()
            seen.append(isinstance(console.screen, Show))

    run(scenario)
    assert seen == [(True, bob.handle), True]
