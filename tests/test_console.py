import asyncio
import errno
import os
import re
import socket

import pytest
from textual.widgets import Button, DataTable, Static

from app.db import get_db
from app.serving import make_app_server
from console import Console, Main, Show, Splash


def run(scenario):
    asyncio.run(scenario())


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
