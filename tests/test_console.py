import asyncio
import os

from textual.widgets import DataTable

from app.db import get_db
from console import Console, Main, Splash


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
