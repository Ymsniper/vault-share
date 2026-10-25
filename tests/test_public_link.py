import json

import pytest

from app import public_link
from console import Choose, Console

from .test_console import answer, choose, run

HOST = "vault-share.tail84faff.ts.net"


class FakeTailscale:
    """Stands in for the tailscale command: a serve config, which the funnel
    and serve commands change the way the real ones do."""

    def __init__(self, config, accept=True, apply=True):
        self.config, self.accept, self.apply = config, accept, apply
        self.calls = []

    def __call__(self, args, timeout=10):
        self.calls.append(args)
        if args == ["funnel", "status", "--json"]:
            return 0, json.dumps(self.config)
        if not self.accept:
            return 1, "error: not allowed"
        if self.apply:
            port = args[3].split("=")[1]
            path = args[4].split("=", 1)[1]
            self.config["Web"][f"{HOST}:{port}"]["Handlers"][path]["Proxy"] = args[5]
        return 0, ""

    def proxy(self, port="443", path="/"):
        return self.config["Web"][f"{HOST}:{port}"]["Handlers"][path]["Proxy"]


def funnel(proxy="https+insecure://127.0.0.1:5000", public=True, port="443", path="/",
           http=False):
    host = f"{HOST}:{port}"
    config = {
        "TCP": {port: {"HTTP" if http else "HTTPS": True}},
        "Web": {host: {"Handlers": {path: {"Proxy": proxy}}}},
    }
    if public:
        config["AllowFunnel"] = {host: True}
    return config


@pytest.fixture
def tailscale(monkeypatch):
    fake = FakeTailscale(funnel())
    monkeypatch.setattr(public_link, "run", fake)
    return fake


def moves(fake):
    return [c for c in fake.calls if c != ["funnel", "status", "--json"]]


def test_the_rules_that_point_at_a_port_here():
    for proxy in ("https+insecure://127.0.0.1:5000", "http://localhost:5000",
                  "http://[::1]:5000/app"):
        assert [r["proxy"] for r in public_link.rules_for(funnel(proxy), 5000)] == [proxy]
    for proxy in ("https+insecure://127.0.0.1:5001", "http://192.168.1.20:5000",
                  "http://example.com:5000", "text:hello"):
        assert public_link.rules_for(funnel(proxy), 5000) == []
    assert public_link.rules_for(None, 5000) == []


def test_a_rule_stays_public_or_tailnet_only():
    rule = public_link.rules_for(funnel(), 5000)[0]
    assert public_link.command(rule, 7000, https=True) == [
        "funnel", "--bg", "--yes", "--https=443", "--set-path=/", "https+insecure://127.0.0.1:7000"
    ]
    config = funnel("http://127.0.0.1:5000/app", public=False, port="8080", path="/files",
                    http=True)
    rule = public_link.rules_for(config, 5000)[0]
    assert public_link.command(rule, 7000, https=False) == [
        "serve", "--bg", "--yes", "--http=8080", "--set-path=/files", "http://127.0.0.1:7000/app"
    ]


def test_moving_the_link(tailscale):
    message = public_link.move(5000, 7000, https=True)
    assert message == f"Moved https://{HOST} to port 7000."
    assert tailscale.proxy() == "https+insecure://127.0.0.1:7000"
    # still public, and nothing else asked of tailscale
    assert tailscale.config["AllowFunnel"] == {f"{HOST}:443": True}
    assert len(moves(tailscale)) == 1


def test_a_refused_change_says_what_to_run(monkeypatch):
    monkeypatch.setattr(public_link, "run", FakeTailscale(funnel(), accept=False))
    assert public_link.move(5000, 7000, https=True) == (
        "Tailscale did not take the change. Run this yourself: tailscale funnel --bg --yes"
        " --https=443 --set-path=/ https+insecure://127.0.0.1:7000"
    )


def test_a_change_that_did_not_happen_is_reported(monkeypatch):
    fake = FakeTailscale(funnel(), apply=False)
    monkeypatch.setattr(public_link, "run", fake)
    assert public_link.move(5000, 7000, https=True).startswith(
        "Tailscale still points at the old port. Run this yourself: tailscale funnel"
    )


def test_without_tailscale_nothing_changes():
    assert public_link.status() is None
    assert public_link.move(5000, 7000, https=True) == (
        "No Tailscale link pointed at port 5000, so nothing was changed."
    )


def test_where_the_link_points():
    assert public_link.describe(None, 7000) == ("no Tailscale link", True)
    assert public_link.describe({"Web": {}}, 7000) == ("no Tailscale link", True)
    assert public_link.describe(funnel("https+insecure://127.0.0.1:7000"), 7000) == (
        f"https://{HOST} (public), to this server", True
    )
    assert public_link.describe(funnel(), 7000) == (
        f"https://{HOST} points at port 5000, not this server (port 7000)", False
    )


def settings(app, *args, input=None):
    return app.test_cli_runner().invoke(args=["server-settings", *args], input=input)


def test_the_command_asks_before_moving_the_link(app, tailscale):
    r = settings(app, "--port", "7000", input="n\n")
    assert f"https://{HOST} still points at port 5000. Move it to 7000?" in r.output
    assert "Left as it is. To move it later: tailscale funnel" in r.output
    assert tailscale.proxy() == "https+insecure://127.0.0.1:5000"
    assert moves(tailscale) == []


def test_the_command_moves_the_link_on_yes(app, tailscale):
    r = settings(app, "--port", "7000", input="y\n")
    assert f"Moved https://{HOST} to port 7000." in r.output
    # this test app serves plain HTTP
    assert tailscale.proxy() == "http://127.0.0.1:7000"


def test_yes_moves_the_link_without_asking(app, tailscale):
    r = settings(app, "--port", "7000", "--yes")
    assert "Move it to 7000?" not in r.output
    assert tailscale.proxy() == "http://127.0.0.1:7000"


def test_no_question_when_no_link_points_at_the_old_port(app, monkeypatch):
    fake = FakeTailscale(funnel("https+insecure://127.0.0.1:9999"))
    monkeypatch.setattr(public_link, "run", fake)
    r = settings(app, "--port", "7000")
    assert "still points" not in r.output
    assert moves(fake) == []


def change_port_in_the_console(app, then):
    shown = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await pilot.press("enter")
            await pilot.pause()
            console.screen.query_one("#tabs").active = "setup-tab"
            await pilot.pause()
            await pilot.click("#server-settings")
            await pilot.pause()
            await answer(pilot, console, "7000", "10")
            await console.workers.wait_for_complete()
            await pilot.pause()
            shown.append(console.screen)
            if isinstance(console.screen, Choose):
                await choose(pilot, console, then)
                await console.workers.wait_for_complete()
                await pilot.pause()

    run(scenario)
    return shown[0]


def test_the_console_offers_to_move_the_link(app, tailscale):
    screen = change_port_in_the_console(app, then=0)
    assert isinstance(screen, Choose)
    assert f"https://{HOST} still points at port 5000. Move it to 7000?" in screen.title_text
    assert tailscale.proxy() == "http://127.0.0.1:7000"


def test_the_console_can_leave_the_link(app, tailscale):
    change_port_in_the_console(app, then=1)
    assert tailscale.proxy() == "https+insecure://127.0.0.1:5000"
    assert moves(tailscale) == []


def test_the_console_does_not_ask_without_tailscale(app):
    assert not isinstance(change_port_in_the_console(app, then=0), Choose)


def test_the_console_shows_where_the_link_points(app, tailscale):
    seen = []

    async def scenario():
        console = Console(app, start_server=False)
        async with console.run_test(size=(140, 45)) as pilot:
            await console.workers.wait_for_complete()
            await pilot.pause()
            seen.append(console.link)
            seen.append(str(console.setup_state()))
            seen.append(dict((c[0], c[1]) for c in console.startup_checks())["link"])

    run(scenario)
    assert seen[0] == (f"https://{HOST} (public), to this server", True)
    assert f"Tailscale link      https://{HOST} (public), to this server" in seen[1]
    assert seen[2] == f"https://{HOST} (public), to this server"
