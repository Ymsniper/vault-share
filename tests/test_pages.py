"""Every page stays within the Content-Security-Policy, and a decoy
session wears the same header and footer as the real one."""
import re

import pytest
from flask import render_template
from werkzeug import exceptions

from .conftest import logged_in
from .samples import zipped
from .test_duress import DURESS, log_in, set_duress
from .test_files import new_file, share

# what the policy would block, or what would need it loosened
FORBIDDEN = {
    "style attribute": r"<[^>]+\sstyle\s*=",
    "style element": r"<style\b",
    "inline script": r"<script(?![^>]*\bsrc=)[^>]*>",
    "event handler": r"<[^>]+\son[a-z]+\s*=",
    "javascript: URL": r"javascript:",
    "outside URL": r"""(?:src|href|action)\s*=\s*["']?(?:https?:)?//""",
    "data: URL": r"""(?:src|href)\s*=\s*["']?data:""",
}

LOGGED_IN = [
    "/",
    "/upload",
    "/auth/totp",
    "/auth/duress",
    "/admin/log",
    "/admin/log?problems=1",
    "/admin/invites",
]


def problems(html):
    text = html.decode()
    return [name for name, pattern in FORBIDDEN.items() if re.search(pattern, text, re.I)]


def make_admin(app, client):
    app.test_cli_runner().invoke(args=["admin", "grant", client.handle])


@pytest.fixture
def pages(app, alice, bob):
    """(label, html) for every kind of page a visitor can reach."""
    make_admin(app, alice)
    owned = new_file(alice)
    archive = new_file(alice, zipped([("plans.txt", b"Ground floor.\n")]), "plans.zip")
    theirs = new_file(bob, name="figures.txt")
    share(bob, theirs, alice.handle)
    set_duress(alice)
    decoy, _ = log_in(app, alice, DURESS)
    long_name = logged_in(app, "x" * 32)

    out = []
    anonymous = app.test_client()
    for url in ("/auth/login", "/auth/register", "/no-such-page", "/auth/logout"):
        out.append((f"anonymous {url}", anonymous.get(url).data))
    for label, client in (("alice", alice), ("decoy", decoy), ("bob", bob), ("long", long_name)):
        for url in LOGGED_IN:
            out.append((f"{label} {url}", client.get(url).data))
    for url in (owned, archive, theirs):
        out.append((f"alice {url}", alice.get(url).data))

    with app.test_request_context():
        for error in (
            exceptions.BadRequest(),
            exceptions.Forbidden(),
            exceptions.NotFound(),
            exceptions.MethodNotAllowed(),
            exceptions.Gone(),
            exceptions.RequestEntityTooLarge(),
            exceptions.TooManyRequests(),
            exceptions.InternalServerError(),
        ):
            out.append((f"error {error.code}", render_template("error.html", error=error).encode()))
        out.append(("locked.html", render_template("locked.html").encode()))
    return out


def test_no_page_needs_the_policy_loosened(pages):
    assert len(pages) > 40
    found = {label: p for label, html in pages if (p := problems(html))}
    assert found == {}


def test_the_check_catches_what_it_looks_for():
    assert problems(b'<p style="color:red">') == ["style attribute"]
    assert problems(b"<script>alert(1)</script>") == ["inline script"]
    assert problems(b'<script src="/static/app.js"></script>') == []
    assert problems(b'<img src="x" onerror="alert(1)">') == ["event handler"]
    assert problems(b'<a href="https://example.com">') == ["outside URL"]
    assert problems(b'<img src="data:image/png;base64,AAAA">') == ["data: URL"]


def frame(html):
    """The header and footer, without the per-session CSRF token."""
    text = re.sub(r'name="csrf_token" value="[^"]*"', 'name="csrf_token"', html.decode())
    header = re.search(r"<header\b.*?</header>", text, re.S)
    footer = re.search(r"<footer\b.*?</footer>", text, re.S)
    assert header and footer
    return header.group(0), footer.group(0)


def test_a_decoy_admin_has_the_same_header_and_footer(app, alice):
    make_admin(app, alice)
    set_duress(alice)
    decoy, _ = log_in(app, alice, DURESS)
    for url in ("/", "/admin/log", "/admin/invites", "/upload", "/auth/totp"):
        assert frame(decoy.get(url).data) == frame(alice.get(url).data), url
