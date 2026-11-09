import os
import re

from app import auth
from app.db import get_db

from .test_files import CONTRACT, my_files, new_file, stored_path
from .test_totp import code, turn_on

PASSWORD = "contract-2026"
DURESS = "quiet-harbor-lantern-17"


def set_duress(client, mode="cover", password=None, duress=DURESS):
    """Set a duress password from client's session, whatever its level."""
    data = {
        "password": password or getattr(client, "password", PASSWORD),
        "duress_password": duress,
        "mode": mode,
    }
    if mode == "wipe":
        data["confirm_wipe"] = "y"
    return client.post("/auth/duress", data=data, follow_redirects=True)


def log_in(app, user, password):
    """A new client logging in as user, another client's account."""
    client = app.test_client()
    r = client.post("/auth/login", data={"username": user.handle, "password": password})
    client.handle, client.password = user.handle, password
    return client, r


def alice_id(app, alice):
    with app.app_context():
        return get_db().execute(
            "SELECT id FROM users WHERE username = ?", (alice.handle,)
        ).fetchone()[0]


def audit_rows(app):
    with app.app_context():
        return [
            tuple(r) for r in get_db().execute("SELECT action, outcome, level FROM audit_log")
        ]


def test_setting_a_duress_password_leaves_no_trace_in_the_log(app, alice):
    before = audit_rows(app)
    set_duress(alice)
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    assert audit_rows(app) == before


def test_a_removed_duress_password_opens_nothing(app, alice):
    set_duress(alice)
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    _, r = log_in(app, alice, DURESS)
    assert b"Incorrect username or password." in r.data


def test_wipe_needs_confirmation(alice):
    r = alice.post(
        "/auth/duress",
        data={"password": PASSWORD, "duress_password": DURESS, "mode": "wipe"},
        follow_redirects=True,
    )
    assert b"Tick the box to confirm the wipe" in r.data


def test_duress_password_rules(alice):
    def attempt(password, duress):
        data = {"password": password, "duress_password": duress, "mode": "cover"}
        return alice.post("/auth/duress", data=data, follow_redirects=True).data

    assert b"Wrong password." in attempt("not my password", DURESS)
    assert b"must be different from your password" in attempt(PASSWORD, PASSWORD)
    assert b"too easy to guess" in attempt(PASSWORD, "Password1234")


def test_the_page_never_says_whether_one_is_set(alice, bob):
    set_duress(alice)

    def page(client, username):
        html = client.get("/auth/duress").data
        for shown in (str(auth.show_handle(username)), username):
            html = html.replace(shown.encode(), b"USER")
        return re.sub(rb'name="csrf_token" value="[^"]*"', b"", html)

    assert page(alice, alice.handle) == page(bob, bob.handle)


def test_duress_with_two_factor_still_asks_for_the_code(app, alice):
    secret = turn_on(alice)
    new_file(alice)
    set_duress(alice)
    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/login/code"
    r = forced.post("/auth/login/code", data={"code": code(secret, 1)})
    assert r.headers["Location"] == "/"
    assert b"contract.txt" not in my_files(forced)


def test_with_two_factor_the_wipe_waits_for_the_code(app, alice):
    secret = turn_on(alice)
    url = new_file(alice)
    set_duress(alice, mode="wipe")
    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/login/code"
    # the duress password alone destroys nothing, but the alarm is raised:
    # the row of the password step, at level 1
    assert os.path.exists(stored_path(app, url))
    assert audit_rows(app)[-1] == ("login", "code asked", 1)

    r = forced.post("/auth/login/code", data={"code": code(secret, 1)})
    assert r.headers["Location"] == "/"
    assert audit_rows(app)[-1] == ("login", "ok", 1)
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
    assert CONTRACT not in forced.get(url).data
