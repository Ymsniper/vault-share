"""Changing a password: each session changes its own level's password, by
locking that level's key again; no file needs encrypting again."""
from app.db import get_db

from .conftest import PASSWORD
from .test_duress import DURESS, log_in, set_duress
from .test_files import CONTRACT, download, new_file

NEW = "orchard-window-copper-58"


def change(client, current, new):
    data = {"password": current, "new_password": new}
    return client.post("/auth/password", data=data, follow_redirects=True)


def sessions(app, client):
    with app.app_context():
        return get_db().execute(
            "SELECT level FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = ?"
            " ORDER BY level",
            (client.handle,),
        ).fetchall()


def test_changing_the_password(app, alice):
    url = new_file(alice)
    with app.app_context():
        keys = get_db().execute("SELECT * FROM level_keys ORDER BY level").fetchall()
    assert b"Password changed." in change(alice, PASSWORD, NEW).data
    _, r = log_in(app, alice, PASSWORD)
    assert b"Incorrect username or password." in r.data
    real, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/"
    # the same keys, locked again: every file still opens
    assert download(real, url, NEW).data == CONTRACT
    with app.app_context():
        assert get_db().execute("SELECT * FROM level_keys ORDER BY level").fetchall() == keys


def test_a_duress_session_changes_its_own_password_only(app, alice):
    url = new_file(alice)
    set_duress(alice)
    forced, _ = log_in(app, alice, DURESS)
    assert b"Password changed." in change(forced, DURESS, NEW).data
    deeper, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/"
    assert deeper.get(url).status_code == 404
    _, r = log_in(app, alice, DURESS)
    assert b"Incorrect username or password." in r.data
    # the real password and everything it opens are untouched
    real, _ = log_in(app, alice, PASSWORD)
    assert download(real, url).data == CONTRACT


def test_a_change_ends_the_other_sessions_at_its_level_and_below(app, alice):
    set_duress(alice)
    other, _ = log_in(app, alice, PASSWORD)
    log_in(app, alice, DURESS)
    forced, _ = log_in(app, alice, DURESS)
    change(forced, DURESS, NEW)
    # level 1's other session ended; level 0's two stay
    assert [r["level"] for r in sessions(app, alice)] == [0, 0, 1]
    change(alice, PASSWORD, "harbor-seventeen-lantern-q")
    assert [r["level"] for r in sessions(app, alice)] == [0]
    assert other.get("/").headers["Location"] == "/auth/login"


def test_the_new_password_is_checked(app, alice):
    assert b"Wrong password." in change(alice, "a guess", NEW).data
    assert b"too easy to guess" in change(alice, PASSWORD, "Password1234").data
    assert b"must be different" in change(alice, PASSWORD, PASSWORD).data
    _, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/"


def test_a_password_cannot_become_the_duress_password(app, alice):
    set_duress(alice)
    r = change(alice, PASSWORD, DURESS)
    assert b"Choose a password other than your duress password." in r.data
    forced, _ = log_in(app, alice, DURESS)
    assert b"<h1>My <em>files</em></h1>" in forced.get("/").data


def test_a_change_at_level_zero_does_not_show_at_level_one(app, alice):
    app.test_cli_runner().invoke(args=["admin", "grant", alice.handle])
    set_duress(alice)
    change(alice, PASSWORD, NEW)
    forced, _ = log_in(app, alice, DURESS)
    assert b'<td class="vs-mono">password</td>' not in forced.get("/admin/log").data
    real, _ = log_in(app, alice, NEW)
    assert b'<td class="vs-mono">password</td>' in real.get("/admin/log").data
