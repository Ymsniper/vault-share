from app.db import get_db
from app.invites import create_invite

from .conftest import PASSWORD
from .test_audit import log_rows
from .test_files import CONTRACT, download, new_file, share, shared_with_me, user_id
from .test_invites import NOT_VALID, step_one


def admin(app, *args):
    return app.test_cli_runner().invoke(args=["admin", *args])


def login(client, username, password=PASSWORD):
    return client.post("/auth/login", data={"username": username, "password": password})


def test_a_banned_account_cannot_log_in(app, alice):
    assert admin(app, "ban", alice.handle).output == f"{alice.handle} is banned.\n"
    fresh = app.test_client()
    r = login(fresh, alice.handle)
    assert b"This account is disabled." in r.data
    assert not any(c.startswith("sid=") for c in r.headers.getlist("Set-Cookie"))
    # a wrong password gets the usual answer: only the owner learns of the ban
    assert b"Incorrect username or password." in login(fresh, alice.handle, "a guess").data


def test_a_ban_ends_open_sessions(app, alice):
    assert alice.get("/").status_code == 200
    admin(app, "ban", alice.handle)
    assert alice.get("/").headers["Location"] == "/auth/login"
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_files_of_a_banned_owner_disappear_until_the_unban(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    admin(app, "ban", alice.handle)
    assert b"contract.txt" not in shared_with_me(bob)
    assert bob.get(url).status_code == 403
    assert download(bob, url).status_code == 403

    assert admin(app, "unban", alice.handle).output == f"{alice.handle} can log in again.\n"
    assert b"contract.txt" in shared_with_me(bob)
    assert download(bob, url).data == CONTRACT


def test_unban_brings_the_account_back_whole(app, alice):
    url = new_file(alice)
    admin(app, "ban", alice.handle)
    admin(app, "unban", alice.handle)
    fresh = app.test_client()
    assert login(fresh, alice.handle).headers["Location"] == "/"
    assert download(fresh, url).data == CONTRACT


def test_a_ban_takes_admin_rights_and_unused_codes(app, alice):
    admin(app, "grant", alice.handle)
    with app.app_context():
        code = create_invite(created_by=user_id(app, alice.handle))
    admin(app, "ban", alice.handle)
    assert "is banned: unban them first" in admin(app, "grant", alice.handle).output
    admin(app, "unban", alice.handle)
    with app.app_context():
        assert get_db().execute("SELECT is_admin FROM users").fetchone()[0] == 0
    assert NOT_VALID in step_one(app.test_client(), code, "mallory").data


def test_nothing_new_is_shared_with_a_banned_account(app, alice, bob):
    url = new_file(alice)
    admin(app, "ban", bob.handle)
    assert b"Unknown user." in share(alice, url, bob.handle, follow_redirects=True).data


def test_ban_commands_check_their_target(app, alice):
    r = admin(app, "ban", "nobody#000000")
    assert r.exit_code != 0
    assert "No user named nobody#000000." in r.output
    admin(app, "ban", alice.handle)
    assert "is already banned" in admin(app, "ban", alice.handle).output
    admin(app, "unban", alice.handle)
    assert "is not banned" in admin(app, "unban", alice.handle).output


def test_bans_are_in_the_audit_log(app, alice):
    admin(app, "ban", alice.handle)
    login(app.test_client(), alice.handle)
    admin(app, "unban", alice.handle)
    rows = log_rows(app)
    for expected in (
        (alice.handle, "ban", "ok", None),
        (alice.handle, "login", "refused", None),
        (alice.handle, "unban", "ok", None),
    ):
        assert expected in rows
