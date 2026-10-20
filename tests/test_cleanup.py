import os

import pytest

from app.db import get_db
from app.invites import code_hash, create_invite, to_local

from .test_files import user_id
from .test_invites import step_one, step_two


def admin(app, *args, input=None):
    return app.test_cli_runner().invoke(args=["admin", *args], input=input)


def code_from(app, inviter=None):
    """A new invite code, made by inviter (a client) or at the server."""
    with app.app_context():
        return create_invite(created_by=user_id(app, inviter.handle) if inviter else None)


def join_with(app, code, name):
    client = app.test_client()
    assert step_one(client, code, name).headers["Location"] == "/auth/register/password"
    with client.session_transaction() as s:
        client.handle = s["new_handle"]
    assert step_two(client).headers["Location"] == "/auth/login"
    return client


def run_sql(app, sql, *params):
    with app.app_context():
        db = get_db()
        db.execute(sql, params)
        db.commit()


def created(app, client, utc):
    run_sql(app, "UPDATE users SET created_at = ? WHERE username = ?", utc, client.handle)


def banned(app, client):
    with app.app_context():
        return get_db().execute(
            "SELECT banned_at FROM users WHERE username = ?", (client.handle,)
        ).fetchone()[0] is not None


def code_states(app):
    with app.app_context():
        return dict(get_db().execute(
            "SELECT created_at, CASE WHEN cancelled_at IS NULL THEN 'open' ELSE 'cancelled' END"
            " FROM invites WHERE used_at IS NULL"
        ).fetchall())


@pytest.fixture
def crowd(app, alice):
    """alice is an admin. bob and dave joined with her codes, carol with one
    from the server, and alice has two codes nobody used yet."""
    admin(app, "grant", alice.handle)
    bob = join_with(app, code_from(app, alice), "bob")
    carol = join_with(app, code_from(app), "carol")
    dave = join_with(app, code_from(app, alice), "dave")
    created(app, bob, "2026-03-01 10:00:00")
    created(app, carol, "2026-03-01 11:00:00")
    created(app, dave, "2026-03-05 10:00:00")
    for code, utc in ((code_from(app, alice), "2026-03-01 10:30:00"),
                      (code_from(app, alice), "2026-03-10 10:00:00")):
        run_sql(app, "UPDATE invites SET created_at = ? WHERE code_hash = ?", utc, code_hash(code))
    return alice, bob, carol, dave


# a window around March 1st, 09:00 to 12:00 UTC, typed in local time
WINDOW = ("--from", to_local("2026-03-01 09:00:00"), "--to", to_local("2026-03-01 12:00:00"))


def test_cleanup_bans_the_window_and_cancels_its_codes(app, crowd):
    alice, bob, carol, dave = crowd
    r = admin(app, "cleanup", *WINDOW, "--yes")
    assert "2 accounts banned, 1 unused codes cancelled." in r.output
    assert [banned(app, c) for c in crowd] == [False, True, True, False]
    assert code_states(app) == {"2026-03-01 10:30:00": "cancelled", "2026-03-10 10:00:00": "open"}


def test_cleanup_can_keep_to_one_admins_codes(app, crowd):
    alice, bob, carol, dave = crowd
    admin(app, "cleanup", *WINDOW, "--admin", alice.handle, "--yes")
    assert [banned(app, c) for c in crowd] == [False, True, False, False]


def test_cleanup_can_keep_to_the_servers_codes(app, crowd):
    admin(app, "cleanup", *WINDOW, "--server", "--yes")
    assert [banned(app, c) for c in crowd] == [False, False, True, False]
    assert code_states(app)["2026-03-01 10:30:00"] == "open"


def test_the_preview_comes_first(app, crowd):
    alice, bob, carol, dave = crowd
    r = admin(app, "cleanup", *WINDOW, input="n\n")
    assert "Accounts to ban: 2" in r.output
    assert bob.handle in r.output and carol.handle in r.output
    assert dave.handle not in r.output
    assert "Unused invite codes to cancel: 1" in r.output
    assert r.exit_code != 0  # aborted
    assert not any(banned(app, c) for c in crowd)


def test_a_cleanup_can_be_undone(app, crowd):
    admin(app, "cleanup", *WINDOW, "--yes")
    r = admin(app, "cleanup", *WINDOW, "--unban", "--yes")
    assert "2 accounts unbanned." in r.output
    assert not any(banned(app, c) for c in crowd)
    # cancelled codes stay cancelled
    assert code_states(app)["2026-03-01 10:30:00"] == "cancelled"


def test_an_empty_window_does_nothing(app, crowd):
    r = admin(app, "cleanup", "--from", "2020-01-01", "--to", "2020-01-02")
    assert r.output == "Nothing in that window.\n"


def test_cleanup_wants_real_times(app, crowd):
    r = admin(app, "cleanup", "--from", "yesterday")
    assert r.exit_code != 0
    assert "Not a date and time" in r.output
    r = admin(app, "cleanup", *WINDOW, "--admin", "x", "--server")
    assert "Use --admin or --server, not both." in r.output


def test_revoke_admin_bans_what_their_codes_made_since(app, crowd):
    alice, bob, carol, dave = crowd
    since = to_local("2026-03-03 00:00:00")
    r = admin(app, "revoke-admin", alice.handle, "--ban-invited-since", since, "--yes")
    assert "is no longer an admin; 2 unused codes cancelled; 1 accounts banned." in r.output
    assert [banned(app, c) for c in crowd] == [False, False, False, True]
    assert set(code_states(app).values()) == {"cancelled"}
    with app.app_context():
        assert get_db().execute(
            "SELECT is_admin FROM users WHERE username = ?", (alice.handle,)
        ).fetchone()[0] == 0


def test_revoke_admin_after_a_stolen_password(app, crowd):
    alice, bob, carol, dave = crowd
    r = admin(app, "revoke-admin", alice.handle, "--ban-all-invited", "--ban",
              "--revoke-certificate", "--yes")
    assert "banned; their certificate revoked." in r.output
    assert [banned(app, c) for c in crowd] == [True, True, False, True]
    with app.app_context():
        assert get_db().execute(
            "SELECT revoked_at FROM certificates c JOIN users u ON u.id = c.user_id"
            " WHERE u.username = ?", (alice.handle,)
        ).fetchone()[0] is not None
    assert os.path.exists(app.config["CA_CRL"])


def test_revoke_admin_checks_its_target(app, crowd):
    alice, bob, carol, dave = crowd
    assert "is not an admin." in admin(app, "revoke-admin", bob.handle, "--yes").output
    assert "No user named" in admin(app, "revoke-admin", "nobody#000000").output
    r = admin(app, "revoke-admin", alice.handle, "--ban-all-invited",
              "--ban-invited-since", "2026-03-01")
    assert "not both" in r.output
