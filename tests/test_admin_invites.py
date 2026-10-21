import re

from app.db import get_db
from app.invites import create_admin_invite, create_invite

from .conftest import PASSWORD
from .test_audit import log_rows
from .test_duress import DURESS, log_in, set_duress
from .test_files import user_id
from .test_invites import CODE_RE, NOT_VALID, step_one, step_two
from .test_totp import code, turn_on


def make_admin(app, client):
    app.test_cli_runner().invoke(args=["admin", "grant", client.handle])


def new_code(client, secret, steps_ahead=1, password=PASSWORD):
    return client.post(
        "/admin/invites/new",
        data={"password": password, "code": code(secret, steps_ahead)},
        follow_redirects=True,
    )


def shown_code(page):
    m = re.search(rb'vs-invite-code vs-mono">([A-Z2-9-]+)<', page)
    return m.group(1).decode() if m else None


def made_by(app, client):
    with app.app_context():
        return get_db().execute(
            "SELECT COUNT(*) FROM invites WHERE created_by = ?", (user_id(app, client.handle),)
        ).fetchone()[0]


def test_only_admins_have_the_invites_page(app, alice):
    assert alice.get("/admin/invites").status_code == 403
    r = alice.post("/admin/invites/new", data={"password": PASSWORD, "code": "123456"})
    assert r.status_code == 403
    assert b">Invites</a>" not in alice.get("/").data
    make_admin(app, alice)
    assert alice.get("/admin/invites").status_code == 200
    assert b">Invites</a>" in alice.get("/").data


def test_admins_need_two_factor_login(app, alice):
    make_admin(app, alice)
    assert b"Turn on <a" in alice.get("/admin/invites").data
    r = alice.post(
        "/admin/invites/new", data={"password": PASSWORD, "code": "123456"}, follow_redirects=True
    )
    assert b"Turn on two-factor login first" in r.data
    assert made_by(app, alice) == 0


def test_a_code_is_shown_once_and_works(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    r = new_code(alice, secret)
    made = shown_code(r.data)
    assert CODE_RE.match(made)
    page = alice.get("/admin/invites")
    assert page.headers["Cache-Control"] == "no-store"
    assert shown_code(page.data) is None
    assert (alice.handle, "invite", "ok", None) in log_rows(app)

    bob = app.test_client()
    assert step_one(bob, made, "bob").headers["Location"] == "/auth/register/password"
    assert step_two(bob).headers["Location"] == "/auth/login"
    assert b"bob<span" in alice.get("/admin/invites").data


def test_a_wrong_password_or_code_makes_nothing(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    assert b"Wrong password." in new_code(alice, secret, password="a guess").data
    r = alice.post(
        "/admin/invites/new", data={"password": PASSWORD, "code": "abcdef"}, follow_redirects=True
    )
    assert b"Type the 6-digit code." in r.data
    assert made_by(app, alice) == 0


def test_wrong_passwords_lock_like_a_login(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    for _ in range(5):
        new_code(alice, secret, password="a guess")
    assert new_code(alice, secret).status_code == 429
    assert made_by(app, alice) == 0


def test_a_phone_code_works_once(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    assert shown_code(new_code(alice, secret).data)
    assert b"Wrong code." in new_code(alice, secret).data
    assert made_by(app, alice) == 1


def test_five_accounts_a_day(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    with app.app_context():
        for _ in range(5):
            create_invite(created_by=user_id(app, alice.handle))
    assert b"Not today: your codes may create 0 more accounts" in alice.get("/admin/invites").data
    r = new_code(alice, secret)
    assert b"Not today" in r.data
    assert shown_code(r.data) is None

    # a day later the count starts over
    with app.app_context():
        db = get_db()
        db.execute("UPDATE invites SET created_at = datetime('now', '-25 hours')")
        db.commit()
    assert shown_code(new_code(alice, secret).data)


def test_admins_see_and_cancel_only_their_own_codes(app, alice):
    make_admin(app, alice)
    made = shown_code(new_code(alice, turn_on(alice)).data)
    with app.app_context():
        create_invite()  # one made at the server
        open_codes = {
            r["created_by"]: r["id"]
            for r in get_db().execute("SELECT id, created_by FROM invites WHERE uses = 0")
        }
    mine, servers = open_codes[user_id(app, alice.handle)], open_codes[None]
    page = alice.get("/admin/invites").data
    assert f'data-prefix="no.">{mine}</td>'.encode() in page
    assert f'data-prefix="no.">{servers}</td>'.encode() not in page

    r = alice.post(f"/admin/invites/{servers}/cancel", follow_redirects=True)
    assert f"No open invite numbered {servers}.".encode() in r.data
    r = alice.post(f"/admin/invites/{mine}/cancel", follow_redirects=True)
    assert f"Invite {mine} cancelled.".encode() in r.data
    assert NOT_VALID in step_one(app.test_client(), made, "bob").data


def test_the_decoy_account_cannot_make_codes(app, alice):
    make_admin(app, alice)
    set_duress(alice)
    forced, _ = log_in(app, alice, DURESS)
    assert forced.get("/admin/invites").status_code == 403
    assert b">Invites</a>" not in forced.get("/").data


def set_defaults(app, *args):
    r = app.test_cli_runner().invoke(args=["invite", "defaults", *args])
    assert r.exit_code == 0, r.output


def codes_by(app, client):
    with app.app_context():
        return [tuple(r) for r in get_db().execute(
            "SELECT max_uses, round((julianday(expires_at) - julianday(created_at)) * 1440)"
            " FROM invites WHERE created_by = ? ORDER BY id", (user_id(app, client.handle),)
        )]


def test_admin_codes_follow_the_defaults(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    set_defaults(app, "--uses", "2", "--valid", "1d")
    r = new_code(alice, secret)
    assert shown_code(r.data)
    assert b"Each code lets 2 people register and expires after 1 day." in r.data
    assert codes_by(app, alice) == [(2, 1440.0)]


def test_the_daily_limit_counts_accounts(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    set_defaults(app, "--uses", "3", "--admin-per-day", "6")
    with app.app_context():
        create_invite(created_by=user_id(app, alice.handle))
    # 3 accounts already, 3 more fit in the 6
    assert shown_code(new_code(alice, secret).data)
    assert b"Not today: your codes may create 0 more accounts" in alice.get("/admin/invites").data


def test_cancelled_codes_still_count(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    set_defaults(app, "--uses", "3", "--admin-per-day", "6")
    with app.app_context():
        for _ in range(2):
            create_invite(created_by=user_id(app, alice.handle))
    alice.post("/admin/invites/2/cancel")
    r = new_code(alice, secret)
    assert b"Not today" in r.data
    assert shown_code(r.data) is None


def test_the_limit_is_checked_where_the_code_is_stored(app, alice):
    make_admin(app, alice)
    set_defaults(app, "--uses", "3", "--admin-per-day", "5")
    with app.app_context():
        assert create_admin_invite(user_id(app, alice.handle))
        assert create_admin_invite(user_id(app, alice.handle)) is None
    assert codes_by(app, alice) == [(3, 10080.0)]


def test_a_limit_of_zero_stops_admin_codes(app, alice):
    make_admin(app, alice)
    secret = turn_on(alice)
    set_defaults(app, "--admin-per-day", "0")
    page = alice.get("/admin/invites").data
    assert b"Admins cannot make codes at the moment." in page
    assert b"switched off at the server" in page
    assert b"switched off at the server" in new_code(alice, secret).data
    assert codes_by(app, alice) == []

