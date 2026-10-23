import hashlib
import re

import pytest
from sqlcipher3.dbapi2 import IntegrityError

from app.db import get_db
from app.invites import (
    ALPHABET,
    code_hash,
    create_invite,
    defaults,
    list_invites,
    parse_duration,
    show_duration,
)

from .conftest import PASSWORD, invite_code

CODE_RE = re.compile(rf"^[{ALPHABET}]{{5}}(-[{ALPHABET}]{{5}}){{3}}$")
NOT_VALID = b"This invite code is not valid."


def step_one(client, code, name="alice"):
    return client.post("/auth/register", data={"code": code, "username": name})


def step_two(client, password=PASSWORD):
    return client.post("/auth/register/password", data={"password": password})


def users(app):
    with app.app_context():
        return get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def invite(app, *args, input=None):
    return app.test_cli_runner().invoke(args=["invite", *args], input=input)


def test_codes_are_four_groups_of_five(app):
    codes = {invite_code(app) for _ in range(20)}
    assert len(codes) == 20
    assert all(CODE_RE.match(c) for c in codes)


def test_registering_needs_a_code(app, client):
    r = client.post("/auth/register", data={"username": "alice"})
    assert b"Type your invite code." in r.data
    assert NOT_VALID in step_one(client, "AAAAA-BBBBB-CCCCC-DDDDD").data
    assert client.get("/auth/register/password").headers["Location"] == "/auth/register"
    assert users(app) == 0


def test_a_code_works_once(app, client):
    code = invite_code(app)
    assert step_one(client, code).headers["Location"] == "/auth/register/password"
    assert step_two(client).headers["Location"] == "/auth/login"
    assert NOT_VALID in step_one(app.test_client(), code).data
    assert users(app) == 1


def test_expired_and_cancelled_codes_get_the_same_answer(app, client):
    with app.app_context():
        expired, cancelled = create_invite(), create_invite()
        db = get_db()
        db.execute(
            "UPDATE invites SET expires_at = datetime('now', '-1 second') WHERE code_hash = ?",
            (code_hash(expired),),
        )
        db.execute(
            "UPDATE invites SET cancelled_at = datetime('now') WHERE code_hash = ?",
            (code_hash(cancelled),),
        )
        db.commit()
    for code in (expired, cancelled, "nothing like a code"):
        assert NOT_VALID in step_one(client, code).data


def test_codes_can_be_typed_loosely(app, client):
    loose = invite_code(app).lower().replace("-", " ")
    assert step_one(client, loose).headers["Location"] == "/auth/register/password"


def test_only_a_hash_of_the_code_is_stored(app):
    code = invite_code(app)
    with app.app_context():
        row = tuple(get_db().execute("SELECT * FROM invites").fetchone())
    assert hashlib.sha256(code.replace("-", "").encode()).hexdigest() in row
    assert not any(code.replace("-", "")[:10] in str(value) for value in row)


def test_a_code_used_between_the_steps_is_refused(app):
    code = invite_code(app)
    first, second = app.test_client(), app.test_client()
    step_one(first, code)
    step_one(second, code, name="mallory")
    assert step_two(first).headers["Location"] == "/auth/login"
    assert step_two(second).headers["Location"] == "/auth/register"
    assert NOT_VALID in second.get("/auth/register").data
    assert users(app) == 1


def test_the_account_remembers_its_code(app, alice):
    with app.app_context():
        [made] = list_invites()
        user = get_db().execute("SELECT invite_id FROM users").fetchone()
    assert user["invite_id"] == made["id"]
    assert (made["state"], made["used_by"], made["made_by"]) == ("used", alice.handle, None)


def test_refused_codes_are_logged(app, client):
    step_one(client, "AAAAA-BBBBB-CCCCC-DDDDD")
    with app.app_context():
        row = get_db().execute(
            "SELECT action, outcome, detail FROM audit_log ORDER BY id DESC"
        ).fetchone()
    assert tuple(row) == ("register", "refused", "invalid invite code")


def test_registering_is_limited_per_address(client):
    for _ in range(10):
        step_one(client, "AAAAA-BBBBB-CCCCC-DDDDD")
    assert step_one(client, "AAAAA-BBBBB-CCCCC-DDDDD").status_code == 429


def test_invite_commands(app, client):
    r = invite(app, "new", "--valid", "2d")
    assert r.exit_code == 0
    code = r.output.strip()
    assert CODE_RE.match(code)
    listed = invite(app, "list").output
    assert re.search(r"^\s+1  open\s+0 of 1 used, made .* by the server, expires ", listed)
    assert step_one(client, code).headers["Location"] == "/auth/register/password"


def test_a_cancelled_code_stops_working(app, client):
    code = invite(app, "new").output.strip()
    assert invite(app, "cancel", "1").output == "Invite 1 cancelled.\n"
    assert NOT_VALID in step_one(client, code).data
    r = invite(app, "cancel", "1")
    assert r.exit_code != 0
    assert "No open invite numbered 1." in r.output


def join(app, code, name):
    client = app.test_client()
    assert step_one(client, code, name).headers["Location"] == "/auth/register/password"
    assert step_two(client).headers["Location"] == "/auth/login"


def test_a_code_can_let_several_people_in(app):
    with app.app_context():
        code = create_invite(uses=3)
    for name in ("amina", "bilel", "chaima"):
        join(app, code, name)
    assert NOT_VALID in step_one(app.test_client(), code, "dali").data
    with app.app_context():
        [made] = list_invites()
    assert (made["state"], made["uses"], made["max_uses"]) == ("used", 3, 3)
    assert sorted(n.split("#")[0] for n in made["used_by"].split(", ")) == [
        "amina", "bilel", "chaima"
    ]


def test_the_last_place_goes_to_one_person(app):
    with app.app_context():
        code = create_invite(uses=2)
    join(app, code, "amina")
    first, second = app.test_client(), app.test_client()
    step_one(first, code, "bilel")
    step_one(second, code, "chaima")
    assert step_two(first).headers["Location"] == "/auth/login"
    assert step_two(second).headers["Location"] == "/auth/register"
    assert users(app) == 2


def test_cancelling_a_partly_used_code_keeps_its_accounts(app):
    with app.app_context():
        code = create_invite(uses=3)
    join(app, code, "amina")
    assert invite(app, "cancel", "1").output == "Invite 1 cancelled.\n"
    assert NOT_VALID in step_one(app.test_client(), code, "bilel").data
    assert re.search(r"^\s+1  cancelled\s+1 of 3 used", invite(app, "list").output)
    assert users(app) == 1


def lifetimes(app):
    with app.app_context():
        return [tuple(r) for r in get_db().execute(
            "SELECT max_uses, round((julianday(expires_at) - julianday(created_at)) * 1440)"
            " FROM invites ORDER BY id"
        )]


def test_the_defaults(app):
    assert invite(app, "defaults").output == (
        "New codes let 1 person register and work for 7 days."
        " Admins' codes may create 5 accounts a day.\n"
    )


def test_new_defaults_only_touch_new_codes(app):
    with app.app_context():
        create_invite()
    r = invite(app, "defaults", "--uses", "3", "--valid", "2d", "--admin-per-day", "9")
    assert "New codes let 3 people register and work for 2 days." in r.output
    with app.app_context():
        create_invite()
    assert lifetimes(app) == [(1, 10080.0), (3, 2880.0)]
    with app.app_context():
        row = get_db().execute(
            "SELECT outcome, detail FROM audit_log WHERE action = 'invite' ORDER BY id"
        ).fetchall()[1]
    assert tuple(row) == (
        "defaults", "uses 1 to 3; time limit 7 days to 2 days; admin accounts a day 5 to 9"
    )


def test_defaults_stay_within_their_limits(app):
    for args, message in (
        (["--uses", "0"], "1 to 100 people"),
        (["--uses", "101"], "1 to 100 people"),
        (["--valid", "5m"], "between 10 minutes and 90 days"),
        (["--valid", "91d"], "between 10 minutes and 90 days"),
        (["--valid", "soon"], "Not a time limit"),
        (["--admin-per-day", "51"], "0 to 50 accounts"),
        (["--admin-per-day", "-1"], "0 to 50 accounts"),
    ):
        r = invite(app, "defaults", *args)
        assert r.exit_code != 0 and message in r.output, (args, r.output)
    with app.app_context():
        assert tuple(defaults()) == (1, 10080, 5)


def test_the_database_holds_the_same_limits(app):
    with app.app_context():
        db = get_db()
        for sql in (
            "UPDATE invite_defaults SET uses = 0",
            "UPDATE invite_defaults SET valid_minutes = 5",
            "UPDATE invite_defaults SET admin_per_day = 51",
            "INSERT INTO invite_defaults (id, uses, valid_minutes, admin_per_day)"
            " VALUES (2, 1, 60, 5)",
        ):
            with pytest.raises(IntegrityError):
                db.execute(sql)


def test_a_warning_when_admins_can_no_longer_make_codes(app):
    r = invite(app, "defaults", "--uses", "6")
    assert "Admins cannot make codes now: a code lets 6 people register" in r.output


def test_durations():
    assert [parse_duration(t) for t in ("30m", "12h", "7d", " 2H ")] == [30, 720, 10080, 120]
    for bad in ("", "7", "7w", "-1h", "1.5h", "0m", "9m"):
        with pytest.raises(ValueError):
            parse_duration(bad)
    assert [show_duration(m) for m in (10080, 1440, 60, 720, 90)] == [
        "7 days", "1 day", "1 hour", "12 hours", "90 minutes"
    ]


def test_special_codes_at_the_server(app):
    r = invite(app, "new", "--uses", "3", "--valid", "30m")
    code = r.output.strip()
    assert lifetimes(app) == [(3, 30.0)]
    for name in ("amina", "bilel", "chaima"):
        join(app, code, name)
    assert NOT_VALID in step_one(app.test_client(), code, "dali").data
    # for that code only
    with app.app_context():
        assert tuple(defaults()) == (1, 10080, 5)
        row = get_db().execute(
            "SELECT detail FROM audit_log WHERE action = 'invite' AND outcome = 'ok'"
        ).fetchone()
    assert row["detail"] == "code 1 at the server, 3 people, 30 minutes"


def test_special_codes_stay_within_the_limits(app):
    for args, message in (
        (["--uses", "101"], "1 to 100 people"),
        (["--uses", "0"], "1 to 100 people"),
        (["--valid", "91d"], "between 10 minutes and 90 days"),
    ):
        r = invite(app, "new", *args)
        assert r.exit_code != 0 and message in r.output
    assert lifetimes(app) == []


def banned(app):
    with app.app_context():
        return get_db().execute(
            "SELECT COUNT(*) FROM users WHERE banned_at IS NOT NULL"
        ).fetchone()[0]


def test_a_leaked_code_takes_its_accounts_with_it(app):
    with app.app_context():
        code = create_invite(uses=3)
    join(app, code, "amina")
    join(app, code, "bilel")
    r = invite(app, "cancel", "1", "--ban-accounts", input="n\n")
    assert "Invite 1 is cancelled if it still has places." in r.output
    assert "Accounts to ban: 2" in r.output
    assert r.exit_code != 0
    assert banned(app) == 0
    assert step_one(app.test_client(), code, "chaima").headers["Location"].endswith("/password")

    r = invite(app, "cancel", "1", "--ban-accounts", "--yes")
    assert "Invite 1 cancelled; 2 accounts banned." in r.output
    assert banned(app) == 2
    assert NOT_VALID in step_one(app.test_client(), code, "dali").data


def test_a_used_up_code_can_still_take_its_accounts(app):
    with app.app_context():
        code = create_invite()
    join(app, code, "amina")
    r = invite(app, "cancel", "1", "--ban-accounts", "--yes")
    assert "Invite 1 already closed; 1 accounts banned." in r.output
    assert banned(app) == 1


def test_cancelling_needs_a_real_code(app):
    r = invite(app, "cancel", "9", "--ban-accounts", "--yes")
    assert r.exit_code != 0
    assert "No invite numbered 9." in r.output

