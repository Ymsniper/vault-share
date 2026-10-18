import hashlib
import re

from app.db import get_db
from app.invites import ALPHABET, code_hash, create_invite, list_invites

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


def invite(app, *args):
    return app.test_cli_runner().invoke(args=["invite", *args])


def test_codes_are_four_groups_of_five(app):
    codes = {invite_code(app) for _ in range(20)}
    assert len(codes) == 20
    assert all(CODE_RE.match(c) for c in codes)


def test_registering_needs_a_code(app, client):
    assert b"Type your invite code." in client.post("/auth/register", data={"username": "alice"}).data
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
    r = invite(app, "new", "--days", "2")
    assert r.exit_code == 0
    code = r.output.strip()
    assert CODE_RE.match(code)
    assert re.search(r"^\s+1  open\s+made .* by the server, expires ", invite(app, "list").output)
    assert step_one(client, code).headers["Location"] == "/auth/register/password"


def test_a_cancelled_code_stops_working(app, client):
    code = invite(app, "new").output.strip()
    assert invite(app, "cancel", "1").output == "Invite 1 cancelled.\n"
    assert NOT_VALID in step_one(client, code).data
    r = invite(app, "cancel", "1")
    assert r.exit_code != 0
    assert "No unused invite numbered 1." in r.output
