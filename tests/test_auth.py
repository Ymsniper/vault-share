import time

from flask import g

from app import auth
from app.auth import new_handle, show_handle
from app.db import get_db

from .conftest import PASSWORD, invite_code, register
from .test_files import CONTRACT, download, new_file


def login(client, username, password=PASSWORD):
    return client.post("/auth/login", data={"username": username, "password": password})


def pick_name(client, name="alice", code=None):
    code = code or invite_code(client.application)
    return client.post("/auth/register", data={"code": code, "username": name})


def pick_password(client, password=PASSWORD, **data):
    return client.post("/auth/register/password", data={"password": password, **data})


def pending_handle(client):
    with client.session_transaction() as s:
        return s["new_handle"]


def test_register_then_login(client):
    handle = register(client)
    with client:
        assert login(client, handle).headers["Location"] == "/"
        client.get("/")
        assert g.user["username"] == handle


def test_usernames_get_a_six_digit_tag():
    for _ in range(50):
        name, sep, tag = new_handle("alice").partition("#")
        assert (name, sep) == ("alice", "#")
        assert len(tag) == 6 and tag.isdigit()


def test_the_same_name_twice_makes_two_accounts(client):
    first = register(client)
    second = register(client)
    assert first != second
    assert first.startswith("alice#") and second.startswith("alice#")
    # nothing along the way says the name is taken
    assert b"already" not in pick_name(client).data
    assert login(client, first).headers["Location"] == "/"
    assert login(client, second).headers["Location"] == "/"


def test_usernames_show_with_their_tag_dimmed(alice):
    name, tag = alice.handle.split("#")
    assert f'{name}<span class="vs-tag">#{tag}</span>'.encode() in alice.get("/").data


def test_the_handle_filter_escapes_markup():
    shown = str(show_handle("<b>x</b>#<i>1</i>"))
    assert shown == '&lt;b&gt;x&lt;/b&gt;<span class="vs-tag">#&lt;i&gt;1&lt;/i&gt;</span>'
    assert str(show_handle("<b>old</b>")) == "&lt;b&gt;old&lt;/b&gt;"


def test_the_server_chooses_the_tag(app, client):
    pick_name(client)
    handle = pending_handle(client)
    # the read-only username field is for the browser only: a changed one is ignored
    pick_password(client, username="alice#000001")
    with app.app_context():
        names = [r[0] for r in get_db().execute("SELECT username FROM users")]
    assert names == [handle]


def test_a_tag_drawn_twice_is_replaced(client, monkeypatch):
    tags = iter(["alice#111111", "alice#111111", "alice#222222"])
    monkeypatch.setattr("app.auth.new_handle", lambda name: next(tags))
    assert register(client) == "alice#111111"
    pick_name(client)
    r = pick_password(client)
    assert b"That tag was just taken" in r.data
    assert b"alice#222222" in r.data
    assert pick_password(client).headers["Location"] == "/auth/login"


def test_password_step_needs_a_name_first(client):
    assert client.get("/auth/register/password").headers["Location"] == "/auth/register"
    assert pick_password(client).headers["Location"] == "/auth/register"


def test_password_step_shows_the_whole_username(client):
    pick_name(client)
    page = client.get("/auth/register/password").data.decode()
    assert f'value="{pending_handle(client)}" autocomplete="username" readonly' in page
    assert 'autocomplete="new-password"' in page
    # the first step has no password, so the browser saves nothing there
    assert 'type="password"' not in client.get("/auth/register").data.decode()


def test_login_page_fills_in_the_new_username_once(client):
    handle = register(client)
    assert f'value="{handle}"' in client.get("/auth/login").data.decode()
    assert f'value="{handle}"' not in client.get("/auth/login").data.decode()


def test_the_name_alone_does_not_log_in(client):
    register(client)
    assert b"Incorrect username or password." in login(client, "alice").data


def test_wrong_passwords_for_the_bare_name_do_not_lock_the_account(client):
    handle = register(client)
    for _ in range(5):
        login(client, "alice", "wrong guess")
    assert login(client, handle).headers["Location"] == "/"


def test_register_validates_username(client):
    for name in ("", "ab", "x" * 33, "two words", "alice<script>", "alice#123456"):
        r = pick_name(client, name)
        assert b"Username must be 3 to 32 letters, digits or underscores." in r.data


def test_register_validates_password(client):
    pick_name(client)
    assert b"12 to 128 characters" in pick_password(client, "short-pass").data
    assert b"12 to 128 characters" in pick_password(client, "x" * 129).data
    assert b"must not contain the username" in pick_password(client, "alice-contract-2026").data
    assert b"too easy to guess" in pick_password(client, "Password1234").data
    assert b"too easy to guess" in pick_password(client, "qwertyuiop12").data
    assert pick_password(client, "amber-lantern-quarry-58").headers["Location"] == "/auth/login"


def test_passwords_are_salted_argon2id_hashes(app, client):
    register(client, "alice")
    register(client, "bob")
    with app.app_context():
        hashes = [r[0] for r in get_db().execute("SELECT password_hash FROM users")]
    assert all(h.startswith("$argon2id$v=19$m=65536,t=3,p=4$") for h in hashes)
    # same password, different salts, different hashes
    assert hashes[0] != hashes[1]


def test_login_rejects_wrong_password(client):
    handle = register(client)
    assert b"Incorrect username or password." in login(client, handle, "wrong").data


def test_login_rejects_unknown_user(client):
    assert b"Incorrect username or password." in login(client, "bob#123456").data


def test_session_cookie_is_protected(client):
    handle = register(client)
    cookie = login(client, handle).headers["Set-Cookie"]
    assert cookie.startswith("sid=")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_only_the_token_hash_is_stored(app, client):
    handle = register(client)
    login(client, handle)
    token = client.get_cookie("sid").value
    with app.app_context():
        stored = get_db().execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored != token
    assert len(token) >= 43  # 32 random bytes, base64


def test_copied_cookie_dies_at_logout(client):
    handle = register(client)
    login(client, handle)
    stolen = client.get_cookie("sid").value

    client.post("/auth/logout")
    client.set_cookie("sid", stolen)
    assert client.get("/").headers["Location"] == "/auth/login"


def test_login_never_keeps_a_planted_token(app, client):
    handle = register(client)
    client.set_cookie("sid", "token-chosen-by-an-attacker")
    login(client, handle)
    assert client.get_cookie("sid").value != "token-chosen-by-an-attacker"
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_idle_session_expires(app, client):
    handle = register(client)
    login(client, handle)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE sessions SET last_seen = datetime('now', '-31 minutes')")
        db.commit()
    assert client.get("/").headers["Location"] == "/auth/login"


def test_session_expires_after_8_hours(app, client):
    handle = register(client)
    login(client, handle)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE sessions SET expires_at = datetime('now', '-1 second')")
        db.commit()
    assert client.get("/").headers["Location"] == "/auth/login"


def test_index_requires_login(client):
    assert client.get("/").headers["Location"] == "/auth/login"


def test_login_is_not_injectable(client):
    register(client)
    r = login(client, "' OR 1=1 --", "anything")
    assert b"Incorrect username or password." in r.data


LOCKED = b"Too many failed attempts. Try again in 15 minutes."


def test_five_failures_lock_the_account(client):
    handle = register(client)
    for _ in range(5):
        assert b"Incorrect username or password." in login(client, handle, "wrong guess").data
    r = login(client, handle)
    assert r.status_code == 429
    assert LOCKED in r.data
    assert not any(c.startswith("sid=") for c in r.headers.getlist("Set-Cookie"))


def test_lock_ends_after_15_minutes(client, monkeypatch):
    handle = register(client)
    for _ in range(5):
        login(client, handle, "wrong guess")
    assert login(client, handle).status_code == 429

    # the limiter's moving window reads time.time()
    later = time.time() + 16 * 60
    monkeypatch.setattr(time, "time", lambda: later)
    assert login(client, handle).headers["Location"] == "/"


def test_successful_logins_do_not_count(client):
    handle = register(client)
    for _ in range(10):
        assert login(client, handle).headers["Location"] == "/"
    for _ in range(4):
        login(client, handle, "wrong guess")
    assert login(client, handle).headers["Location"] == "/"


def test_lock_is_written_to_the_audit_log(app, client):
    handle = register(client)
    for _ in range(6):
        login(client, handle, "wrong guess")
    with app.app_context():
        actions = [tuple(r) for r in get_db().execute("SELECT action, outcome FROM audit_log")]
    assert actions.count(("login", "failed")) == 5
    assert ("password", "locked") in actions


def test_unknown_usernames_lock_the_same_way(client):
    for _ in range(5):
        r = login(client, "ghost#000000", "wrong guess")
        assert b"Incorrect username or password." in r.data
    assert login(client, "ghost#000000", "wrong guess").status_code == 429


def test_overlong_login_fields_are_refused_before_any_check(client, monkeypatch):
    checks = []
    monkeypatch.setattr(auth, "check_password", lambda *a: checks.append(a) or False)
    monkeypatch.setattr(auth, "check_password_of_unknown_user", lambda *a: checks.append(a))
    for username, password in (("a" * 41, PASSWORD), ("alice#000000", "p" * 129)):
        r = login(client, username, password)
        assert b"Incorrect username or password." in r.data
    assert checks == []


def from_address(app, address):
    client = app.test_client()
    client.environ_base["REMOTE_ADDR"] = address
    return client


def test_others_cannot_lock_an_owner_out(app):
    owner = from_address(app, "198.51.100.7")
    handle = register(owner)
    login(owner, handle)
    url = new_file(owner)

    attacker = from_address(app, "203.0.113.9")
    for _ in range(5):
        login(attacker, handle, "a guess")
    assert login(attacker, handle).status_code == 429

    # the owner still logs in from her own address, and her session works
    assert login(from_address(app, "198.51.100.7"), handle).headers["Location"] == "/"
    assert download(owner, url).data == CONTRACT


def test_one_address_cannot_spray_many_accounts(client):
    for i in range(20):
        login(client, f"user{i}#000000", "wrong guess")
    handle = register(client)
    assert login(client, handle).status_code == 429
