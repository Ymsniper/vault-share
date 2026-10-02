from flask import g

from app.db import get_db


def register(client, username="alice", password="contract-2026"):
    return client.post("/auth/register", data={"username": username, "password": password})


def login(client, username="alice", password="contract-2026"):
    return client.post("/auth/login", data={"username": username, "password": password})


def test_register_then_login(client):
    assert register(client).headers["Location"] == "/auth/login"

    with client:
        assert login(client).headers["Location"] == "/"
        client.get("/")
        assert g.user["username"] == "alice"


def test_register_rejects_taken_username(client):
    register(client)
    assert b"already registered" in register(client).data


def test_register_validates_username(client):
    for username in ("", "ab", "x" * 33, "two words", "alice<script>"):
        r = register(client, username=username)
        assert b"Username must be 3 to 32 letters, digits or underscores." in r.data


def test_register_validates_password(client):
    assert b"12 to 128 characters" in register(client, password="short-pass").data
    assert b"12 to 128 characters" in register(client, password="x" * 129).data
    assert b"must not contain the username" in register(client, password="alice-contract-2026").data
    assert b"too easy to guess" in register(client, password="Password1234").data
    assert b"too easy to guess" in register(client, password="qwertyuiop12").data
    assert register(client, password="amber-lantern-quarry-58").headers["Location"] == "/auth/login"


def test_passwords_are_salted_argon2id_hashes(app, client):
    register(client, username="alice")
    register(client, username="bob")
    with app.app_context():
        hashes = [r[0] for r in get_db().execute("SELECT password_hash FROM users")]
    assert all(h.startswith("$argon2id$v=19$m=65536,t=3,p=4$") for h in hashes)
    # same password, different salts, different hashes
    assert hashes[0] != hashes[1]


def test_login_rejects_wrong_password(client):
    register(client)
    assert b"Incorrect username or password." in login(client, password="wrong").data


def test_login_rejects_unknown_user(client):
    assert b"Incorrect username or password." in login(client, username="bob").data


def test_session_cookie_is_protected(client):
    register(client)
    cookie = login(client).headers["Set-Cookie"]
    assert cookie.startswith("sid=")
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_only_the_token_hash_is_stored(app, client):
    register(client)
    login(client)
    token = client.get_cookie("sid").value
    with app.app_context():
        stored = get_db().execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert stored != token
    assert len(token) >= 43  # 32 random bytes, base64


def test_copied_cookie_dies_at_logout(client):
    register(client)
    login(client)
    stolen = client.get_cookie("sid").value

    client.post("/auth/logout")
    client.set_cookie("sid", stolen)
    assert client.get("/").headers["Location"] == "/auth/login"


def test_login_never_keeps_a_planted_token(app, client):
    register(client)
    client.set_cookie("sid", "token-chosen-by-an-attacker")
    login(client)
    assert client.get_cookie("sid").value != "token-chosen-by-an-attacker"
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_idle_session_expires(app, client):
    register(client)
    login(client)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE sessions SET last_seen = datetime('now', '-31 minutes')")
        db.commit()
    assert client.get("/").headers["Location"] == "/auth/login"


def test_session_expires_after_8_hours(app, client):
    register(client)
    login(client)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE sessions SET expires_at = datetime('now', '-1 second')")
        db.commit()
    assert client.get("/").headers["Location"] == "/auth/login"


def test_index_requires_login(client):
    assert client.get("/").headers["Location"] == "/auth/login"


def test_login_is_not_injectable(client):
    register(client)
    r = login(client, username="' OR 1=1 --", password="anything")
    assert b"Incorrect username or password." in r.data


LOCKED = b"Too many failed attempts. Try again in 15 minutes."


def test_five_failures_lock_the_account(client):
    register(client)
    for _ in range(5):
        assert b"Incorrect username or password." in login(client, password="wrong guess").data
    r = login(client)
    assert LOCKED in r.data
    assert not any(c.startswith("sid=") for c in r.headers.getlist("Set-Cookie"))


def test_lock_ends_after_15_minutes(app, client):
    register(client)
    for _ in range(5):
        login(client, password="wrong guess")
    with app.app_context():
        db = get_db()
        db.execute("UPDATE login_failures SET at = datetime('now', '-16 minutes')")
        db.commit()
    assert login(client).headers["Location"] == "/"


def test_successful_login_resets_the_count(client):
    register(client)
    for _ in range(4):
        login(client, password="wrong guess")
    login(client)
    for _ in range(4):
        login(client, password="wrong guess")
    assert login(client).headers["Location"] == "/"


def test_unknown_usernames_lock_the_same_way(client):
    for _ in range(5):
        r = login(client, username="ghost", password="wrong guess")
        assert b"Incorrect username or password." in r.data
    assert LOCKED in login(client, username="ghost", password="wrong guess").data


def test_one_address_cannot_spray_many_accounts(client):
    for i in range(20):
        login(client, username=f"user{i}", password="wrong guess")
    register(client)
    assert LOCKED in login(client).data
