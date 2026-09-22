from flask import g, session

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
        assert session["user_id"] == 1
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
    assert b"too common" in register(client, password="Password1234").data


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


def test_logout_clears_session(client):
    register(client)
    login(client)

    with client:
        client.get("/auth/logout")
        assert "user_id" not in session


def test_index_requires_login(client):
    assert client.get("/").headers["Location"] == "/auth/login"


def test_login_is_not_injectable(client):
    register(client)
    r = login(client, username="' OR 1=1 --", password="anything")
    assert b"Incorrect username or password." in r.data
