from flask import g, session


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


def test_register_requires_both_fields(client):
    assert b"Username is required." in register(client, username="").data
    assert b"Password is required." in register(client, password="").data


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
