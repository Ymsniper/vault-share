import re
import time
from urllib.parse import urlparse

import pyotp

from app.db import get_db
from security.totp import new_secret, provisioning_uri

PASSWORD = "contract-2026"


def code(secret, steps_ahead=0):
    """The code an authenticator app would show, steps_ahead x 30 s from now."""
    return pyotp.TOTP(secret).at(time.time() + 30 * steps_ahead)


def turn_on(client):
    page = client.get("/auth/totp").data
    secret = re.search(rb"<code>([A-Z2-7]{32})</code>", page).group(1).decode()
    r = client.post(
        "/auth/totp", data={"password": PASSWORD, "code": code(secret)}, follow_redirects=True
    )
    assert b"Two-factor login is on." in r.data
    return secret


def log_out_and_in(client):
    client.post("/auth/logout")
    return client.post("/auth/login", data={"username": client.handle, "password": PASSWORD})


def test_setup_shows_a_qr_code_and_stores_the_secret_encrypted(app, alice):
    page = alice.get("/auth/totp")
    assert page.headers["Cache-Control"] == "no-store"
    qr = alice.get("/auth/totp/qr.svg")
    assert qr.mimetype == "image/svg+xml" and qr.data.startswith(b"<svg")

    secret = turn_on(alice)
    with app.app_context():
        stored = get_db().execute("SELECT totp_secret FROM users").fetchone()[0]
    assert secret.encode() not in stored
    assert alice.get("/auth/totp/qr.svg").status_code == 404


def test_setup_needs_the_password_and_a_good_code(alice):
    page = alice.get("/auth/totp").data
    secret = re.search(rb"<code>([A-Z2-7]{32})</code>", page).group(1).decode()
    r = alice.post("/auth/totp", data={"password": "not my password", "code": code(secret)})
    assert b"Wrong password." in r.data
    r = alice.post("/auth/totp", data={"password": PASSWORD, "code": "000000"})
    assert b"Wrong code." in r.data
    r = alice.post("/auth/totp", data={"password": PASSWORD, "code": "12ab"})
    assert b"Type the 6-digit code." in r.data


def test_login_asks_for_the_code(alice):
    secret = turn_on(alice)
    r = log_out_and_in(alice)
    assert r.headers["Location"] == "/auth/login/code"
    # the password alone gives no session
    assert alice.get("/").headers["Location"] == "/auth/login"

    r = alice.post("/auth/login/code", data={"code": code(secret, 1)})
    assert r.headers["Location"] == "/"
    assert alice.get("/").status_code == 200


def test_a_code_works_only_once(alice):
    secret = turn_on(alice)
    log_out_and_in(alice)
    used = code(secret, 1)
    alice.post("/auth/login/code", data={"code": used})

    log_out_and_in(alice)
    r = alice.post("/auth/login/code", data={"code": used})
    assert b"Wrong code." in r.data


def test_wrong_codes_count_toward_the_lock(alice):
    turn_on(alice)
    log_out_and_in(alice)
    for _ in range(5):
        alice.post("/auth/login/code", data={"code": "000000"})
    assert alice.post("/auth/login/code", data={"code": "000000"}).status_code == 429


def test_the_code_step_expires_after_5_minutes(alice, monkeypatch):
    secret = turn_on(alice)
    log_out_and_in(alice)
    later = time.time() + 301
    monkeypatch.setattr(time, "time", lambda: later)
    r = alice.post("/auth/login/code", data={"code": code(secret, 1)}, follow_redirects=True)
    assert b"Log in again." in r.data


def test_turning_it_off(alice):
    secret = turn_on(alice)
    r = alice.post(
        "/auth/totp/disable",
        data={"password": PASSWORD, "code": code(secret, 1)},
        follow_redirects=True,
    )
    assert b"Two-factor login is off." in r.data
    assert log_out_and_in(alice).headers["Location"] == "/"


def test_the_tag_stays_in_the_authenticator_label():
    uri = provisioning_uri(new_secret(), "alice#516850")
    assert "alice%23516850" in uri
    assert urlparse(uri).fragment == ""
