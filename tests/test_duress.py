import io
import os
import re

from app import auth
from app.db import get_db

from .test_files import CONTRACT, new_file, shared_with_me, stored_path
from .test_totp import code, turn_on

PASSWORD = "contract-2026"
DURESS = "quiet-harbor-lantern-17"


def set_duress(client, mode="decoy"):
    data = {"password": PASSWORD, "duress_password": DURESS, "mode": mode}
    if mode == "wipe":
        data["confirm_wipe"] = "y"
    return client.post("/auth/duress", data=data, follow_redirects=True)


def log_in(app, password, username="alice"):
    client = app.test_client()
    r = client.post("/auth/login", data={"username": username, "password": password})
    return client, r


def alice_id(app):
    with app.app_context():
        return get_db().execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]


def test_duress_password_opens_an_empty_account(app, alice, bob):
    url = new_file(alice)
    bob_url = new_file(bob, name="bob-notes.txt")
    bob.post(f"{bob_url}/share", data={"username": "alice"})
    assert b"Duress password saved." in set_duress(alice).data

    forced, r = log_in(app, DURESS)
    assert r.headers["Location"] == "/"
    page = forced.get("/").data
    assert b"contract.txt" not in page and b"bob-notes.txt" not in page
    assert b"No files found." in page and b"Nothing shared with you yet." in page
    assert forced.get(url).status_code == 404
    assert forced.get(f"{bob_url}/download").status_code == 404

    # nothing was destroyed: the real password still opens everything
    real, _ = log_in(app, PASSWORD)
    assert real.get(f"{url}/download").data == CONTRACT


def test_duress_raises_a_silent_alarm(app, alice):
    set_duress(alice)
    log_in(app, DURESS)
    with app.app_context():
        rows = [
            tuple(r)
            for r in get_db().execute(
                "SELECT action, outcome, detail FROM audit_log WHERE action = 'duress'"
            )
        ]
    assert ("duress", "used", "decoy") in rows


def test_the_decoy_account_cannot_upload_or_read_the_log(app, alice):
    set_duress(alice)
    app.test_cli_runner().invoke(args=["admin", "grant", "alice"])
    forced, _ = log_in(app, DURESS)

    r = forced.post(
        "/upload",
        data={"file": (io.BytesIO(CONTRACT), "contract.txt"), "password": DURESS},
        content_type="multipart/form-data",
    )
    assert b"The upload failed. Try again later." in r.data
    assert b"Wrong password" not in r.data
    assert forced.get("/admin/log").status_code == 403
    assert b"Audit log" not in forced.get("/").data
    r = forced.post("/auth/duress", data={"password": DURESS}, follow_redirects=True)
    assert b"could not be saved" in r.data


def test_wipe_destroys_files_and_keys(app, alice, bob):
    url = new_file(alice)
    alice.post(f"{url}/share", data={"username": "bob"})
    set_duress(alice, mode="wipe")

    forced, _ = log_in(app, DURESS)
    assert b"No files found." in forced.get("/").data
    assert not os.path.exists(stored_path(app, url))
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
        for table in ("user_keys", "encryption_keys"):
            assert db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", (alice_id(app),)
            ).fetchone()[0] == 0
        assert db.execute(
            "SELECT revoked_at FROM certificates WHERE user_id = ?", (alice_id(app),)
        ).fetchone()[0] is not None
    assert os.path.exists(app.config["CA_CRL"])
    assert b"contract.txt" not in shared_with_me(bob)


def test_after_a_wipe_the_real_password_starts_over(app, alice):
    def encryption_key():
        with app.app_context():
            return get_db().execute(
                "SELECT public_key FROM encryption_keys WHERE user_id = ?", (alice_id(app),)
            ).fetchone()

    before = encryption_key()["public_key"]
    set_duress(alice, mode="wipe")
    log_in(app, DURESS)
    assert encryption_key() is None
    real, _ = log_in(app, PASSWORD)
    # a new key pair at the first real login after the wipe
    assert encryption_key()["public_key"] != before
    url = new_file(real)
    assert b"Integrity verified. Signature valid, signed by alice." in real.get(url).data


def test_wipe_needs_confirmation(alice):
    r = alice.post(
        "/auth/duress",
        data={"password": PASSWORD, "duress_password": DURESS, "mode": "wipe"},
        follow_redirects=True,
    )
    assert b"Tick the box to confirm the wipe" in r.data


def test_duress_password_rules(alice):
    def attempt(password, duress):
        data = {"password": password, "duress_password": duress, "mode": "decoy"}
        return alice.post("/auth/duress", data=data, follow_redirects=True).data

    assert b"Wrong password." in attempt("not my password", DURESS)
    assert b"must be different from your password" in attempt(PASSWORD, PASSWORD)
    assert b"too easy to guess" in attempt(PASSWORD, "Password1234")


def test_every_account_has_the_same_kind_of_duress_slot(app, alice, bob):
    set_duress(alice, mode="wipe")
    with app.app_context():
        rows = get_db().execute("SELECT duress_hash, duress_policy FROM users").fetchall()
    assert len(rows) == 2
    assert all(r["duress_hash"].startswith("$argon2id$") for r in rows)
    assert len(rows[0]["duress_policy"]) == len(rows[1]["duress_policy"])


def test_the_page_never_says_whether_one_is_set(alice, bob):
    set_duress(alice)

    def page(client, username):
        html = client.get("/auth/duress").data.replace(username.encode(), b"USER")
        return re.sub(rb'name="csrf_token" value="[^"]*"', b"", html)

    assert page(alice, "alice") == page(bob, "bob")


def test_login_checks_both_passwords_every_time(app, client, monkeypatch):
    client.post("/auth/register", data={"username": "alice", "password": PASSWORD})
    calls = []

    def counting(stored_hash, password):
        calls.append(stored_hash)
        return real_check(stored_hash, password)

    real_check = auth.check_password
    monkeypatch.setattr(auth, "check_password", counting)
    client.post("/auth/login", data={"username": "alice", "password": "wrong guess"})
    assert len(calls) == 2
    client.post("/auth/login", data={"username": "alice", "password": PASSWORD})
    assert len(calls) == 4


def test_duress_with_two_factor_still_asks_for_the_code(app, alice):
    secret = turn_on(alice)
    set_duress(alice)
    forced, r = log_in(app, DURESS)
    assert r.headers["Location"] == "/auth/login/code"
    r = forced.post("/auth/login/code", data={"code": code(secret, 1)})
    assert r.headers["Location"] == "/"
    assert b"No files found." in forced.get("/").data
