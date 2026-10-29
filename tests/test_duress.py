import io
import os
import re

from app import auth
from app.db import get_db

from .conftest import register
from .test_files import CONTRACT, download, new_file, share, shared_with_me, stored_path
from .test_totp import code, turn_on

PASSWORD = "contract-2026"
DURESS = "quiet-harbor-lantern-17"


def set_duress(client, mode="decoy"):
    data = {"password": PASSWORD, "duress_password": DURESS, "mode": mode}
    if mode == "wipe":
        data["confirm_wipe"] = "y"
    return client.post("/auth/duress", data=data, follow_redirects=True)


def log_in(app, user, password):
    """A new client logging in as user, another client's account."""
    client = app.test_client()
    r = client.post("/auth/login", data={"username": user.handle, "password": password})
    return client, r


def alice_id(app, alice):
    with app.app_context():
        return get_db().execute(
            "SELECT id FROM users WHERE username = ?", (alice.handle,)
        ).fetchone()[0]


def test_duress_password_opens_an_empty_account(app, alice, bob):
    url = new_file(alice)
    bob_url = new_file(bob, name="bob-notes.txt")
    share(bob, bob_url, alice.handle)
    assert b"Duress password saved." in set_duress(alice).data

    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/"
    page = forced.get("/").data
    assert b"contract.txt" not in page and b"bob-notes.txt" not in page
    assert b"No files found." in page and b"Nothing shared with you yet." in page
    assert forced.get(url).status_code == 404
    assert download(forced, bob_url).status_code == 404

    # nothing was destroyed: the real password still opens everything
    real, _ = log_in(app, alice, PASSWORD)
    assert download(real, url).data == CONTRACT


def test_duress_raises_a_silent_alarm(app, alice):
    set_duress(alice)
    log_in(app, alice, DURESS)
    with app.app_context():
        rows = [
            tuple(r)
            for r in get_db().execute(
                "SELECT action, outcome, detail FROM audit_log WHERE action = 'duress'"
            )
        ]
    assert ("duress", "used", "decoy") in rows


def test_the_decoy_account_cannot_upload_or_change_settings(app, alice):
    set_duress(alice)
    forced, _ = log_in(app, alice, DURESS)

    r = forced.post(
        "/upload",
        data={"file": (io.BytesIO(CONTRACT), "contract.txt"), "password": DURESS},
        content_type="multipart/form-data",
    )
    assert b"The upload failed. Try again later." in r.data
    assert b"Wrong password" not in r.data
    r = forced.post("/auth/duress", data={"password": DURESS}, follow_redirects=True)
    assert b"could not be saved" in r.data


ALARM_CELL = b'<td class="vs-mono">duress</td>'


def audit_rows(app):
    with app.app_context():
        return [tuple(r) for r in get_db().execute("SELECT action, outcome FROM audit_log")]


def test_setting_a_duress_password_leaves_no_trace_in_the_log(app, alice):
    set_duress(alice)
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    assert [r for r in audit_rows(app) if r[0] == "duress"] == []


def test_a_decoy_admin_sees_the_admin_pages_without_the_alarm(app, alice):
    set_duress(alice)
    app.test_cli_runner().invoke(args=["admin", "grant", alice.handle])
    forced, _ = log_in(app, alice, DURESS)
    assert b"Audit log" in forced.get("/").data
    page = forced.get("/admin/log")
    assert page.status_code == 200
    assert b'<td class="vs-mono">login</td>' in page.data
    assert ALARM_CELL not in page.data
    assert forced.get("/admin/invites").status_code == 200

    # the decoy cannot make a code, and its attempt shows only to real admins
    r = forced.post(
        "/admin/invites/new", data={"password": DURESS, "code": "123456"}, follow_redirects=True
    )
    assert b"could not be saved" in r.data
    assert ALARM_CELL not in forced.get("/admin/log").data
    assert ("duress", "refused") in audit_rows(app)
    with app.app_context():
        made = get_db().execute("SELECT COUNT(*) FROM invites WHERE created_by IS NOT NULL")
        assert made.fetchone()[0] == 0


def test_the_decoy_never_sees_the_alarm_filtered_or_paged(app, alice):
    set_duress(alice)
    app.test_cli_runner().invoke(args=["admin", "grant", alice.handle])
    forced, _ = log_in(app, alice, DURESS)
    with app.app_context():
        db = get_db()
        for i in range(250):
            db.execute("INSERT INTO audit_log (action, outcome) VALUES ('test', 'ok')")
        db.commit()
    assert ALARM_CELL not in forced.get("/admin/log?problems=1").data
    first = forced.get("/admin/log").data
    older = re.search(rb'href="([^"]*before=[^"]*)"', first).group(1).decode()
    assert ALARM_CELL not in forced.get(older.replace("&amp;", "&")).data


def test_wipe_destroys_files_and_keys(app, alice, bob):
    url = new_file(alice)
    share(alice, url, bob.handle)
    set_duress(alice, mode="wipe")

    forced, _ = log_in(app, alice, DURESS)
    assert b"No files found." in forced.get("/").data
    assert not os.path.exists(stored_path(app, url))
    with app.app_context():
        db = get_db()
        assert db.execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0
        for table in ("user_keys", "encryption_keys"):
            assert db.execute(
                f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", (alice_id(app, alice),)
            ).fetchone()[0] == 0
        assert db.execute(
            "SELECT revoked_at FROM certificates WHERE user_id = ?", (alice_id(app, alice),)
        ).fetchone()[0] is not None
    assert os.path.exists(app.config["CA_CRL"])
    assert b"contract.txt" not in shared_with_me(bob)


def test_wipe_removes_the_copies_made_for_the_user(app, alice, bob):
    bob_url = new_file(bob, name="bob-notes.txt")
    share(bob, bob_url, alice.handle)
    set_duress(alice, mode="wipe")
    log_in(app, alice, DURESS)
    with app.app_context():
        db = get_db()
        assert db.execute(
            "SELECT COUNT(*) FROM file_keys WHERE user_id = ?", (alice_id(app, alice),)
        ).fetchone()[0] == 0
        assert db.execute(
            "SELECT revoked_at FROM shares WHERE recipient_id = ?", (alice_id(app, alice),)
        ).fetchone()[0] is not None
    # the owner's own copy is untouched
    assert download(bob, bob_url).data == CONTRACT

def test_after_a_wipe_the_real_password_starts_over(app, alice):
    def encryption_key():
        with app.app_context():
            return get_db().execute(
                "SELECT public_key FROM encryption_keys WHERE user_id = ?", (alice_id(app, alice),)
            ).fetchone()

    before = encryption_key()["public_key"]
    set_duress(alice, mode="wipe")
    log_in(app, alice, DURESS)
    assert encryption_key() is None
    real, _ = log_in(app, alice, PASSWORD)
    # a new key pair at the first real login after the wipe
    assert encryption_key()["public_key"] != before
    url = new_file(real)
    verified = f"Record verified. Signature valid, signed by {alice.handle}."
    assert verified.encode() in real.get(url).data


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
        html = client.get("/auth/duress").data
        for shown in (str(auth.show_handle(username)), username):
            html = html.replace(shown.encode(), b"USER")
        return re.sub(rb'name="csrf_token" value="[^"]*"', b"", html)

    assert page(alice, alice.handle) == page(bob, bob.handle)


def test_login_checks_both_passwords_every_time(app, client, monkeypatch):
    handle = register(client)
    calls = []

    def counting(stored_hash, password):
        calls.append(stored_hash)
        return real_check(stored_hash, password)

    real_check = auth.check_password
    monkeypatch.setattr(auth, "check_password", counting)
    client.post("/auth/login", data={"username": handle, "password": "wrong guess"})
    assert len(calls) == 2
    client.post("/auth/login", data={"username": handle, "password": PASSWORD})
    assert len(calls) == 4


def test_duress_with_two_factor_still_asks_for_the_code(app, alice):
    secret = turn_on(alice)
    set_duress(alice)
    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/login/code"
    r = forced.post("/auth/login/code", data={"code": code(secret, 1)})
    assert r.headers["Location"] == "/"
    assert b"No files found." in forced.get("/").data



def test_with_two_factor_the_wipe_waits_for_the_code(app, alice):
    secret = turn_on(alice)
    url = new_file(alice)
    set_duress(alice, mode="wipe")
    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/login/code"
    # the duress password alone destroys nothing, but the alarm is raised
    assert os.path.exists(stored_path(app, url))
    assert ("duress", "used") in audit_rows(app)

    r = forced.post("/auth/login/code", data={"code": code(secret, 1)})
    assert r.headers["Location"] == "/"
    assert not os.path.exists(stored_path(app, url))
