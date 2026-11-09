"""An account's levels: the duress password opens a second vault that is
real, and keys, not hidden buttons, keep it from the first. "Section 13"
is the list of checks the design asked the next audit to make."""
import os
import re
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from app import levels
from app.auth import show_handle
from app.db import get_db
from app.invites import create_admin_invite
from security.hybrid import unwrap_file_key
from security.keychain import follow_link, unlock_key
from security.passwords import check_password

from .conftest import PASSWORD, logged_in
from .test_duress import DURESS, alice_id, log_in, set_duress
from .test_files import (
    CONTRACT,
    cover_files,
    delete,
    dismiss,
    download,
    file_id,
    my_files,
    new_file,
    revoke,
    share,
    shared_with_me,
    stored_path,
    upload,
    user_id,
)
from .test_totp import code, turn_on

# a duress password set from a level 1 session, for level 2
DEEPER = "lantern-quiet-harbor-29"
MENU = b"Lunch on Friday: soup, bread, apples.\n"


def at_level_one(app, client, mode="cover"):
    set_duress(client, mode)
    forced, r = log_in(app, client, DURESS)
    assert r.headers["Location"] == "/"
    return forced


def make_admin(app, client):
    app.test_cli_runner().invoke(args=["admin", "grant", client.handle])


def tick(monkeypatch, seconds):
    """Move the clocks the two-factor codes and the limits read: a code is
    taken only one step either side of the current one."""
    now = time.time() + seconds
    monkeypatch.setattr(time, "time", lambda: now)


def rows(app):
    with app.app_context():
        return [
            tuple(r)
            for r in get_db().execute("SELECT action, outcome, level FROM audit_log ORDER BY id")
        ]


def gone(app, url):
    """The stored file of url is removed, maybe by the background part of a wipe."""
    deadline = time.monotonic() + 3
    while os.path.exists(stored_path(app, url)) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not os.path.exists(stored_path(app, url))


def test_the_duress_password_opens_a_vault_of_its_own(app, alice):
    new_file(alice)
    forced = at_level_one(app, alice)
    assert b"contract.txt" not in forced.get("/").data
    # what it does is real: an upload stays, and opens
    menu = new_file(forced, MENU, "menu.txt")
    assert download(forced, menu).data == MENU
    assert b"menu.txt" in my_files(forced)
    # the real password sees both, the duress vault's files as cover files
    assert b"contract.txt" in my_files(alice) and b"menu.txt" not in my_files(alice)
    assert b"menu.txt" in cover_files(alice)
    assert download(alice, menu).data == MENU


def test_a_session_sees_its_level_and_those_below_only(app, alice):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    set_duress(forced, duress=DEEPER)
    deeper, r = log_in(app, alice, DEEPER)
    assert r.headers["Location"] == "/"
    notes = new_file(deeper, b"Notes from the meeting.\n", "notes.txt")
    # level 2 does not see level 1; level 1 sees level 2 as its cover files
    assert b"menu.txt" not in deeper.get("/").data
    assert deeper.get(menu).status_code == 404
    assert b"notes.txt" in cover_files(forced)
    assert download(forced, notes).data == b"Notes from the meeting.\n"


def test_an_own_file_hidden_by_its_level_answers_like_a_deleted_one(app, alice):
    hidden = new_file(alice)
    deleted = new_file(alice, name="old.txt")
    delete(alice, deleted)
    forced = at_level_one(app, alice)
    before = len(rows(app))
    for url in (hidden, deleted):
        assert forced.get(url).status_code == 404
        assert download(forced, url).status_code == 404
    # neither leaves a row
    assert len(rows(app)) == before


def test_a_received_file_hidden_by_its_level_answers_like_a_dismissed_one(app, alice, bob):
    hidden = new_file(bob, name="figures.txt")
    share(bob, hidden, alice.handle)
    # its twin: a file shared with her that she dismissed
    dismissed = new_file(bob, name="old-figures.txt")
    share(bob, dismissed, alice.handle)
    dismiss(alice, dismissed)
    forced = at_level_one(app, alice)
    answers = []
    for url in (hidden, dismissed):
        r = forced.get(url)
        answers.append((r.status_code, rows(app)[-1]))
    assert answers == [(403, ("access", "denied", 1))] * 2
    assert b"figures.txt" not in shared_with_me(forced)


def test_no_form_at_level_one_takes_the_real_password(app, alice):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    for r in (
        download(forced, menu, PASSWORD, follow_redirects=True),
        upload(forced, password=PASSWORD),
        delete(forced, menu, PASSWORD, follow_redirects=True),
        set_duress(forced, password=PASSWORD, duress=DEEPER),
    ):
        assert b"Wrong password" in r.data
    assert download(forced, menu).data == MENU


def test_the_limits_count_each_level_apart(app, alice):
    url = new_file(alice)
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    for _ in range(5):
        download(alice, url, "a guess")
    assert download(alice, url).status_code == 429
    # the real session's failures do not lock the duress one, nor the reverse
    assert download(forced, menu).status_code == 200
    for _ in range(5):
        download(forced, menu, "a guess")
    assert download(forced, menu).status_code == 429


def test_a_duress_login_is_one_row_at_its_level(app, alice):
    at_level_one(app, alice)
    assert rows(app)[-1] == ("login", "ok", 1)


ALARM = b'">duress</span>'


def test_the_real_admin_sees_the_alarm_and_the_duress_session_a_login(app, alice):
    make_admin(app, alice)
    forced = at_level_one(app, alice)
    assert ALARM in alice.get("/admin/log").data
    assert ALARM in alice.get("/admin/log?problems=1").data
    page = forced.get("/admin/log").data
    assert ALARM not in page and b'<td class="vs-mono">login</td>' in page
    assert ALARM not in forced.get("/admin/log?problems=1").data


def test_a_level_one_admin_sees_no_level_zero_rows(app, alice, bob, monkeypatch):
    make_admin(app, alice)
    secret = turn_on(alice)
    real = new_file(alice)
    share(alice, real, bob.handle)
    download(bob, real)
    tick(monkeypatch, 30)
    alice.post("/admin/invites/new", data={"password": PASSWORD, "code": code(secret)})
    with app.app_context():
        number = get_db().execute("SELECT MAX(id) FROM invites").fetchone()[0]
    her_code = f"code {number}, ".encode()

    set_duress(alice)
    tick(monkeypatch, 60)
    forced, _ = log_in(app, alice, DURESS)
    forced.post("/auth/login/code", data={"code": code(secret)})
    menu = new_file(forced, MENU, "menu.txt")
    share(forced, menu, bob.handle)
    # written at bob's level 0, about a file alice holds at level 1: bob
    # could check that it shows
    download(bob, menu)

    for page in (
        forced.get("/admin/log").data,
        forced.get("/admin/log?problems=1").data,
    ):
        assert file_id(real).encode() not in page and her_code not in page
    assert file_id(menu).encode() in forced.get("/admin/log").data
    codes = forced.get("/admin/invites").data
    assert b'Your codes <span class="vs-count">0</span>' in codes
    assert b"Your codes may create 5 more accounts" in codes
    # the real account sees all of it
    page = alice.get("/admin/log").data
    assert file_id(real).encode() in page and file_id(menu).encode() in page and her_code in page


def test_older_pages_keep_the_level_rule(app, alice):
    make_admin(app, alice)
    real = new_file(alice)
    forced = at_level_one(app, alice)
    with app.app_context():
        db = get_db()
        for _ in range(250):
            db.execute("INSERT INTO audit_log (action, outcome) VALUES ('test', 'ok')")
        db.commit()
    first = forced.get("/admin/log").data
    older = re.search(rb'href="([^"]*before=[^"]*)"', first).group(1).decode()
    page = forced.get(older.replace("&amp;", "&")).data
    assert b'<td class="vs-mono">register</td>' in page
    assert file_id(real).encode() not in page


def test_rows_no_session_wrote_show_at_every_level(app, alice):
    make_admin(app, alice)
    forced = at_level_one(app, alice)
    # registering, as admin grants and bans, is not a session's act
    assert b'<td class="vs-mono">register</td>' in forced.get("/admin/log").data


def test_a_level_one_admin_makes_codes_of_its_own(app, alice, monkeypatch):
    make_admin(app, alice)
    secret = turn_on(alice)
    with app.app_context():
        for _ in range(5):
            create_admin_invite(alice_id(app, alice))
    set_duress(alice)
    tick(monkeypatch, 30)
    forced, _ = log_in(app, alice, DURESS)
    forced.post("/auth/login/code", data={"code": code(secret)})
    # level 0 used up its allowance; level 1 has its own, and its code works
    tick(monkeypatch, 60)
    r = forced.post("/admin/invites/new", data={"password": DURESS, "code": code(secret)})
    assert re.search(rb'vs-invite-code vs-mono">[A-Z2-9-]+<', r.data)
    assert b'Your codes <span class="vs-count">1</span>' in forced.get("/admin/invites").data
    assert b'Your codes <span class="vs-count">6</span>' in alice.get("/admin/invites").data


def test_a_new_duress_password_works_after_48_hours(app, alice, monkeypatch):
    app.config["DURESS_DELAY"] = 48 * 3600
    r = set_duress(alice)
    assert b"It becomes active in 48 hours." in r.data
    # not yet: it is refused like a wrong password, and counts as one
    _, r = log_in(app, alice, DURESS)
    assert b"Incorrect username or password." in r.data
    tick(monkeypatch, 48 * 3600 + 1)
    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/"
    assert rows(app)[-1] == ("login", "ok", 1)


def test_setting_a_duress_password_answers_the_same_at_levels_0_and_1(app, alice, monkeypatch):
    app.config["DURESS_DELAY"] = 48 * 3600
    real = set_duress(alice, duress=DURESS)
    tick(monkeypatch, 48 * 3600 + 1)
    forced, _ = log_in(app, alice, DURESS)
    duress = set_duress(forced, duress=DEEPER)

    # the same page, the same message
    assert b"It becomes active in 48 hours." in real.data
    assert normalized(real.data, alice.handle) == normalized(duress.data, alice.handle)
    # and after the delay, each opens a smaller vault that is real
    tick(monkeypatch, 2 * (48 * 3600 + 1))
    deeper, r = log_in(app, alice, DEEPER)
    assert r.headers["Location"] == "/"
    assert rows(app)[-1] == ("login", "ok", 2)
    notes = new_file(deeper, b"Notes from the meeting.\n", "notes.txt")
    assert download(deeper, notes).data == b"Notes from the meeting.\n"


def test_level_two_answers_the_same_and_changes_nothing(app, alice):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    deeper, _ = log_in(app, alice, DEEPER)
    with app.app_context():
        before = get_db().execute("SELECT * FROM credentials ORDER BY id").fetchall()
    r = set_duress(deeper, duress="harbor-lantern-quiet-41")
    assert b"Duress password saved." in r.data
    with app.app_context():
        assert get_db().execute("SELECT * FROM credentials ORDER BY id").fetchall() == before


def move(client, urls, direction, password=None):
    data = {
        "file": [file_id(u) for u in urls],
        "direction": direction,
        "password": password or getattr(client, "password", PASSWORD),
    }
    return client.post("/auth/duress/cover", data=data, follow_redirects=True)


def test_moving_files_to_cover_and_back(app, alice, bob):
    real = new_file(alice)
    received = new_file(bob, name="figures.txt")
    share(bob, received, alice.handle)
    forced = at_level_one(app, alice)
    before = len(rows(app))
    r = move(alice, [real, received], "down")
    assert b"Moved 2 files." in r.data
    # moves are not logged: the log of the lower vault must not show them
    assert len(rows(app)) == before
    # the duress vault opens them now, and the real one lists them as cover
    assert download(forced, real).data == CONTRACT
    assert b"figures.txt" in shared_with_me(forced)
    assert b"contract.txt" in cover_files(alice) and b"contract.txt" not in my_files(alice)
    # bob's own copy is not touched
    assert download(bob, received).status_code == 200

    before = len(rows(app))
    move(alice, [real], "up")
    assert len(rows(app)) == before
    assert forced.get(real).status_code == 404
    assert b"contract.txt" in my_files(alice)


def test_moving_asks_for_the_password(app, alice):
    real = new_file(alice)
    r = move(alice, [real], "down", "a guess")
    assert b"Wrong password" in r.data
    assert b"contract.txt" in my_files(alice)


def test_a_session_moves_only_what_it_sees(app, alice):
    real = new_file(alice)
    forced = at_level_one(app, alice)
    # level 1 cannot reach a level 0 file, by any id
    r = move(forced, [real], "down")
    assert b"Moved 0 files." in r.data
    r = move(forced, [real], "up")
    assert b"Moved 0 files." in r.data
    assert b"contract.txt" in my_files(alice)


def test_the_page_says_when_the_cover_vault_last_changed(app, alice):
    page = alice.get("/auth/duress").data
    assert b"Cover files last changed: never" in page
    move(alice, [new_file(alice)], "down")
    page = alice.get("/auth/duress").data
    assert re.search(rb"Cover files last changed: \d{4}-\d{2}-\d{2} \d{2}:\d{2}", page)


def test_the_bottom_vault_has_nowhere_to_move_files(app, alice):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    deeper, _ = log_in(app, alice, DEEPER)
    notes = new_file(deeper, b"Notes from the meeting.\n", "notes.txt")
    r = move(deeper, [notes], "down")
    assert b"could not be saved" in r.data
    assert download(deeper, notes).status_code == 200


def test_a_wipe_destroys_level_zero_and_nothing_else(app, alice, bob):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    real = new_file(alice)
    share(alice, real, bob.handle)
    received = new_file(bob, name="figures.txt")
    share(bob, received, alice.handle)
    with app.app_context():
        keys_before = get_db().execute("SELECT * FROM level_keys ORDER BY user_id, level").fetchall()
    set_duress(alice, "wipe")

    log_in(app, alice, DURESS)
    assert gone(app, real)
    assert alice.get(real).status_code == 404
    assert b"contract.txt" not in shared_with_me(bob)
    assert b"figures.txt" not in shared_with_me(alice)
    # the keys stay, so the cover files and the real password still work
    with app.app_context():
        assert get_db().execute("SELECT * FROM level_keys ORDER BY user_id, level").fetchall() == keys_before
    assert download(alice, menu).data == MENU
    after = new_file(alice, name="after.txt")
    assert f"Signature valid, signed by {alice.handle}.".encode() in alice.get(after).data


def test_a_level_two_wipe_leaves_level_zero_intact(app, alice):
    real = new_file(alice)
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    set_duress(forced, "wipe", duress=DEEPER)
    log_in(app, alice, DEEPER)
    assert alice.get(menu).status_code == 404
    assert download(alice, real).data == CONTRACT
    after = new_file(alice, name="after.txt")
    assert f"Signature valid, signed by {alice.handle}.".encode() in alice.get(after).data


def test_every_account_has_three_levels_of_one_shape(app, alice, bob):
    set_duress(alice, "wipe")
    with app.app_context():
        db = get_db()
        creds = db.execute(
            "SELECT user_id, password_hash, length(kdf_salt) AS salt, length(lock) AS lock"
            " FROM credentials"
        ).fetchall()
        keys = db.execute(
            "SELECT level, length(public_key) AS public, link IS NULL AS top FROM level_keys"
        ).fetchall()
        policies = {len(r[0]) for r in db.execute("SELECT duress_policy FROM users")}
    assert len(creds) == 6 and all(r["password_hash"].startswith("$argon2id$") for r in creds)
    assert {(r["salt"], r["lock"]) for r in creds} == {(16, 60)}
    assert sorted(tuple(k) for k in keys) == [(0, 32, 1)] * 2 + [(1, 32, 0)] * 2 + [(2, 32, 0)] * 2
    assert len(policies) == 1


def test_login_costs_the_same_at_every_level(app, alice, monkeypatch):
    calls = []
    real_check = levels.check_password
    monkeypatch.setattr(levels, "check_password", lambda h, p: calls.append(h) or real_check(h, p))
    monkeypatch.setattr(levels, "check_password_of_unknown_user", lambda p: calls.append(None))
    set_duress(alice)
    for username, password in (
        (alice.handle, PASSWORD),
        (alice.handle, DURESS),
        (alice.handle, "a guess"),
        ("ghost#000000", PASSWORD),
    ):
        before, written = len(calls), len(rows(app))
        app.test_client().post("/auth/login", data={"username": username, "password": password})
        assert len(calls) - before == 3
        assert len(rows(app)) - written == 1


def test_a_change_made_in_between_is_kept(app, alice):
    uid = alice_id(app, alice)
    with app.app_context():
        def change(policy):
            if not change.ran:
                change.ran = True
                # another request writes between this one's read and write
                levels.update_policy(uid, lambda p: p.window_since.__setitem__(1, 111))
            policy.active_from[0] = 222

        change.ran = False
        levels.update_policy(uid, change)
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        policy = levels.open_policy(user)
    assert policy.window_since[1] == 111 and policy.active_from[0] == 222


def normalized(html, handle):
    text = html.decode()
    for shown in (str(show_handle(handle)), handle):
        text = text.replace(shown, "USER")
    text = re.sub(r'name="csrf_token" value="[^"]*"', 'name="csrf_token"', text)
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "ID", text)
    text = re.sub(r"\d{4}-\d{2}-\d{2}( \d{2}:\d{2}(:\d{2})?)?", "TIME", text)
    text = re.sub(r"<code>[A-Z2-7]{32}</code>", "<code>SECRET</code>", text)
    return re.sub(r"\b[0-9a-f]{16,}\b", "HEX", text)


def test_a_level_one_vault_looks_like_a_level_zero_one(app):
    """Section 13: for an account whose level 1 holds the same files as
    another account's level 0, every page and every answer is the same,
    apart from ids, tokens and times."""
    a, b = logged_in(app, "alice"), logged_in(app, "alice")
    carol = logged_in(app, "carol")
    forced = at_level_one(app, a)
    names = (("contract.txt", CONTRACT), ("menu.txt", MENU))
    files_a = [new_file(forced, data, name) for name, data in names]
    files_b = [new_file(b, data, name) for name, data in names]
    pages = ["/", "/upload", "/auth/totp", "/auth/duress"]
    for url in pages:
        assert normalized(forced.get(url).data, a.handle) == normalized(b.get(url).data, b.handle), url
    for fa, fb in zip(files_a, files_b):
        assert normalized(forced.get(fa).data, a.handle) == normalized(b.get(fb).data, b.handle)
        da, db = download(forced, fa), download(b, fb)
        assert da.data == db.data
        assert da.headers["Content-Disposition"] == db.headers["Content-Disposition"]
        sa = share(forced, fa, carol.handle, follow_redirects=True)
        sb = share(b, fb, carol.handle, follow_redirects=True)
        assert normalized(sa.data, a.handle) == normalized(sb.data, b.handle)
    wrong_a = download(forced, files_a[0], "a guess", follow_redirects=True)
    wrong_b = download(b, files_b[0], "a guess", follow_redirects=True)
    assert normalized(wrong_a.data, a.handle) == normalized(wrong_b.data, b.handle)


def test_the_duress_password_reaches_no_level_zero_key(app, alice, bob):
    """Section 13: with the duress password and a full copy of the database
    and storage, no level 0 file key can be recovered. Opened by hand, from
    the tables, not through the app's own unlocking."""
    real = new_file(alice)
    theirs = new_file(bob, name="figures.txt")
    share(bob, theirs, alice.handle)
    forced = at_level_one(app, alice)
    new_file(forced, MENU, "menu.txt")
    uid = alice_id(app, alice)
    with app.app_context():
        db = get_db()
        creds = db.execute("SELECT * FROM credentials WHERE user_id = ?", (uid,)).fetchall()
        links = {r["level"]: r["link"] for r in db.execute(
            "SELECT level, link FROM level_keys WHERE user_id = ?", (uid,))}
        copies = db.execute(
            "SELECT file_id, wrapped_key, level FROM file_keys WHERE user_id = ?", (uid,)
        ).fetchall()

    # everything the duress password opens: the one credential it matches...
    opened = []
    for cred in creds:
        if check_password(cred["password_hash"], DURESS):
            for level in range(3):
                try:
                    opened.append(unlock_key(
                        cred["lock"], DURESS, cred["kdf_salt"], f"lock|{uid}|{level}".encode()))
                except InvalidTag:
                    pass
    # ...and whatever its keys open in turn
    for _ in range(3):
        for key in list(opened):
            for level, link in links.items():
                if link is None:
                    continue
                try:
                    found = follow_link(key, link, f"link|{uid}|{level}".encode())
                except InvalidTag:
                    continue
                if all(found.public_key().public_bytes_raw() != k.public_key().public_bytes_raw()
                       for k in opened):
                    opened.append(found)
    assert len(opened) == 2  # levels 1 and 2

    level_zero = [c for c in copies if c["level"] == 0]
    assert {c["file_id"] for c in level_zero} == {file_id(real), file_id(theirs)}
    for key in opened:
        for c in level_zero:
            for level in range(3):
                with pytest.raises(InvalidTag):
                    unwrap_file_key(key, c["wrapped_key"], c["file_id"], uid, level)
        # nor the lock of level 0, nor the link from 0 down to 1
        with pytest.raises(InvalidTag):
            follow_link(key, links[1], f"link|{uid}|1".encode())
    zero = [c for c in creds if check_password(c["password_hash"], PASSWORD)][0]
    with pytest.raises(InvalidTag):
        unlock_key(zero["lock"], DURESS, zero["kdf_salt"], f"lock|{uid}|0".encode())


# where a session's level may be read (section 11): the levels themselves,
# the session they are loaded into, the level an audit row is written at,
# and the invite codes each level sees
LEVEL_READERS = {"levels.py", "auth.py", "audit.py", "invites.py"}


def test_the_level_is_read_in_the_named_places_only():
    app_dir = Path(__file__).parent.parent / "app"
    for path in app_dir.glob("*.py"):
        text = path.read_text()
        assert "g.duress" not in text, path.name
        # other modules call into app/levels.py, but never see a level
        if path.name not in LEVEL_READERS:
            assert not re.search(r"\blevel\b", text, re.I), path.name
    # no page is ever given the level: it looks the same at every one
    for path in (app_dir / "templates").rglob("*.html"):
        assert not re.search(r"\blevel\b", path.read_text(), re.I), path.name
