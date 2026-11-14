"""An account's levels: the duress password opens a second vault that is
real, and keys, not hidden buttons, keep it from the first. "Section 13"
is the list of checks the design asked the next audit to make."""
import os
import re
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from sqlcipher3 import dbapi2 as sqlcipher

from app import create_app, levels
from app.admin import log_entries
from app.auth import show_handle
from app.db import get_db, init_db
from app.invites import create_admin_invite
from security.hybrid import public_bytes, unwrap_file_key
from security.keychain import follow_link, lock_secret, unlock_key, verifier
from security import passwords
from security.passwords import derive_master

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
    private_key,
    revoke,
    share,
    shared_with_me,
    stored_path,
    upload,
    user_id,
)
from .test_totp import RECOVERY_SHAPE, code, secret_on_page, turn_on

# a duress password set from a level 1 session, for level 2
DEEPER = "lantern-quiet-harbor-29"
MENU = b"Lunch on Friday: soup, bread, apples.\n"
# a password for every level, the real one first
PASSWORDS = [PASSWORD, DURESS, DEEPER] + [f"copper-lantern-orchard-{n}" for n in range(3, 8)]


def descend(app, client, to):
    """A session at level `to` of client's account: each level, from the real
    password down, sets the duress password of the next one and is left by a
    login with it, as a coercer who knows the design would go."""
    session = client
    for level in range(1, to + 1):
        set_duress(session, duress=PASSWORDS[level])
        session, r = log_in(app, client, PASSWORDS[level])
        assert r.headers["Location"] == "/", (level, r.headers.get("Location"))
    return session


def opened(*open_levels):
    """windows() of an account whose open windows are these levels."""
    return [level in open_levels for level in range(levels.LEVELS)]


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


def test_a_level_one_admin_sees_the_alarm_of_level_two(app, alice):
    """One step down the alarm works as at the top: a level 1 admin session
    sees its account's level 2 logins as the alarm, as level 0 sees level
    1's, or it would know it is not the top."""
    make_admin(app, alice)
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    for url in ("/admin/log", "/admin/log?problems=1"):
        assert ALARM not in forced.get(url).data
    log_in(app, alice, DEEPER)
    for url in ("/admin/log", "/admin/log?problems=1"):
        assert forced.get(url).data.count(ALARM) == 1


def test_every_admin_session_sees_another_account_s_alarm(app, alice, bob):
    """Another account's duress login is the alarm at every level, as the
    real session shows it: otherwise an accomplice with a duress password
    on an account of their own could tell a duress admin session apart."""
    make_admin(app, alice)
    forced = at_level_one(app, alice)
    set_duress(bob)

    def alarms():
        return [viewer.get(url).data.count(ALARM)
                for viewer in (alice, forced) for url in ("/admin/log", "/admin/log?problems=1")]

    before = alarms()
    log_in(app, bob, DURESS)
    assert [a - b for a, b in zip(alarms(), before)] == [1, 1, 1, 1]


def test_a_duress_admin_log_holds_no_file_row_and_no_code_number(app, alice, bob, monkeypatch):
    """Design revision 2, B3: with file activity and invite code numbers left
    to the console, a duress admin session's log has no row a cover file
    could miss, and no numbers that count the codes made above it."""
    make_admin(app, alice)
    secret = turn_on(alice)
    real = new_file(alice)
    share(alice, real, bob.handle)
    download(bob, real)
    tick(monkeypatch, 30)
    alice.post("/admin/invites/new", data={"password": PASSWORD, "code": code(secret)})

    set_duress(alice)
    tick(monkeypatch, 60)
    forced, _ = log_in(app, alice, DURESS)
    forced.post("/auth/login/code", data={"code": code(secret)})
    menu = new_file(forced, MENU, "menu.txt")
    share(forced, menu, bob.handle)
    download(bob, menu)
    tick(monkeypatch, 60)
    forced.post("/admin/invites/new", data={"password": DURESS, "code": code(secret)})

    for viewer in (forced, alice):
        for url in ("/admin/log", "/admin/log?problems=1"):
            page = viewer.get(url).data
            assert file_id(real).encode() not in page and file_id(menu).encode() not in page
            assert not re.search(rb'<td class="vs-mono">(upload|download|share|verify)</td>', page)
            assert not re.search(rb"code \d", page)
    assert b'Your codes <span class="vs-count">1</span>' in forced.get("/admin/invites").data
    # the console has it all
    with app.app_context():
        entries = log_entries(limit=1000)
    assert {file_id(real), file_id(menu)} <= {e["file_id"] for e in entries}
    assert sum(bool(re.search(r"code \d", e["detail"] or "")) for e in entries) >= 4


def another_server(app, tmp_path):
    """A second, empty server with the first one's settings and CA."""
    folder = tmp_path / "another-server"
    other = create_app({
        **{k: v for k, v in app.config.items() if k.isupper()},
        "DATABASE": str(folder / "db.sqlite3"), "STORAGE_FOLDER": str(folder / "storage"),
        "SECRETS_DIR": str(folder / "secrets"), "SETTINGS_FILE": str(folder / "server.toml"),
        "CA_CRL": str(folder / "crl.pem"),
    })
    with other.app_context():
        init_db()
    return other


def test_a_duress_admin_log_reads_as_a_real_admin_log(app, tmp_path):
    """Design revision 2, B3: the log a duress admin session sees is the one
    a real admin sees on a server where the same visible things happened,
    though its cover file was uploaded at level 0 and moved down."""
    alice = logged_in(app, "alice")
    make_admin(app, alice)
    move(alice, [new_file(alice, MENU, "menu.txt")], "down")
    forced = at_level_one(app, alice)
    new_file(forced, b"Notes from the meeting.\n", "notes.txt")

    other = another_server(app, tmp_path)
    plain = logged_in(other, "alice")
    make_admin(other, plain)
    for name, data in (("menu.txt", MENU), ("notes.txt", b"Notes from the meeting.\n")):
        new_file(plain, data, name)

    for url in ("/admin/log", "/admin/log?problems=1"):
        assert normalized(forced.get(url).data, alice.handle) == \
            normalized(plain.get(url).data, plain.handle), url


def test_older_pages_keep_the_level_rule(app, alice):
    make_admin(app, alice)
    real = new_file(alice)
    forced = at_level_one(app, alice)
    with app.app_context():
        db = get_db()
        for _ in range(250):
            db.execute("INSERT INTO audit_log (action, outcome) VALUES ('logout', 'ok')")
        db.commit()
    first = forced.get("/admin/log").data
    older = re.search(rb'href="([^"]*before=[^"]*)"', first).group(1).decode()
    page = forced.get(older.replace("&amp;", "&")).data
    assert b'<td class="vs-mono">register</td>' in page
    # the level 1 login, and not the one at level 0 before it
    assert page.count(b'<td class="vs-mono">login</td>') == 1
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


DELAY = 48 * 3600
# a duress password saved where one is in use
NEW = "willow-copper-signal-63"
WRONG = b"Incorrect username or password."


def in_use(app, alice, monkeypatch):
    """A duress session whose password has started to work."""
    app.config["DURESS_DELAY"] = DELAY
    set_duress(alice)
    tick(monkeypatch, DELAY + 1)
    forced, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/"
    return forced


def test_an_old_duress_password_works_until_the_new_one_does(app, alice, monkeypatch):
    """Design revision 2, A6: a duress password replaced keeps working until
    the new one starts to, so whoever holds it notices nothing before; from
    then on only the new one opens the level."""
    in_use(app, alice, monkeypatch)
    set_duress(alice, duress=NEW)
    again, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/" and rows(app)[-1] == ("login", "ok", 1)
    assert download(again, new_file(again, MENU, "menu.txt")).data == MENU
    _, r = log_in(app, alice, NEW)
    assert WRONG in r.data
    tick(monkeypatch, DELAY + 1)
    _, r = log_in(app, alice, DURESS)
    assert WRONG in r.data
    _, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/" and rows(app)[-1] == ("login", "ok", 1)


def test_a_session_of_the_old_password_ends_when_the_new_one_starts(app, alice, monkeypatch):
    """Ended, never told its own password is wrong."""
    forced = in_use(app, alice, monkeypatch)
    set_duress(alice, duress=NEW)
    menu = new_file(forced, MENU, "menu.txt")
    tick(monkeypatch, DELAY + 1)
    assert forced.get("/").headers["Location"] == "/auth/login"
    r = download(forced, menu, follow_redirects=True)
    assert b"Wrong password." not in r.data and WRONG not in r.data
    assert r.request.path == "/auth/login"


def test_a_code_typed_after_the_switch_opens_nothing(app, alice, monkeypatch):
    """A login that typed the old password before the switch and its
    two-factor code after it gets no session either."""
    forced = in_use(app, alice, monkeypatch)
    theirs = secret_on_page(forced)
    forced.post("/auth/totp", data={"password": DURESS, "code": code(theirs)})
    set_duress(alice, duress=NEW)
    tick(monkeypatch, DELAY - 60)
    late, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/login/code"
    tick(monkeypatch, 120)
    r = late.post("/auth/login/code", data={"code": code(theirs)}, follow_redirects=True)
    assert b"Log in again." in r.data
    assert late.get("/").headers["Location"] == "/auth/login"


def test_removing_ends_both_duress_passwords_at_once(app, alice, monkeypatch):
    in_use(app, alice, monkeypatch)
    set_duress(alice, duress=NEW)
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    _, r = log_in(app, alice, DURESS)
    assert WRONG in r.data
    tick(monkeypatch, DELAY + 1)
    _, r = log_in(app, alice, NEW)
    assert WRONG in r.data


def test_what_the_old_holder_set_up_meanwhile_ends_with_the_switch(app, alice, monkeypatch):
    """In the 48 hours the old holder can still set a deeper password and
    turn two-factor login on; once the new password works, neither does,
    not even at the first login after the switch."""
    forced = in_use(app, alice, monkeypatch)
    set_duress(alice, duress=NEW)
    set_duress(forced, duress=DEEPER)
    theirs = secret_on_page(forced)
    r = forced.post("/auth/totp", data={"password": DURESS, "code": code(theirs)},
                    follow_redirects=True)
    assert b"Two-factor login is on." in r.data
    tick(monkeypatch, DELAY + 1)
    _, r = log_in(app, alice, DEEPER)
    assert WRONG in r.data
    _, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/"


@pytest.mark.parametrize("old, new", [("wipe", "cover"), ("cover", "wipe")])
def test_the_first_login_after_the_switch_follows_the_new_mode(app, alice, monkeypatch, old, new):
    app.config["DURESS_DELAY"] = DELAY
    url = new_file(alice)
    set_duress(alice, old)
    tick(monkeypatch, DELAY + 1)
    set_duress(alice, new, duress=NEW)
    tick(monkeypatch, DELAY + 1)
    _, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/"
    with app.app_context():
        kept = get_db().execute("SELECT 1 FROM files WHERE id = ?", (file_id(url),)).fetchone()
    assert (kept is None) == (new == "wipe")


def test_a_session_older_than_the_switch_saves_after_the_new_password(app, alice, monkeypatch):
    """A save made after the new password started to work, from a session
    opened before, replaces the new one, never the old one again."""
    in_use(app, alice, monkeypatch)
    set_duress(alice, duress=NEW)
    tick(monkeypatch, DELAY + 1)
    set_duress(alice, duress=DEEPER)
    _, r = log_in(app, alice, DURESS)
    assert WRONG in r.data
    _, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/"


def test_replacing_answers_as_saving_the_first(app, alice, bob, monkeypatch):
    """Saving where a duress password is in use answers as saving where none
    is: at a duress level as at another account's real one."""
    forced = in_use(app, alice, monkeypatch)
    pages = []
    for client in (forced, bob):
        first = set_duress(client, duress=DEEPER)
        tick(monkeypatch, DELAY + 1)
        second = set_duress(client, duress=NEW)
        pages.append([normalized(p.data, client.handle) for p in (first, second)])
    assert b"It becomes active in 48 hours." in second.data
    assert pages[0] == pages[1]


def test_the_password_page_refuses_a_duress_password_still_to_come(app, alice, monkeypatch):
    in_use(app, alice, monkeypatch)
    set_duress(alice, duress=NEW)
    for taken in (DURESS, NEW):
        r = change_password(alice, taken)
        assert b"Choose a password other than your duress password." in r.data


def test_the_last_level_refuses_a_replaced_password_as_the_levels_above(app, alice, bob, monkeypatch):
    """The password saved at the last level opens nothing, but it is kept and
    replaced as the levels above keep and replace theirs, so the Password
    page there answers the same through a replacement."""
    one, last = at_level_one(app, bob), descend(app, alice, levels.LEVELS - 1)
    app.config["DURESS_DELAY"] = DELAY
    answers = []
    for client in (one, last):
        set_duress(client, duress="harbor-lantern-quiet-41")
        tick(monkeypatch, DELAY + 1)
        client.get("/")
        set_duress(client, duress=NEW)
        answers.append([normalized(change_password(client, taken, password=client.password).data,
                                   client.handle)
                        for taken in ("harbor-lantern-quiet-41", NEW)])
    assert answers[0] == answers[1]
    assert all("Choose a password other than your duress password." in a for a in answers[0])


def test_the_review_offers_to_keep_or_replace_the_duress_password(app, alice):
    at_level_one(app, alice)
    real, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    page = real.get("/auth/review").data.decode()
    assert "Whoever holds it can log in with it again" in page
    form = re.search(r'<form method="post" action="/auth/duress".*?</form>', page, re.S)
    assert form is not None
    for name in ("csrf_token", "duress_password", "mode", "password"):
        assert f'name="{name}"' in form.group(0)
    r = set_duress(real, duress=NEW)
    assert b"Duress password saved." in r.data
    _, r = log_in(app, alice, NEW)
    assert r.headers["Location"] == "/"


def test_a_duress_password_set_at_the_last_level_opens_nothing(app, alice):
    deeper = descend(app, alice, levels.LEVELS - 1)
    r = set_duress(deeper, duress="harbor-lantern-quiet-41")
    assert b"Duress password saved." in r.data
    # the end of the chain: once its delay is over, it still opens nothing,
    # and no key of the account opens with it: its lock holds a spare key
    _, r = log_in(app, alice, "harbor-lantern-quiet-41")
    assert b"Incorrect username or password." in r.data
    uid = alice_id(app, alice)
    with app.app_context():
        db = get_db()
        salt = db.execute("SELECT kdf_salt FROM users WHERE id = ?", (uid,)).fetchone()[0]
        locks = [r[0] for r in db.execute("SELECT lock FROM credentials WHERE user_id = ?", (uid,))]
        mine = {r[0] for r in db.execute("SELECT public_key FROM level_keys WHERE user_id = ?",
                                         (uid,))}
    master = derive_master("harbor-lantern-quiet-41", salt)
    opened = []
    for level in range(levels.KEY_LEVELS):
        secret = lock_secret(master, uid, level)
        for lock in locks:
            try:
                opened.append(unlock_key(lock, secret, f"lock|{uid}|{level}".encode()))
            except InvalidTag:
                pass
    assert len(opened) == 1 and public_bytes(opened[0]) not in mine


def settings_in_use(client, saved):
    """Every form of the Duress and Password pages, in an order that shows
    what a saved duress password changes."""
    me = client.password
    return [
        lambda: client.get("/auth/duress"),
        lambda: client.get("/auth/password"),
        lambda: set_duress(client, duress=saved),
        lambda: change_password(client, saved, password=me),
        lambda: set_duress(client, mode="wipe", duress=saved),
        lambda: change_password(client, saved, password=me),
        lambda: client.post("/auth/duress/remove", data={"password": me}, follow_redirects=True),
        lambda: change_password(client, saved, password=me),
    ]


def test_the_last_level_settings_answer_like_level_one(app, alice, bob, monkeypatch):
    """The Duress and Password pages answer at the last level as at another
    account's level 1, form after form, with the same Argon2 work. A duress
    password saved at the last level opens nothing, but the Password page
    there refuses it as a new password, as the levels above refuse theirs,
    until it is removed."""
    one = at_level_one(app, bob)
    two = descend(app, alice, levels.LEVELS - 1)
    argon2, _ = counted(monkeypatch)
    answers, costs = [], []
    for client in (two, one):
        pages, cost = [], []
        for step in settings_in_use(client, "harbor-lantern-quiet-41"):
            argon2.clear()
            pages.append(step().data)
            cost.append(len(argon2))
        answers.append([normalized(page, client.handle) for page in pages])
        costs.append(cost)
    assert answers[0] == answers[1]
    assert costs[0] == costs[1]
    assert b"Choose a password other than your duress password." in pages[3]
    assert b"Password changed." in pages[7]


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


def test_the_duress_page_lists_the_files_it_can_move(app, alice):
    real = new_file(alice)
    menu = new_file(alice, MENU, "menu.txt")
    move(alice, [menu], "down")
    page = alice.get("/auth/duress").data
    mine, cover = page.split(b"Move to the cover files")
    assert f'value="{file_id(real)}"'.encode() in mine and b">contract.txt<" in mine
    assert f'value="{file_id(menu)}"'.encode() in cover and b">menu.txt<" in cover
    assert page.count(b'name="file"') == 2


def test_moving_asks_for_the_password(app, alice):
    real = new_file(alice)
    r = move(alice, [real], "down", "a guess")
    assert b"Wrong password" in r.data
    assert b"contract.txt" in my_files(alice)


def test_a_new_share_keeps_a_file_in_the_cover_files(app, alice, bob):
    """Design revision 2, A4: sharing a file again outside a window leaves
    the recipient's copy where they put it."""
    url = new_file(bob, name="figures.txt")
    share(bob, url, alice.handle)
    move(alice, [url], "down")
    share(bob, url, alice.handle)
    assert b"figures.txt" in cover_files(alice)
    assert b"figures.txt" not in shared_with_me(alice)
    # inside a window a share still brings a file down, as designed
    forced = at_level_one(app, alice)
    mine = new_file(bob, name="minutes.txt")
    share(bob, mine, alice.handle)
    assert b"minutes.txt" in shared_with_me(forced)


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


def test_the_last_level_moves_files_like_level_one(app, alice, bob):
    """The last level a password opens has cover files too, under one more
    key that no password opens: its Duress page and its moves answer as a
    level 1 session's do, so the end of the chain shows only when a duress
    password set there never opens anything."""
    one = at_level_one(app, bob)
    two = descend(app, alice, levels.LEVELS - 1)
    answers = []
    for client in (two, one):
        notes = new_file(client, b"Notes from the meeting.\n", "notes.txt")
        new_file(client, MENU, "menu.txt")
        moved = move(client, [notes], "down")
        answers.append([
            normalized(moved.data, client.handle),
            normalized(client.get("/").data, client.handle),
            normalized(download(client, notes).data, client.handle),
        ])
        assert b"Moved 1 file." in moved.data
        assert b"notes.txt" in cover_files(client) and b"notes.txt" not in my_files(client)
        back = move(client, [notes], "up")
        answers[-1].append(normalized(back.data, client.handle))
        assert b"notes.txt" in my_files(client)
    assert answers[0] == answers[1]
    # the levels above see the last level's cover files among theirs
    move(two, [notes := new_file(two, b"Minutes.\n", "minutes.txt")], "down")
    assert b"minutes.txt" in cover_files(alice)
    assert download(alice, notes).data == b"Minutes.\n"


def windows(app, client):
    with app.app_context():
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (client.handle,)
        ).fetchone()
        return [bool(w) for w in levels.open_policy(user).window_since]


def test_a_share_arrives_where_the_duress_session_is(app, alice, bob):
    forced = at_level_one(app, alice)
    during = new_file(bob, name="figures.txt")
    share(bob, during, alice.handle)
    # the coercer sees it arrive, as on a real account
    assert b"figures.txt" in shared_with_me(forced)
    assert download(forced, during).status_code == 200
    # the next real login closes the window: shares arrive at level 0 again
    log_in(app, alice, PASSWORD)
    after = new_file(bob, name="minutes.txt")
    share(bob, after, alice.handle)
    assert b"minutes.txt" not in shared_with_me(forced)
    assert b"minutes.txt" in shared_with_me(alice)


def test_logins_at_one_two_then_one_close_only_the_higher_window(app, alice):
    forced = at_level_one(app, alice)
    assert windows(app, alice) == opened(1)
    set_duress(forced, duress=DEEPER)
    log_in(app, alice, DEEPER)
    assert windows(app, alice) == opened(1, 2)
    log_in(app, alice, DURESS)
    assert windows(app, alice) == opened(1)
    log_in(app, alice, PASSWORD)
    assert windows(app, alice) == opened()


def test_a_share_arrives_at_the_highest_open_window(app, alice, bob):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    deeper, _ = log_in(app, alice, DEEPER)
    url = new_file(bob, name="figures.txt")
    share(bob, url, alice.handle)
    # level 2 sees it, and so does level 1, which sees level 2
    assert b"figures.txt" in shared_with_me(deeper)
    assert b"figures.txt" in cover_files(forced)


def test_a_duress_session_deletes_softly(app, alice, bob, monkeypatch):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    share(forced, menu, bob.handle)
    r = delete(forced, menu, follow_redirects=True)
    assert b"Deleted menu.txt." in r.data
    # gone for everyone, recipients and the real password included...
    for client in (forced, alice, bob):
        assert client.get(menu).status_code == 404
    assert b"menu.txt" not in cover_files(alice)
    # ...but kept for the real owner, however long they stay away
    assert os.path.exists(stored_path(app, menu))
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET trashed_at = datetime('now', '-31 days')")
        db.commit()
    log_in(app, bob, PASSWORD)
    assert os.path.exists(stored_path(app, menu))
    # and 30 days from when their review first shows it
    real, _ = log_in(app, alice, PASSWORD)
    assert b"menu.txt" in real.get("/auth/review").data
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET review_from = datetime('now', '-31 days')")
        db.commit()
    log_in(app, bob, PASSWORD)
    assert not os.path.exists(stored_path(app, menu))
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def test_deletes_stay_soft_after_the_window_closes(app, alice):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    log_in(app, alice, PASSWORD)
    delete(forced, menu)
    with app.app_context():
        assert get_db().execute("SELECT trashed_at FROM files").fetchone()[0] is not None


def test_the_real_password_deletes_for_good(app, alice):
    real = new_file(alice)
    delete(alice, real)
    assert not os.path.exists(stored_path(app, real))
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM files").fetchone()[0] == 0


def a_duress_visit(app, alice, bob):
    """A coercer at level 1 uploads, deletes a cover file and receives a
    share from bob: what the next real login's review should show."""
    forced = at_level_one(app, alice)
    old = new_file(forced, MENU, "menu.txt")
    planted = new_file(forced, b"Not mine.\n", "planted.txt")
    delete(forced, old)
    arrived = new_file(bob, name="figures.txt")
    share(bob, arrived, alice.handle)
    return forced, old, planted, arrived


def test_the_next_real_login_gets_the_review(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    page = real.get("/auth/review").data
    for shown in (b"menu.txt", b"planted.txt", b"figures.txt", b"duress password was used"):
        assert shown in page, shown
    # the certificate stays with the operator: the page gives the time
    assert b"admin revoke --since" in page
    # what is done here shows in the duress vault: the page says so (D9)
    assert b"whoever logs in with the duress password again will see" in page


def review_done(client, leftover, password=PASSWORD):
    data = {"leftover": leftover, "password": password}
    return client.post("/auth/review/done", data=data, follow_redirects=True)


def test_the_review_lasts_until_the_owner_says_done(app, alice, bob):
    """Design revision 2, A2: every login goes to the review, through a
    logout or a timeout, until the owner says done."""
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    real.post("/auth/logout")
    again, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    # a session that timed out
    with app.app_context():
        db = get_db()
        db.execute("UPDATE sessions SET last_seen = datetime('now', '-31 minutes')")
        db.commit()
    assert again.get("/").headers["Location"].startswith("/auth/login")
    again, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    assert b"menu.txt" in again.get("/auth/review").data
    # done, with the password; what is left is restored
    assert b"Wrong password" in review_done(again, "restore", "a guess").data
    assert again.get("/auth/review").status_code == 200
    review_done(again, "restore")
    assert download(again, old).data == MENU
    _, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/"
    assert again.get("/auth/review").headers["Location"] == "/"


def test_done_can_let_what_is_left_go(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, _ = log_in(app, alice, PASSWORD)
    review_done(real, "let-go")
    assert not os.path.exists(stored_path(app, old))
    # the rest of what the window brought stays as it is
    assert download(forced, planted).status_code == 200


def test_other_open_sessions_get_the_review_link(app, alice, bob):
    a_duress_visit(app, alice, bob)
    # alice's own session was open all along; a new real login closes the
    # window, and from then on her open session links to the review too
    assert b'href="/auth/review"' not in alice.get("/").data
    log_in(app, alice, PASSWORD)
    assert b'href="/auth/review"' in alice.get("/").data
    review_done(alice, "restore")
    assert b'href="/auth/review"' not in alice.get("/").data


def test_a_duress_dismiss_can_be_put_back(app, alice, bob):
    """Design revision 2, A2: a dismiss in a duress session keeps the key
    copy, so the review can put the file back; the duress session still
    sees it dismissed."""
    url = new_file(bob, name="figures.txt")
    share(bob, url, alice.handle)
    move(alice, [url], "down")
    forced = at_level_one(app, alice)
    dismiss(forced, url)
    assert forced.get(url).status_code == 403
    real, _ = log_in(app, alice, PASSWORD)
    page = real.get("/auth/review").data
    assert b"figures.txt" in page
    assert b"Put back 1 file." in review_action(real, "put-back", [url]).data
    assert download(real, url).status_code == 200
    assert b"figures.txt" in shared_with_me(real)
    assert forced.get(url).status_code == 403
    # bob still sees his share, as after any dismiss
    assert alice.handle.split("#")[0].encode() in bob.get(url).data


def test_a_dismiss_at_level_one_answers_like_one_at_level_zero(app, alice, bob):
    one = at_level_one(app, alice)
    carol = logged_in(app, "carol")
    answers = []
    for client, recipient in ((one, alice), (carol, carol)):
        url = new_file(bob, name="figures.txt")
        share(bob, url, recipient.handle)
        if client is one:
            # shared while the window is open: it arrives at level 1
            assert b"figures.txt" in shared_with_me(one)
        before = len(rows(app))
        r = dismiss(client, url, follow_redirects=True)
        answers.append((normalized(r.data, client.handle), len(rows(app)) - before,
                        client.get(url).status_code))
    assert answers[0] == answers[1]


def test_the_trash_waits_for_an_owner_who_never_logs_in(app, alice, bob):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    delete(forced, menu)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET trashed_at = datetime('now', '-400 days')")
        db.commit()
    log_in(app, bob, PASSWORD)
    assert os.path.exists(stored_path(app, menu))


def test_a_new_duress_password_starts_without_the_old_holders_two_factor(app, alice):
    """A replaced duress password starts afresh, its two-factor login
    inherited again, so a code the old holder set up is never asked of the
    new one; after a remove and a new one alike."""
    set_duress(alice)
    forced, _ = log_in(app, alice, DURESS)
    theirs = secret_on_page(forced)
    forced.post("/auth/totp", data={"password": DURESS, "code": code(theirs)})
    set_duress(alice, duress="harbor-lantern-quiet-41")
    again, r = log_in(app, alice, "harbor-lantern-quiet-41")
    assert r.headers["Location"] != "/auth/login/code"
    theirs = secret_on_page(again)
    again.post("/auth/totp", data={"password": "harbor-lantern-quiet-41", "code": code(theirs)})
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    set_duress(alice, duress="copper-window-orchard-58")
    _, r = log_in(app, alice, "copper-window-orchard-58")
    assert r.headers["Location"] != "/auth/login/code"


def test_a_new_duress_password_takes_the_owners_code(app, alice, monkeypatch):
    secret = turn_on(alice)
    set_duress(alice)
    forced, _ = log_in(app, alice, DURESS)
    forced.post("/auth/login/code", data={"code": code(secret, 1)})
    tick(monkeypatch, 60)
    # the holder turns it off for the duress password
    forced.post("/auth/totp/disable", data={"password": DURESS, "code": code(secret, 1)})
    set_duress(alice, duress="harbor-lantern-quiet-41")
    other, r = log_in(app, alice, "harbor-lantern-quiet-41")
    assert r.headers["Location"] == "/auth/login/code"
    tick(monkeypatch, 60)
    assert other.post("/auth/login/code", data={"code": code(secret, 1)}).headers["Location"] == "/"


def test_let_go_at_a_duress_level_destroys_nothing(app, alice):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    set_duress(forced, "wipe", duress=DEEPER)
    log_in(app, alice, DEEPER)
    again, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/review"
    assert b"Review done." in review_done(again, "let-go", DURESS).data
    real, _ = log_in(app, alice, PASSWORD)
    assert b"menu.txt" in real.get("/auth/review").data
    assert b"Restored 1 file." in review_action(real, "restore", [menu]).data
    assert download(real, menu).data == MENU


def test_a_duress_level_starts_no_clock(app, alice, bob):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    deeper, _ = log_in(app, alice, DEEPER)
    notes = new_file(deeper, b"Notes from the meeting.\n", "notes.txt")
    delete(deeper, notes)
    # level 1's login closes level 2's window: its review is no reason to
    # start the 30 days, which only the real owner's review starts
    log_in(app, alice, DURESS)
    with app.app_context():
        assert get_db().execute("SELECT review_from FROM files").fetchone()[0] is None
    real, _ = log_in(app, alice, PASSWORD)
    assert b"notes.txt" in real.get("/auth/review").data
    assert b"Restored 1 file." in review_action(real, "restore", [notes]).data


def test_a_cover_move_leaves_a_dismissed_file_in_the_review(app, alice, bob):
    forced = at_level_one(app, alice)
    url = new_file(bob, name="figures.txt")
    share(bob, url, alice.handle)
    dismiss(forced, url)
    assert b"Moved 0 files." in move(forced, [url], "down").data
    real, _ = log_in(app, alice, PASSWORD)
    assert b"figures.txt" in real.get("/auth/review").data
    assert b"Put back 1 file." in review_action(real, "put-back", [url]).data


def test_a_duress_session_that_outlives_the_owners_done_is_reviewed(app, alice):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    real, _ = log_in(app, alice, PASSWORD)
    review_done(real, "restore")
    # the duress session is still open, and deletes after the owner's done
    delete(forced, menu)
    again, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    assert b"menu.txt" in again.get("/auth/review").data
    assert b"Restored 1 file." in review_action(again, "restore", [menu]).data


def review_action(client, action, urls, password=PASSWORD):
    data = {"file": [file_id(u) for u in urls], "password": password}
    return client.post(f"/auth/review/{action}", data=data, follow_redirects=True)


QUIET = b"the duress vault sees no change"
LOUD = b"the duress vault will see"


def seen(client, urls):
    """What a session sees: its lists, the Duress page and the given file
    pages, normalized."""
    return [normalized(client.get(u).data, client.handle) for u in ["/", "/auth/duress", *urls]]


def test_quiet_review_actions_leave_the_duress_vault_as_it_was(app, alice, bob):
    """Design revision 2, A5: the review's quiet actions, its defaults, change
    nothing that whoever logs in with the duress password again can see: a
    private copy of a deleted file, a label on an uploaded one, a removed
    one put back, an arrived one left where it is."""
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    report = new_file(bob, b"Report.\n", "report.txt")
    share(bob, report, alice.handle)
    dismiss(forced, report)
    forced.get("/")  # the message of the dismiss, shown once
    real, _ = log_in(app, alice, PASSWORD)
    page = real.get("/auth/review").data
    # every action says which kind it is, five quiet and five loud: copy
    # or restore, label or delete, leave or bring back, put back, replace,
    # and Done's let go or restore
    assert page.count(QUIET) == 5 and page.count(LOUD) == 5
    before = seen(forced, [old, planted, arrived, report])
    for action, urls, shown in (
        ("copy", [old], b"Saved a private copy of 1 file."),
        ("label", [planted], b"Labelled 1 file for you only."),
        ("put-back", [report], b"Put back 1 file."),
    ):
        assert shown in review_action(real, action, urls).data
    assert seen(forced, [old, planted, arrived, report]) == before


def test_a_private_copy_opens_at_the_owners_level_and_is_signed(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, _ = log_in(app, alice, PASSWORD)
    review_action(real, "copy", [old])
    uid = alice_id(app, alice)
    with app.app_context():
        db = get_db()
        copies = db.execute(
            "SELECT f.id, c.level FROM files f JOIN file_keys c ON c.file_id = f.id"
            " AND c.user_id = f.owner_id WHERE f.owner_id = ? AND f.filename = 'menu.txt'"
            " AND f.trashed_at IS NULL", (uid,)
        ).fetchall()
        still = db.execute("SELECT trashed_at FROM files WHERE id = ?", (file_id(old),)).fetchone()
    # a new file of the real level's own, and the deleted one still deleted
    assert len(copies) == 1 and copies[0]["level"] == 0 and copies[0]["id"] != file_id(old)
    assert still["trashed_at"] is not None
    url = f"/files/{copies[0]['id']}"
    assert download(real, url).data == MENU
    assert b"Signature valid" in real.get(url).data
    forced.get("/")  # the message of the delete, shown once
    assert b"menu.txt" in my_files(real) and b"menu.txt" not in forced.get("/").data


def test_a_label_shows_on_the_labelling_levels_lists_only(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, _ = log_in(app, alice, PASSWORD)
    chip = b"uploaded under duress"
    assert chip not in real.get("/").data
    review_action(real, "label", [planted])
    assert chip in cover_files(real)
    assert chip not in forced.get("/").data
    # and it goes with the file
    review_action(real, "delete", [planted])
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM labels").fetchone()[0] == 0


def copies_of_menu(app, alice):
    with app.app_context():
        return get_db().execute(
            "SELECT COUNT(*) FROM files WHERE owner_id = ? AND filename = 'menu.txt'"
            " AND trashed_at IS NULL", (alice_id(app, alice),)
        ).fetchone()[0]


def test_done_after_a_private_copy_brings_nothing_back(app, alice, bob):
    """A copied file leaves the review: neither Done's default nor a second
    copy brings the deleted one back beside it."""
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    forced.get("/")
    real, _ = log_in(app, alice, PASSWORD)
    review_action(real, "copy", [old])
    before = seen(forced, [old])
    assert b"Saved a private copy of 0 files." in review_action(real, "copy", [old]).data
    assert b"Review done." in review_done(real, "restore").data
    assert seen(forced, [old]) == before
    assert copies_of_menu(app, alice) == 1


def deleted_entry(page, name):
    panel = page.split("Deleted</h2>")[1].split("</form>")[0]
    return re.search(r"<li>(?:(?!</li>).)*" + re.escape(name) + r"(?:(?!</li>).)*</li>",
                     panel, re.S).group(0)


def test_the_review_marks_a_deleted_file_uploaded_while_it_was_in_use(app, alice, bob):
    """A private copy signs what it copies: the list says which deleted files
    were uploaded in the window, maybe by whoever held the password."""
    older = new_file(alice, b"Older notes.\n", "older.txt")
    move(alice, [older], "down")
    # times go by the second: the window opens in a later one
    time.sleep(1.1)
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    delete(forced, older)
    real, _ = log_in(app, alice, PASSWORD)
    page = real.get("/auth/review").data.decode()
    assert "uploaded while it was in use" in deleted_entry(page, "menu.txt")
    assert "uploaded while it was in use" not in deleted_entry(page, "older.txt")


def test_quiet_actions_answer_the_same_one_level_down(app, alice, bob):
    """A level 1 session reviewing a level 2 window copies and labels as
    another account's level 0 does with its level 1 window."""
    one = at_level_one(app, alice)
    set_duress(one, duress=DEEPER)
    two, _ = log_in(app, alice, DEEPER)
    visits = []
    for visitor in (two, at_level_one(app, bob)):
        old = new_file(visitor, MENU, "menu.txt")
        planted = new_file(visitor, b"Not mine.\n", "planted.txt")
        delete(visitor, old)
        visits.append((old, planted))
    reviewers = [log_in(app, alice, DURESS), log_in(app, bob, PASSWORD)]
    pages = []
    for (client, r), (old, planted) in zip(reviewers, visits):
        assert r.headers["Location"] == "/auth/review"
        steps = [client.get("/auth/review"),
                 review_action(client, "copy", [old], password=client.password),
                 review_action(client, "label", [planted], password=client.password),
                 client.get("/")]
        pages.append([normalized(step.data, client.handle) for step in steps])
    assert pages[0] == pages[1]
    assert b"uploaded under duress" in reviewers[0][0].get("/").data


def test_a_replaced_password_starts_without_the_old_holders_labels(app, alice):
    one = at_level_one(app, alice)
    set_duress(one, duress=DEEPER)
    two, _ = log_in(app, alice, DEEPER)
    planted = new_file(two, b"Not mine.\n", "planted.txt")
    again, _ = log_in(app, alice, DURESS)
    review_action(again, "label", [planted], password=DURESS)
    assert b"uploaded under duress" in cover_files(again)
    set_duress(alice, duress=NEW)
    fresh, r = log_in(app, alice, NEW)
    assert b"planted.txt" in cover_files(fresh)
    assert b"uploaded under duress" not in fresh.get("/").data


def test_the_review_shows_no_code_number(app, alice):
    """A level reviewing a deeper admin session's window sees its invites
    without their numbers, as the log shows them."""
    at_level_one(app, alice)
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, action, outcome, detail, level)"
            " VALUES (?, 'invite', 'ok', 'code 7, 5 people, 7 days', 1)", (alice_id(app, alice),)
        )
        db.commit()
    real, _ = log_in(app, alice, PASSWORD)
    page = real.get("/auth/review").data
    assert b"a code, 5 people, 7 days" in page and not re.search(rb"code \d", page)


def test_a_copy_that_fails_its_checks_is_reported(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    with open(stored_path(app, old), "r+b") as fp:
        fp.seek(20)
        fp.write(b"\0" * 8)
    real, _ = log_in(app, alice, PASSWORD)
    r = review_action(real, "copy", [old])
    assert b"Saved a private copy of 0 files." in r.data
    assert b"Not copied: menu.txt: Verification failed: the stored file was modified." in r.data
    # it stays in the list, to restore or let go
    assert b"menu.txt" in real.get("/auth/review").data.split(b"Deleted</h2>")[1]


def test_the_review_restores_deletes_and_brings_back(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, _ = log_in(app, alice, PASSWORD)
    assert b"Restored 1 file." in review_action(real, "restore", [old]).data
    assert download(real, old).data == MENU
    assert b"Deleted 1 file." in review_action(real, "delete", [planted]).data
    assert real.get(planted).status_code == 404
    assert b"Moved 1 file." in review_action(real, "move", [arrived]).data
    # moved to the real vault: the duress session no longer has it
    assert b"figures.txt" in shared_with_me(real)
    assert forced.get(arrived).status_code == 403


def test_review_actions_ask_for_the_password(app, alice, bob):
    forced, old, planted, arrived = a_duress_visit(app, alice, bob)
    real, _ = log_in(app, alice, PASSWORD)
    r = review_action(real, "delete", [planted], "a guess")
    assert b"Wrong password" in r.data
    assert download(forced, planted).status_code == 200


def test_a_level_one_login_gets_the_review_of_level_two(app, alice, bob):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    deeper, _ = log_in(app, alice, DEEPER)
    new_file(deeper, b"From level two.\n", "deep.txt")
    again, r = log_in(app, alice, DURESS)
    assert r.headers["Location"] == "/auth/review"
    assert b"deep.txt" in again.get("/auth/review").data


def test_with_two_factor_the_review_follows_the_code(app, alice, bob, monkeypatch):
    secret = turn_on(alice)
    set_duress(alice)
    tick(monkeypatch, 30)
    forced, _ = log_in(app, alice, DURESS)
    forced.post("/auth/login/code", data={"code": code(secret)})
    new_file(forced, MENU, "menu.txt")
    tick(monkeypatch, 60)
    real, r = log_in(app, alice, PASSWORD)
    # the password alone closes no window
    assert windows(app, alice) == opened(1)
    r = real.post("/auth/login/code", data={"code": code(secret)})
    assert r.headers["Location"] == "/auth/review"


def test_removing_the_duress_password_ends_every_one_below(app, alice):
    # a coercer at level 1 set a level 2 password, which the real user
    # cannot see: removing the duress password must end that one too
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    for password in (DURESS, DEEPER):
        _, r = log_in(app, alice, password)
        assert b"Incorrect username or password." in r.data


def test_a_new_duress_password_ends_the_one_below_it(app, alice):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    set_duress(alice, duress="lantern-copper-harbor-63")
    _, r = log_in(app, alice, DEEPER)
    assert b"Incorrect username or password." in r.data
    _, r = log_in(app, alice, "lantern-copper-harbor-63")
    assert r.headers["Location"] == "/"


def test_removing_the_duress_password_ends_its_sessions(app, alice):
    forced = at_level_one(app, alice)
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    # logged out, as sessions are: never "wrong password" for the one it
    # logged in with
    assert forced.get("/").headers["Location"] == "/auth/login"
    assert alice.get("/").status_code == 200


def test_a_new_duress_password_ends_the_sessions_of_the_old_one(app, alice):
    forced = at_level_one(app, alice)
    set_duress(forced, duress=DEEPER)
    deeper, _ = log_in(app, alice, DEEPER)
    set_duress(forced, duress="lantern-copper-harbor-63")
    assert deeper.get("/").headers["Location"] == "/auth/login"
    assert forced.get("/").status_code == 200
    set_duress(alice, duress="orchard-window-copper-58")
    assert forced.get("/").headers["Location"] == "/auth/login"
    assert alice.get("/").status_code == 200


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


def test_a_wipe_leaves_the_senders_page_as_it_was(app, alice, bob):
    """Design revision 2, A3: a wipe takes the account's incoming shares off
    its list, as a dismiss does, rather than ending them, so a sender sees
    nothing change at the moment of the wipe."""
    received = new_file(bob, name="figures.txt")
    share(bob, received, alice.handle)
    set_duress(alice, "wipe")
    bob.get(received)  # past the "Shared with" message
    before = normalized(bob.get(received).data, bob.handle)
    log_in(app, alice, DURESS)
    assert b"figures.txt" not in shared_with_me(alice)
    assert normalized(bob.get(received).data, bob.handle) == before


def test_a_level_two_wipe_keeps_received_files_for_the_review(app, alice, bob):
    forced = at_level_one(app, alice)
    received = new_file(bob, name="figures.txt")
    share(bob, received, alice.handle)
    assert b"figures.txt" in shared_with_me(forced)
    set_duress(forced, "wipe", duress=DEEPER)
    bob.get(received)  # past the "Shared with" message
    before = normalized(bob.get(received).data, bob.handle)
    log_in(app, alice, DEEPER)
    assert forced.get(received).status_code == 403
    assert normalized(bob.get(received).data, bob.handle) == before
    # armed at level 1, the wipe is soft: the review can put it back
    real, _ = log_in(app, alice, PASSWORD)
    assert b"figures.txt" in real.get("/auth/review").data
    assert b"Put back 1 file." in review_action(real, "put-back", [received]).data
    assert download(real, received).status_code == 200


def test_a_level_two_wipe_leaves_level_zero_intact(app, alice):
    real = new_file(alice)
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    set_duress(forced, "wipe", duress=DEEPER)
    log_in(app, alice, DEEPER)
    assert alice.get(menu).status_code == 404
    # armed at level 1, the wipe is soft: kept for the real owner
    with app.app_context():
        assert get_db().execute("SELECT trashed_at FROM files WHERE filename = 'menu.txt'"
                                ).fetchone()[0] is not None
    assert download(alice, real).data == CONTRACT
    after = new_file(alice, name="after.txt")
    assert f"Signature valid, signed by {alice.handle}.".encode() in alice.get(after).data


def test_a_level_two_wipe_can_be_undone_from_the_review(app, alice):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    set_duress(forced, "wipe", duress=DEEPER)
    log_in(app, alice, DEEPER)
    real, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    assert b"menu.txt" in real.get("/auth/review").data
    assert b"Restored 1 file." in review_action(real, "restore", [menu]).data
    assert download(real, menu).data == MENU


def test_every_account_has_every_level_in_one_shape(app, alice, bob):
    set_duress(alice, "wipe")
    with app.app_context():
        db = get_db()
        creds = db.execute(
            "SELECT user_id, length(verifier) AS verifier, length(lock) AS lock FROM credentials"
        ).fetchall()
        salts = {r[0] for r in db.execute("SELECT length(kdf_salt) FROM users")}
        keys = db.execute(
            "SELECT level, length(public_key) AS public, link IS NULL AS top FROM level_keys"
        ).fetchall()
        policies = {len(r[0]) for r in db.execute("SELECT duress_policy FROM users")}
    # a verifier and a lock per row, all of one length, and a salt per
    # account: level 0's row, then two for every level below it, the
    # password in use and the next one, and two for the one saved at the
    # last level, which opens nothing
    assert levels.ROWS == 1 + 2 * levels.LEVELS
    assert len(creds) == 2 * levels.ROWS
    assert {(r["verifier"], r["lock"]) for r in creds} == {(32, 60)}
    assert salts == {16}
    # and a key pair for each level, and one below the last for its cover
    # files, every one but level 0's linked from the one above
    pairs = [(level, 32, level == 0) for level in range(levels.KEY_LEVELS) for _ in range(2)]
    assert sorted(tuple(k) for k in keys) == pairs
    assert len(policies) == 1


def runs_of(monkeypatch):
    """The Argon2 runs over each password typed, from now on."""
    calls = []
    real = levels.derive_master
    monkeypatch.setattr(levels, "derive_master", lambda p, s: calls.append(s) or real(p, s))
    return calls


def test_requests_make_the_same_key_operations_at_every_level(app, monkeypatch):
    """Design revision 2, B2: unlocking always makes as many link operations,
    the real ones down from the session's level and the rest on a spare pair,
    so a request at level 0 and one at the last level do the same work."""
    a, b = logged_in(app, "alice"), logged_in(app, "alice")
    last = descend(app, a, levels.LEVELS - 1)
    calls = []
    real = levels.follow_link
    monkeypatch.setattr(levels, "follow_link", lambda *args: calls.append(1) or real(*args))
    counts = []
    for client in (last, b):
        url = new_file(client, MENU, "menu.txt")
        before = len(calls)
        download(client, url)
        counts.append(len(calls) - before)
    assert counts[0] == counts[1] == levels.KEY_LEVELS - 1


def test_the_schema_holds_every_level():
    schema = (Path(__file__).parent.parent / "app" / "schema.sql").read_text()
    bounds = {int(n) for n in re.findall(r"CHECK \(level BETWEEN 0 AND (\d+)\)", schema)}
    assert bounds == {levels.LEVELS - 1, levels.KEY_LEVELS - 1}


def test_login_costs_the_same_at_every_level(app, alice, monkeypatch):
    """Design revision 2, B1: one Argon2 run per login, whatever the password
    opens, at any number of levels, and for a username that does not exist."""
    calls = runs_of(monkeypatch)
    set_duress(alice)
    for username, password in (
        (alice.handle, PASSWORD),
        (alice.handle, DURESS),
        (alice.handle, "a guess"),
        ("ghost#000000", PASSWORD),
    ):
        before, written = len(calls), len(rows(app))
        app.test_client().post("/auth/login", data={"username": username, "password": password})
        assert len(calls) - before == 1
        assert len(rows(app)) - written == 1


def test_each_password_typed_costs_one_argon2_run(app, alice, bob, monkeypatch):
    """Design revision 2, B1: every key and check of a password comes from
    one Argon2 run over it, so an action costs one run for each password
    typed in its form."""
    url = new_file(alice)
    calls = runs_of(monkeypatch)

    def runs(action):
        before = len(calls)
        action()
        return len(calls) - before

    assert runs(lambda: new_file(alice, MENU, "menu.txt")) == 1
    assert runs(lambda: download(alice, url)) == 1
    assert runs(lambda: share(alice, url, bob.handle)) == 1
    # a new password as well as one's own: two
    assert runs(lambda: set_duress(alice)) == 2
    assert runs(lambda: change_password(alice, "orchard-window-copper-58")) == 2
    assert runs(lambda: delete(alice, url, password="orchard-window-copper-58")) == 1


def test_login_rows_are_the_same_with_two_factor_at_every_level(app, alice, monkeypatch):
    calls = runs_of(monkeypatch)
    turn_on(alice)
    set_duress(alice)
    for password in (PASSWORD, DURESS):
        before, written = len(calls), len(rows(app))
        r = app.test_client().post("/auth/login", data={"username": alice.handle, "password": password})
        assert r.headers["Location"] == "/auth/login/code"
        assert len(calls) - before == 1
        assert [row[:2] for row in rows(app)[written:]] == [("login", "code asked")]


def change_password(client, new, password=PASSWORD):
    data = {"password": password, "new_password": new}
    return client.post("/auth/password", data=data, follow_redirects=True)


def counted(monkeypatch):
    """Count the Argon2 calls and the SQL statements from now on."""
    argon2, statements = [], []

    class Slots:
        def __enter__(self):
            argon2.append(1)

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(passwords, "_slots", Slots())
    real_connect = sqlcipher.connect

    def connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(sqlcipher, "connect", connect)
    return argon2, statements


def test_requests_do_the_same_work_at_every_level(app, monkeypatch):
    """Section 13 and design revision 2, B2: requests at level 0 and at the
    last level must not be told apart by their timing. Deterministic
    stand-ins: the same number of Argon2 calls, which are what take time,
    of key operations, and of SQL statements."""
    a, b, carol = logged_in(app, "alice"), logged_in(app, "alice"), logged_in(app, "carol")
    last = descend(app, a, levels.LEVELS - 1)
    argon2, statements = counted(monkeypatch)
    keys = []
    for name in ("follow_link", "wrap_file_key", "unwrap_file_key", "lock_key", "unlock_key"):
        def counting(*args, real=getattr(levels, name), **kwargs):
            keys.append(1)
            return real(*args, **kwargs)

        monkeypatch.setattr(levels, name, counting)

    def work(action):
        argon2.clear()
        keys.clear()
        statements.clear()
        action()
        return len(argon2), len(keys), len(statements)

    url_a, url_b = [], []
    for one, two, uses_keys in (
        (lambda: url_a.append(new_file(last, MENU, "menu.txt")),
         lambda: url_b.append(new_file(b, MENU, "menu.txt")), True),
        (lambda: last.get("/"), lambda: b.get("/"), False),
        (lambda: download(last, url_a[0]), lambda: download(b, url_b[0]), True),
        (lambda: share(last, url_a[0], carol.handle), lambda: share(b, url_b[0], carol.handle),
         True),
    ):
        first, second = work(one), work(two)
        assert first == second and first[2] > 0 and (first[1] > 0) == uses_keys
    # an upload and a download each take one Argon2 call, at either level
    assert work(lambda: download(last, url_a[0]))[0] == 1
    # and so does every page that asks for the password, with the same key
    # operations and statements: a test of the new password against duress
    # passwords, saving one, and removing them
    new = "orchard-window-copper-58"
    answers = []

    def done(r):
        answers.append(r.data)

    for one, two in (
        (lambda: done(change_password(last, new, password=last.password)),
         lambda: done(change_password(b, new))),
        (lambda: done(set_duress(last, password=new, duress=DEEPER)),
         lambda: done(set_duress(b, password=new, duress=DEEPER))),
        (lambda: done(last.post("/auth/duress/remove", data={"password": new},
                                follow_redirects=True)),
         lambda: done(b.post("/auth/duress/remove", data={"password": new},
                             follow_redirects=True))),
    ):
        first, second = work(one), work(two)
        assert first == second and first[0] > 0
    for page, shown in zip(answers[::2], (b"Password changed.", b"Duress password saved.",
                                          b"Duress password removed")):
        assert shown in page


def test_after_a_wipe_nothing_opens_level_zero(app, alice, bob):
    """Section 13: after a wipe, no level 0 file key can be recovered from
    the database as it is, with the real password either."""
    real = new_file(alice)
    received = new_file(bob, name="figures.txt")
    share(bob, received, alice.handle)
    set_duress(alice, "wipe")
    log_in(app, alice, DURESS)
    uid = alice_id(app, alice)
    with app.app_context():
        copies = get_db().execute(
            "SELECT file_id, level FROM file_keys WHERE user_id = ?", (uid,)
        ).fetchall()
    # the real password still opens level 0's key, but no copy is left for
    # it to open, and the stored file is gone
    assert private_key(app, alice.handle) is not None
    assert [c for c in copies if c["level"] == 0] == []
    assert {c["file_id"] for c in copies} & {file_id(real), file_id(received)} == set()
    assert gone(app, real)


# Section 5: what an accomplice can try, with their own account and files
# shared with or by the user before or during the coercion


def test_probe_a_file_shared_last_week_is_not_listed(app, alice, bob):
    url = new_file(bob, name="figures.txt")
    share(bob, url, alice.handle)
    forced = at_level_one(app, alice)
    # as if she had dismissed it
    assert b"figures.txt" not in shared_with_me(forced)
    assert forced.get(url).status_code == 403


def test_probe_sharing_it_again_brings_it_in(app, alice, bob):
    url = new_file(bob, name="figures.txt")
    share(bob, url, alice.handle)
    forced = at_level_one(app, alice)
    share(bob, url, alice.handle)
    assert b"figures.txt" in shared_with_me(forced)
    assert download(forced, url).status_code == 200


def test_probe_sharing_one_of_her_files_works(app, alice, bob):
    forced = at_level_one(app, alice)
    menu = new_file(forced, MENU, "menu.txt")
    r = share(forced, menu, bob.handle, follow_redirects=True)
    assert f"Shared with {bob.handle}.".encode() in r.data
    assert download(bob, menu).data == MENU


def test_probe_uploading_their_file_and_sharing_it_back_works(app, alice, bob):
    forced = at_level_one(app, alice)
    url = new_file(forced, b"Their figures.\n", "their.txt")
    share(forced, url, bob.handle)
    assert download(bob, url).data == b"Their figures.\n"


def test_probe_the_certificate_serial_is_the_same(app, alice):
    new_file(alice)
    forced = at_level_one(app, alice)
    new_file(forced, MENU, "menu.txt")
    with app.app_context():
        serials = [r[0] for r in get_db().execute(
            "SELECT c.serial FROM files f JOIN certificates c ON c.id = f.cert_id ORDER BY f.rowid"
        )]
    assert len(serials) == 2 and serials[0] == serials[1]


def test_probe_a_file_she_shared_before_stays_with_them(app, alice, bob):
    """Section 9, limit 3: nothing hides a file the accomplice already holds.
    The share form says so, at every level."""
    real = new_file(alice)
    share(alice, real, bob.handle)
    forced = at_level_one(app, alice)
    assert b"contract.txt" not in forced.get("/").data
    assert download(bob, real).data == CONTRACT
    assert b"they can still tell it exists" in alice.get(real).data


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


def test_the_two_factor_page_is_the_same_at_every_level(app, monkeypatch):
    """Design revision 2, A1: two-factor login is kept per level, and its
    page answers the same at each: off, turned on, new codes, turned off."""
    a, b = logged_in(app, "alice"), logged_in(app, "alice")
    forced = at_level_one(app, a)
    pages = []
    for client, password in ((forced, DURESS), (b, PASSWORD)):
        seen = [client.get("/auth/totp").data]
        secret = re.search(rb"<code>([A-Z2-7]{32})</code>", seen[0]).group(1).decode()
        on = client.post("/auth/totp", data={"password": password, "code": code(secret)})
        seen.append(on.data)
        seen.append(client.get("/auth/totp").data)
        seen.append(client.post("/auth/totp/recovery",
                                data={"password": password, "code": code(secret, 1)}).data)
        tick(monkeypatch, 30)
        seen.append(client.post("/auth/totp/disable", follow_redirects=True,
                                data={"password": password, "code": code(secret, 1)}).data)
        tick(monkeypatch, 30)
        pages.append([normalized(re.sub(RECOVERY_SHAPE, b"CODE", page), client.handle)
                      for page in seen])
    assert pages[0] == pages[1]
    assert b"Two-factor login is off." in pages[1][-1].encode()


def test_a_level_one_vault_looks_like_a_level_zero_one(app):
    """Section 13: for an account whose level 1 holds the same files as
    another account's level 0, every page and every answer is the same,
    apart from ids, tokens and times."""
    a, b = logged_in(app, "alice"), logged_in(app, "alice")
    carol, dave = logged_in(app, "carol"), logged_in(app, "dave")
    for client in (a, b):
        make_admin(app, client)
    # a cover vault is filled from level 0, as the real user does: an own
    # file and a received one moved down; the other account keeps the same
    # two at level 0
    notes = b"Notes from the meeting.\n"
    received = new_file(dave, b"Quarterly figures.\n", "figures.txt")
    share(dave, received, a.handle)
    share(dave, received, b.handle)
    move(a, [new_file(a, notes, "notes.txt"), received], "down")
    new_file(b, notes, "notes.txt")
    forced = at_level_one(app, a)
    names = (("contract.txt", CONTRACT), ("menu.txt", MENU))
    files_a = [new_file(forced, data, name) for name, data in names]
    files_b = [new_file(b, data, name) for name, data in names]
    pages = ["/", "/upload", "/auth/totp", "/auth/duress", "/auth/password", received]
    for url in pages:
        assert normalized(forced.get(url).data, a.handle) == normalized(b.get(url).data, b.handle), url
    # the admin pages answer the same; their rows are each account's own
    for url in ("/admin/log", "/admin/invites", "/admin/log?problems=1"):
        assert forced.get(url).status_code == b.get(url).status_code == 200
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
    # a delete is soft at level 1 and for good at level 0, and looks the same
    gone_a = delete(forced, files_a[1], follow_redirects=True)
    gone_b = delete(b, files_b[1], follow_redirects=True)
    assert normalized(gone_a.data, a.handle) == normalized(gone_b.data, b.handle)


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
        salt = db.execute("SELECT kdf_salt FROM users WHERE id = ?", (uid,)).fetchone()[0]
        links = {r["level"]: r["link"] for r in db.execute(
            "SELECT level, link FROM level_keys WHERE user_id = ?", (uid,))}
        copies = db.execute(
            "SELECT file_id, wrapped_key, level FROM file_keys WHERE user_id = ?", (uid,)
        ).fetchall()

    # everything the duress password opens: the one credential it matches...
    master, opened = derive_master(DURESS, salt), []
    for cred in creds:
        if verifier(master, uid, cred["id"]) == cred["verifier"]:
            for level in range(levels.LEVELS):
                try:
                    opened.append(unlock_key(
                        cred["lock"], lock_secret(master, uid, level), f"lock|{uid}|{level}".encode()))
                except InvalidTag:
                    pass
    # ...and whatever its keys open in turn
    for _ in range(levels.KEY_LEVELS):
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
    # levels 1 to 7, and the key of the last level's cover files
    assert len(opened) == levels.KEY_LEVELS - 1

    level_zero = [c for c in copies if c["level"] == 0]
    assert {c["file_id"] for c in level_zero} == {file_id(real), file_id(theirs)}
    for key in opened:
        for c in level_zero:
            for level in range(levels.KEY_LEVELS):
                with pytest.raises(InvalidTag):
                    unwrap_file_key(key, c["wrapped_key"], c["file_id"], uid, level)
        # nor the lock of level 0, nor the link from 0 down to 1
        with pytest.raises(InvalidTag):
            follow_link(key, links[1], f"link|{uid}|1".encode())
    real_master = derive_master(PASSWORD, salt)
    zero = [c for c in creds if verifier(real_master, uid, c["id"]) == c["verifier"]][0]
    with pytest.raises(InvalidTag):
        unlock_key(zero["lock"], lock_secret(master, uid, 0), f"lock|{uid}|0".encode())


# where a session's level may be read (section 11): the levels themselves,
# the session they are loaded into, the level an audit row is written at,
# and the invite codes each level sees
LEVEL_READERS = {"levels.py", "auth.py", "audit.py", "invites.py"}


def test_the_level_is_read_in_the_named_places_only():
    app_dir = Path(__file__).parent.parent / "app"
    for path in app_dir.glob("*.py"):
        text = path.read_text()
        assert "g.duress" not in text, path.name
        # other modules call into app/levels.py, but never see a level,
        # under any name (session_level, trashed_level...)
        if path.name not in LEVEL_READERS:
            assert not re.search(r"level\b", text, re.I), path.name
    # no page is ever given the level: it looks the same at every one
    for path in (app_dir / "templates").rglob("*.html"):
        assert not re.search(r"level\b", path.read_text(), re.I), path.name
