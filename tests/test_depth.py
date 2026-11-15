"""A secret number of levels per account: the server draws it at
registration, evenly from its range, keeps it sealed and shows it nowhere.
Every account has rows and keys for the largest number and does the same
work at every level, so the end of a chain is found only by reaching it,
and counting nested duress passwords inside the range tells a coercer
nothing."""
import pytest

from app import levels, server_settings
from app.db import get_db

from .conftest import PASSWORD, logged_in
from .test_duress import DURESS, log_in, set_duress
from .test_files import download, new_file
from .test_levels import (
    MENU,
    change_password,
    counted,
    depth_of,
    descend,
    normalized,
    review_done,
)

WRONG = b"Incorrect username or password."
SAVED = "harbor-lantern-quiet-41"


def account(app, name, depth):
    """A new account the server drew depth levels for."""
    app.config["LEVELS_RANGE"] = (depth, depth)
    return logged_in(app, name)


def key_operations(monkeypatch):
    """Count the key operations from now on, by name."""
    calls = []
    for name in ("follow_link", "wrap_file_key", "unwrap_file_key", "lock_key", "unlock_key"):
        def counting(*args, real=getattr(levels, name), name=name, **kwargs):
            calls.append(name)
            return real(*args, **kwargs)

        monkeypatch.setattr(levels, name, counting)
    return calls


def test_each_account_draws_its_own_number_evenly_from_the_range(app, monkeypatch):
    app.config["LEVELS_RANGE"] = (16, 47)
    asked, answers = [], iter([0, 31, 13])

    def randbelow(n):
        asked.append(n)
        return next(answers)

    monkeypatch.setattr(levels, "randbelow", randbelow)
    clients = [logged_in(app, name) for name in ("alice", "bob", "carol")]
    # one even draw for every account, both edges of the range included
    assert asked == [32, 32, 32]
    assert [depth_of(app, c) for c in clients] == [16, 47, 29]


def test_a_save_past_the_end_answers_and_works_as_one_that_opens(app, monkeypatch):
    """At level 2, the last level of one account and the middle of another,
    saving a duress password gives the same page for the same work. Only a
    login with it, once it works, tells the two apart."""
    short, long = account(app, "alice", 3), account(app, "bob", 6)
    sessions = [descend(app, c, 2) for c in (short, long)]
    argon2, statements = counted(monkeypatch)
    keys = key_operations(monkeypatch)
    answers = []
    for client, session in zip((short, long), sessions):
        argon2.clear()
        keys.clear()
        statements.clear()
        page = set_duress(session, duress=SAVED).data
        answers.append((normalized(page, client.handle), len(argon2), sorted(keys),
                        len(statements)))
    assert b"Duress password saved." in page
    assert answers[0] == answers[1]
    _, r = log_in(app, short, SAVED)
    assert WRONG in r.data
    _, r = log_in(app, long, SAVED)
    assert r.headers["Location"] == "/"


def test_requests_on_short_and_long_accounts_do_the_same_work(app, monkeypatch):
    short, long = account(app, "alice", 3), account(app, "bob", levels.LEVELS)
    sessions = [descend(app, c, 2) for c in (short, long)]
    argon2, statements = counted(monkeypatch)
    keys = key_operations(monkeypatch)

    def work(action):
        argon2.clear()
        keys.clear()
        statements.clear()
        action()
        return len(argon2), sorted(keys), len(statements)

    urls = []
    for one, two in (
        (lambda: urls.append(new_file(sessions[0], MENU, "menu.txt")),
         lambda: urls.append(new_file(sessions[1], MENU, "menu.txt"))),
        (lambda: sessions[0].get("/"), lambda: sessions[1].get("/")),
        (lambda: download(sessions[0], urls[0]), lambda: download(sessions[1], urls[1])),
    ):
        first, second = work(one), work(two)
        assert first == second and first[2] > 0


def test_every_account_has_the_same_rows_whatever_its_number(app):
    accounts = [account(app, "alice", 2), account(app, "bob", levels.LEVELS)]
    shapes = []
    with app.app_context():
        db = get_db()
        for client in accounts:
            user = db.execute(
                "SELECT id, duress_policy FROM users WHERE username = ?", (client.handle,)
            ).fetchone()
            counts = [db.execute(f"SELECT COUNT(*) FROM {table} WHERE user_id = ?",
                                 (user["id"],)).fetchone()[0]
                      for table in ("credentials", "level_keys", "two_factor")]
            shapes.append((*counts, len(user["duress_policy"])))
    assert shapes[0] == shapes[1]
    assert shapes[0][:3] == (levels.ROWS, levels.KEY_LEVELS, levels.LEVELS)


def test_the_largest_number_ends_at_the_last_row_there_is(app):
    top = account(app, "alice", levels.LEVELS)
    last = descend(app, top, levels.LEVELS - 1)
    assert b"Duress password saved." in set_duress(last, duress=SAVED).data
    _, r = log_in(app, top, SAVED)
    assert WRONG in r.data


def test_nothing_a_session_does_changes_the_number(app):
    alice = account(app, "alice", 5)
    set_duress(alice)
    assert depth_of(app, alice) == 5
    # the new password takes over at the login
    forced, _ = log_in(app, alice, DURESS)
    assert depth_of(app, alice) == 5
    change_password(forced, "orchard-window-copper-58", password=DURESS)
    assert depth_of(app, alice) == 5
    real, r = log_in(app, alice, PASSWORD)
    assert r.headers["Location"] == "/auth/review"
    assert b"Review done." in review_done(real, "restore").data
    alice.post("/auth/duress/remove", data={"password": PASSWORD})
    assert depth_of(app, alice) == 5


def test_the_range_is_a_server_setting_for_new_accounts(app, tmp_path):
    path = str(tmp_path / "server.toml")
    settings, trouble = server_settings.load(path)
    assert (settings["min_levels"], settings["max_levels"]) == (16, levels.LEVELS)
    assert trouble is None
    # a range of one number would be the ruler again
    for bad in ({"min_levels": 1}, {"max_levels": levels.LEVELS + 1},
                {"min_levels": 20, "max_levels": 20}, {"min_levels": 30, "max_levels": 20}):
        with pytest.raises(ValueError):
            server_settings.save(path, **bad)
    old = logged_in(app, "alice")
    server_settings.apply(app, server_settings.save(path, min_levels=4, max_levels=6))
    new = logged_in(app, "bob")
    # the accounts made before keep theirs
    assert depth_of(app, old) == 8 and 4 <= depth_of(app, new) <= 6


def test_the_command_changes_the_range(app):
    r = app.test_cli_runner().invoke(
        args=["server-settings", "--min-levels", "20", "--max-levels", "30"])
    assert "Saved: port 5000, uploads up to 10 MB, 20 to 30 levels per new account." in r.output
    with app.app_context():
        row = get_db().execute(
            "SELECT detail FROM audit_log WHERE action = 'settings'"
        ).fetchone()
    assert row["detail"] == "levels per new account 16 to 47, now 20 to 30"
