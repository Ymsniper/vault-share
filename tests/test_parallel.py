"""Requests sent at the same time must not slip past the limits together."""
import threading
import time

from app import auth, levels
from app.db import get_db
from security import passwords

from .conftest import register
from .test_files import download, new_file


def run_together(target, n, settled):
    """Start target in n threads and return them once settled() is true,
    or after 10 seconds."""
    threads = [threading.Thread(target=target) for _ in range(n)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + 10
    while not settled() and time.monotonic() < deadline:
        time.sleep(0.01)
    return threads


def test_parallel_wrong_passwords_stay_under_the_limit(app, monkeypatch):
    handle = register(app.test_client())
    release = threading.Event()
    reached = set()
    real_check = levels.check_password

    def slow_check(stored_hash, password):
        reached.add(threading.get_ident())
        release.wait(10)
        return real_check(stored_hash, password)

    monkeypatch.setattr(levels, "check_password", slow_check)
    answers = []

    def guess():
        r = app.test_client().post("/auth/login", data={"username": handle, "password": "a guess"})
        answers.append((r.status_code, r.data))

    threads = run_together(guess, 12, lambda: len(reached) == 5 and waiting() == 7)
    # five checks at once at most; the other seven wait for a place
    assert len(reached) == 5 and answers == []
    release.set()
    for t in threads:
        t.join()
    # the five failed, so the seven that waited were locked out without a check
    assert len(reached) == 5
    refused = [data for code, data in answers if code == 429]
    assert len(refused) == 7
    assert all(b"Too many failed attempts" in data for data in refused)
    with app.app_context():
        rows = [tuple(r) for r in get_db().execute("SELECT action, outcome FROM audit_log")]
    assert rows.count(("login", "failed")) == 5
    assert rows.count(("password", "locked")) == 1


def waiting():
    with auth._gate:
        return max(auth._waiting.values(), default=0)


def slow_unlock(monkeypatch, release, reached):
    real = levels.unlock

    def slow(*args):
        reached.add(threading.get_ident())
        release.wait(10)
        return real(*args)

    monkeypatch.setattr(levels, "unlock", slow)


def test_parallel_right_passwords_wait_for_a_place(app, alice, monkeypatch):
    url = new_file(alice)
    release, reached, answers = threading.Event(), set(), []
    slow_unlock(monkeypatch, release, reached)

    def fetch():
        answers.append(download(alice, url).status_code)

    # five run, eight wait their turn, and the rest are told to come back
    threads = run_together(fetch, 16, lambda: len(reached) == 5 and len(answers) == 3)
    assert answers == [429, 429, 429] and waiting() == 8
    release.set()
    for t in threads:
        t.join()
    assert sorted(answers) == [200] * 13 + [429] * 3


def test_a_wait_has_an_end(app, alice, monkeypatch):
    url = new_file(alice)
    release, reached, answers = threading.Event(), set(), []
    slow_unlock(monkeypatch, release, reached)
    monkeypatch.setattr(auth, "WAIT_SECONDS", 0.5)

    def fetch():
        answers.append(download(alice, url))

    threads = run_together(fetch, 6, lambda: len(answers) == 1)
    release.set()
    for t in threads:
        t.join()
    late = [r for r in answers if r.status_code == 429]
    assert len(late) == 1 and b"Too many attempts at once" in late[0].data


def test_every_password_check_counts_toward_sixty(app, alice):
    url = new_file(alice)
    # the upload was one check
    for _ in range(59):
        assert download(alice, url).status_code == 200
    r = download(alice, url)
    assert r.status_code == 429
    assert b"Too many password checks" in r.data
    with app.app_context():
        rows = get_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'password' AND outcome = 'locked'"
        ).fetchone()[0]
    assert rows == 1


def test_at_most_four_argon2_calls_run_at_once(monkeypatch):
    running = peak = 0
    lock = threading.Lock()

    class SlowHasher:
        def verify(self, stored_hash, password):
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.2)
            with lock:
                running -= 1
            return True

    monkeypatch.setattr(passwords, "_hasher", SlowHasher())
    threads = [
        threading.Thread(target=passwords.check_password, args=("hash", "password"))
        for _ in range(10)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert peak <= 4
