"""Requests sent at the same time must not slip past the limits together."""
import threading
import time

from app import auth
from app.db import get_db
from security import passwords

from .conftest import register


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
    real_check = auth.check_password

    def slow_check(stored_hash, password):
        reached.add(threading.get_ident())
        release.wait(10)
        return real_check(stored_hash, password)

    monkeypatch.setattr(auth, "check_password", slow_check)
    answers = []

    def guess():
        r = app.test_client().post("/auth/login", data={"username": handle, "password": "a guess"})
        answers.append((r.status_code, r.data))

    threads = run_together(guess, 12, lambda: len(reached) + len(answers) >= 12)
    release.set()
    for t in threads:
        t.join()
    # five checks at once at most; the others were turned away without one
    assert len(reached) == 5
    refused = [data for code, data in answers if code == 429]
    assert len(refused) == 7
    assert all(b"Too many attempts at once" in data for data in refused)
    with app.app_context():
        rows = [tuple(r) for r in get_db().execute("SELECT action, outcome FROM audit_log")]
    assert rows.count(("login", "failed")) == 5
    # nobody was locked out: they were only too many at the same time
    assert ("password", "locked") not in rows

    # the five failures are recorded now, so the next try is a real lock
    r = app.test_client().post("/auth/login", data={"username": handle, "password": "a guess"})
    assert r.status_code == 429
    assert b"Too many failed attempts" in r.data


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
