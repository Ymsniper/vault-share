import json
import os
import re
import stat

import pytest
from sqlcipher3 import dbapi2 as sqlcipher

from app import create_app
from app.db import get_db
from app.levels import COVER, open_policy
from app.keyring import USB_KEY_FILE, connect
from app.totp import unseal
from app.unlock import unlock_from_terminal, wants_passphrase

from .samples import ARCHIVES
from .test_duress import set_duress
from .test_files import CONTRACT, download, file_id, new_file, share
from .test_totp import code, turn_on

PASSPHRASE = "amber-lantern-quarry-58"
CODE_RE = re.compile(r"\b(?:[A-Z2-7]{4}-){12}[A-Z2-7]{4}\b")


@pytest.fixture
def stick(app):
    path = os.path.join(app.config["USB_MOUNT_ROOTS"][0], "KEYSTICK")
    os.makedirs(path)
    return path


def keys(app, *args, input=None):
    return app.test_cli_runner().invoke(args=["keys", *args], input=input)


def keyring(app):
    return app.extensions["keyring"]


def pulled_out(stick):
    # outside the folder where sticks are mounted, as when the stick is pulled
    return os.path.join(os.path.dirname(os.path.dirname(stick)), "pulled-out")


def unplug(stick):
    os.rename(stick, pulled_out(stick))


def plug(stick):
    os.rename(pulled_out(stick), stick)


def restart(app, **config):
    """The same instance folder opened by a fresh process."""
    return create_app({**{k: v for k, v in app.config.items() if k.isupper()}, **config})


def test_by_default_only_the_machine_key_is_used(app):
    out = keys(app, "status").output
    assert "USB stick: not used" in out and "Passphrase: not used" in out
    assert not keyring(app).locked


def test_adding_a_stick_keeps_everything_readable(app, alice, bob, stick):
    url = new_file(alice)
    share(alice, url, bob.handle)
    # an archive's record carries its "not checked" mark in the HMAC too
    archive = new_file(alice, ARCHIVES["bundle.zip"], name="bundle.zip")
    secret = turn_on(alice)
    set_duress(alice)

    r = keys(app, "add-usb", stick)
    assert r.exit_code == 0, r.output
    assert CODE_RE.search(r.output)
    key_file = os.path.join(stick, USB_KEY_FILE)
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert "USB stick: required" in keys(app, "status").output

    # files, shares, two-factor secrets and duress settings all moved over
    assert b"Record verified" in alice.get(url).data
    assert b"Record verified" in alice.get(archive).data
    assert download(bob, url).data == CONTRACT
    alice.post("/auth/logout")
    alice.post("/auth/login", data={"username": alice.handle, "password": "contract-2026"})
    assert alice.post("/auth/login/code", data={"code": code(secret, 1)}).headers["Location"] == "/"
    with app.app_context():
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (alice.handle,)
        ).fetchone()
        assert unseal(user["id"], user["totp_secret"]) == secret
        # the sealed levels open under the new master key
        assert open_policy(user).modes[1] == COVER

    # the machine key alone no longer opens the database
    with pytest.raises(sqlcipher.DatabaseError):
        connect(app.config["DATABASE"], keyring(app).machine).execute("SELECT * FROM users").fetchall()


def user_version(app):
    with app.app_context():
        return get_db().execute("PRAGMA user_version").fetchone()[0]


def test_a_key_change_keeps_the_database_version(app, stick):
    """Adding a stick or a passphrase copies the database under the new key;
    the copy keeps the version number the code checks it against."""
    before = user_version(app)
    assert before == 1
    assert keys(app, "add-usb", stick).exit_code == 0
    assert user_version(app) == before
    assert keys(app, "set-passphrase", input=f"{PASSPHRASE}\n{PASSPHRASE}\n").exit_code == 0
    assert user_version(app) == before


def test_pulling_the_stick_locks_the_app(app, alice, stick):
    url = new_file(alice)
    keys(app, "add-usb", stick)

    unplug(stick)
    keyring(app).poll(app)
    assert keyring(app).locked
    r = alice.get(url)
    assert r.status_code == 503 and b"This service is paused." in r.data
    assert b"USB" not in r.data and b"passphrase" not in r.data.lower()
    with app.app_context(), pytest.raises(Exception):
        get_db()

    plug(stick)
    keyring(app).poll(app)
    assert not keyring(app).locked
    # everyone was logged out when the stick went away
    assert alice.get(url).headers["Location"] == "/auth/login"
    alice.post("/auth/login", data={"username": alice.handle, "password": "contract-2026"})
    assert download(alice, url).data == CONTRACT


def test_another_stick_does_not_unlock(app, stick):
    keys(app, "add-usb", stick)
    with open(os.path.join(stick, USB_KEY_FILE), "wb") as f:
        f.write(os.urandom(32))
    keyring(app).poll(app)
    assert keyring(app).locked


def test_the_recovery_code_replaces_a_lost_stick(app, alice, stick):
    url = new_file(alice)
    recovery = CODE_RE.search(keys(app, "add-usb", stick).output).group(0)
    unplug(stick)
    keyring(app).poll(app)

    r = keys(app, "remove-usb", input=recovery + "\n")
    assert r.exit_code == 0, r.output
    assert not keyring(app).locked
    assert "USB stick: not used" in keys(app, "status").output
    alice.post("/auth/login", data={"username": alice.handle, "password": "contract-2026"})
    assert download(alice, url).data == CONTRACT


def test_a_passphrase_is_asked_after_every_start(app, alice):
    url = new_file(alice)
    r = keys(app, "set-passphrase", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    assert r.exit_code == 0, r.output

    started = restart(app)
    assert started.extensions["keyring"].locked and wants_passphrase(started.extensions["keyring"])
    client = started.test_client()
    page = client.get("/")
    assert page.status_code == 503 and b'name="passphrase"' not in page.data

    # what vault-share serve does on its terminal
    typed, said = iter(["not the passphrase", PASSPHRASE]), []
    assert unlock_from_terminal(started, ask=lambda: next(typed), say=said.append)
    assert [str(e) for e in said] == ["Wrong passphrase, or not the right USB stick."]
    assert not started.extensions["keyring"].locked
    client.post("/auth/login", data={"username": alice.handle, "password": "contract-2026"})
    assert download(client, url).data == CONTRACT


def test_unlocking_stops_when_the_terminal_input_ends(app):
    keys(app, "set-passphrase", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    started = restart(app)

    def nothing_more():
        raise EOFError

    assert not unlock_from_terminal(started, ask=nothing_more)
    assert started.extensions["keyring"].locked


def test_unlocking_before_there_is_a_database(app, tmp_path):
    keys(app, "set-passphrase", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    # a passphrase can be set before init-db: the unlock is not logged then,
    # and no empty database appears
    fresh = restart(app, DATABASE=str(tmp_path / "not-made-yet.sqlite3"))
    assert unlock_from_terminal(fresh, ask=lambda: PASSPHRASE)
    assert not fresh.extensions["keyring"].locked
    assert not (tmp_path / "not-made-yet.sqlite3").exists()


@pytest.mark.parametrize("behind_proxy", [False, True])
def test_there_is_no_unlock_page(app, behind_proxy):
    keys(app, "set-passphrase", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    started = restart(app, BEHIND_PROXY=behind_proxy)
    local = started.test_client()
    remote = started.test_client()
    remote.environ_base["REMOTE_ADDR"] = "203.0.113.9"
    # what a visitor through a proxy on this machine looks like
    proxied = started.test_client()
    proxied.environ_base["HTTP_X_FORWARDED_FOR"] = "203.0.113.9"
    # while locked, every visitor only learns that the service is paused,
    # and nobody can try a passphrase over the network
    for visitor in (local, remote, proxied):
        r = visitor.post("/unlock", data={"passphrase": PASSPHRASE})
        assert r.status_code == 503 and b"passphrase" not in r.data.lower()
    assert started.extensions["keyring"].locked

    unlock_from_terminal(started, ask=lambda: PASSPHRASE)
    for visitor in (local, remote, proxied):
        assert visitor.get("/unlock").status_code == 404


def test_a_weak_passphrase_is_refused(app):
    r = keys(app, "set-passphrase", input="short\nshort\n")
    assert r.exit_code != 0 and "at least 12 characters" in r.output
    r = keys(app, "set-passphrase", input="password1234\npassword1234\n")
    assert r.exit_code != 0 and "too easy to guess" in r.output


def test_removing_both_factors_brings_back_the_machine_key(app, alice, stick):
    url = new_file(alice)
    keys(app, "add-usb", stick)
    keys(app, "set-passphrase", input=f"{PASSPHRASE}\n{PASSPHRASE}\n")
    keys(app, "remove-passphrase", input=f"{PASSPHRASE}\n")
    assert keys(app, "remove-usb").exit_code == 0
    assert not os.path.exists(os.path.join(app.config["SECRETS_DIR"], "keyring.json"))
    # the database opens with the machine key alone again
    connect(app.config["DATABASE"], keyring(app).machine).execute("SELECT * FROM users").fetchall()
    assert download(alice, url).data == CONTRACT


def test_a_tampered_record_stops_the_change(app, alice, stick):
    url = new_file(alice)
    with app.app_context():
        db = get_db()
        db.execute("UPDATE files SET size = 1 WHERE id = ?", (file_id(url),))
        db.commit()

    r = keys(app, "add-usb", stick)
    assert r.exit_code != 0 and "nothing was changed" in r.output
    assert not os.path.exists(os.path.join(stick, USB_KEY_FILE))
    assert "USB stick: not used" in keys(app, "status").output
    config_path = os.path.join(app.config["SECRETS_DIR"], "keyring.json")
    assert not os.path.exists(config_path) or json.load(open(config_path)) == {}
