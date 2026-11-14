"""The security and privacy page: public, served while the service is paused
too, the same for every session, and true to the server's settings."""
import re

from app.db import get_db

from .conftest import logged_in
from .test_keyring import keyring, keys, stick, unplug  # noqa: F401 (stick is a fixture)
from .test_levels import at_level_one, normalized

TITLE = b"Security and privacy"


def test_everyone_can_read_it(client, alice):
    for visitor in (client, alice):
        r = visitor.get("/security")
        assert r.status_code == 200 and TITLE in r.data


def test_it_is_served_while_the_service_is_paused(app, client, alice, stick):
    keys(app, "add-usb", stick)
    unplug(stick)
    keyring(app).poll(app)
    assert keyring(app).locked
    assert alice.get("/").status_code == 503
    for visitor in (client, alice):
        r = visitor.get("/security")
        assert r.status_code == 200 and TITLE in r.data


def test_it_is_served_with_a_database_of_another_version(app, client, alice):
    with app.app_context():
        db = get_db()
        db.execute("PRAGMA user_version = 99")
        db.commit()
    assert client.get("/auth/login").status_code == 503
    for visitor in (client, alice):
        r = visitor.get("/security")
        assert r.status_code == 200 and TITLE in r.data


def test_it_is_the_same_for_every_session(app, alice, bob):
    forced = at_level_one(app, alice)
    assert normalized(forced.get("/security").data, alice.handle) == \
        normalized(bob.get("/security").data, bob.handle)


def test_it_states_this_servers_settings(app, client):
    app.config["DURESS_DELAY"] = 48 * 3600
    page = client.get("/security").data
    assert f"deleted after {app.config['AUDIT_LOG_DAYS']} days".encode() in page
    assert b"starts to work 48 hours after it is saved" in page
    # and, like every page, never says which password opened the session
    assert not re.search(rb"\blevels?\b", page, re.I)


def test_it_names_every_cookie_the_server_sets(app, client):
    """The page lists the cookies; a login sets only those."""
    page = client.get("/security").data
    alice = logged_in(app, "alice")
    names = {c.key for c in alice._cookies.values()}
    assert names <= {"sid", "session", "device"}
    for name in names:
        assert f"<code>{name}</code>".encode() in page
