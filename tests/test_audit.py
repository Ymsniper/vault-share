import io

from app import create_app
from app.audit import network_of
from app.db import get_db

from .test_files import download, share


def log_rows(app):
    with app.app_context():
        return [
            tuple(r)
            for r in get_db().execute(
                "SELECT u.username, a.action, a.outcome, a.file_id FROM audit_log a"
                " LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id"
            )
        ]


def test_file_actions_are_logged(app, alice, bob):
    url = alice.post(
        "/upload",
        data={"file": (io.BytesIO(b"quarterly figures"), "q3.txt"), "password": "contract-2026"},
        content_type="multipart/form-data",
    ).headers["Location"]
    file_id = url.rsplit("/", 1)[-1]
    alice.get(url)
    share(alice, url, bob.handle)
    download(bob, url)
    alice.post(f"{url}/delete")

    rows = log_rows(app)
    for expected in (
        (alice.handle, "upload", "ok", file_id),
        (alice.handle, "verify", "ok", file_id),
        (alice.handle, "share", "ok", file_id),
        (bob.handle, "download", "ok", file_id),
        (alice.handle, "delete", "ok", file_id),
    ):
        assert expected in rows


def test_failed_login_is_not_blamed_on_the_current_user(app, alice):
    alice.post("/auth/login", data={"username": alice.handle, "password": "wrong"})
    assert log_rows(app)[-1] == (None, "login", "failed", None)


def test_log_never_contains_passwords(app, alice):
    alice.post("/auth/login", data={"username": alice.handle, "password": "wrong guess 123"})
    with app.app_context():
        rows = [str(tuple(r)) for r in get_db().execute("SELECT * FROM audit_log")]
    assert rows
    assert not any("contract-2026" in row or "wrong guess 123" in row for row in rows)


def test_audit_log_is_for_admins_only(app, alice):
    assert alice.get("/admin/log").status_code == 403
    assert (alice.handle, "read_log", "denied", None) in log_rows(app)

    r = app.test_cli_runner().invoke(args=["admin", "grant", alice.handle])
    assert f"{alice.handle} can now read the audit log." in r.output
    r = alice.get("/admin/log")
    assert r.status_code == 200
    assert b"read_log" in r.data


def test_grant_rejects_unknown_user(app):
    r = app.test_cli_runner().invoke(args=["admin", "grant", "nobody"])
    assert r.exit_code != 0
    assert "No user named nobody." in r.output


def test_addresses_are_cut_to_their_network():
    assert network_of("203.0.113.57") == "203.0.113.0/24"
    assert network_of("2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::/48"
    assert network_of("::ffff:198.51.100.7") == "198.51.100.0/24"
    assert network_of("not an address") is None


def test_log_keeps_networks_not_addresses(app, alice):
    with app.app_context():
        rows = get_db().execute("SELECT action, ip FROM audit_log").fetchall()
    assert {ip for action, ip in rows if action != "invite"} == {"127.0.0.0/24"}
    # alice's invite code was made at the server, which has no address
    assert {ip for action, ip in rows if action == "invite"} == {None}


def test_forwarded_address_counts_only_behind_a_proxy(app):
    proxied = create_app({**app.config, "BEHIND_PROXY": True})
    # a client may send its own X-Forwarded-For; the proxy adds the real one last
    forwarded = {"X-Forwarded-For": "198.51.100.7, 203.0.113.57"}
    for a in (proxied, app):
        a.test_client().post(
            "/auth/login", data={"username": "nobody", "password": "wrong"}, headers=forwarded
        )
    with app.app_context():
        ips = [r[0] for r in get_db().execute("SELECT ip FROM audit_log ORDER BY id")]
    assert ips == ["203.0.113.0/24", "127.0.0.0/24"]


def test_entries_older_than_90_days_are_deleted(app, alice):
    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (at, action, outcome) VALUES (datetime('now', '-91 days'), 'old', 'ok')"
        )
        db.execute(
            "INSERT INTO audit_log (at, action, outcome) VALUES (datetime('now', '-89 days'), 'recent', 'ok')"
        )
        db.commit()
    alice.post("/auth/login", data={"username": alice.handle, "password": "wrong guess"})
    with app.app_context():
        actions = {r[0] for r in get_db().execute("SELECT action FROM audit_log")}
    assert "old" not in actions
    assert "recent" in actions
