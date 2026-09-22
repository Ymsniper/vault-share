import io

from app.db import get_db


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
    alice.post(
        "/upload",
        data={"file": (io.BytesIO(b"quarterly figures"), "q3.txt")},
        content_type="multipart/form-data",
    )
    alice.get("/files/1")
    alice.post("/files/1/share", data={"username": "bob"})
    bob.get("/files/1/download")
    alice.post("/files/1/delete")

    rows = log_rows(app)
    for expected in (
        ("alice", "upload", "ok", 1),
        ("alice", "verify", "ok", 1),
        ("alice", "share", "ok", 1),
        ("bob", "download", "ok", 1),
        ("alice", "delete", "ok", 1),
    ):
        assert expected in rows


def test_failed_login_is_not_blamed_on_the_current_user(app, alice):
    alice.post("/auth/login", data={"username": "alice", "password": "wrong"})
    assert log_rows(app)[-1] == (None, "login", "failed", None)


def test_log_never_contains_passwords(app, alice):
    alice.post("/auth/login", data={"username": "alice", "password": "wrong guess 123"})
    with app.app_context():
        dump = "\n".join(get_db().iterdump())
    log_lines = [line for line in dump.splitlines() if "audit_log" in line]
    assert log_lines
    assert not any("contract-2026" in line or "wrong guess 123" in line for line in log_lines)


def test_audit_log_is_for_admins_only(app, alice):
    assert alice.get("/admin/log").status_code == 403
    assert ("alice", "read_log", "denied", None) in log_rows(app)

    r = app.test_cli_runner().invoke(args=["admin", "grant", "alice"])
    assert "alice can now read the audit log." in r.output
    r = alice.get("/admin/log")
    assert r.status_code == 200
    assert b"read_log" in r.data


def test_grant_rejects_unknown_user(app):
    r = app.test_cli_runner().invoke(args=["admin", "grant", "nobody"])
    assert r.exit_code != 0
    assert "No user named nobody." in r.output
