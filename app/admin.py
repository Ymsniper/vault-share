import click
from flask import Blueprint, abort, g, render_template

from .audit import audit
from .auth import login_required
from .db import get_db

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/log")
@login_required
def log():
    if not g.user["is_admin"]:
        audit("read_log", "denied")
        abort(403)
    entries = get_db().execute(
        "SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.user_id"
        " ORDER BY a.id DESC LIMIT 200"
    ).fetchall()
    return render_template("admin/log.html", entries=entries)


@bp.cli.command("grant")
@click.argument("username")
def grant_command(username):
    """Let USERNAME read the audit log."""
    db = get_db()
    cur = db.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
    db.commit()
    if cur.rowcount == 0:
        raise click.ClickException(f"No user named {username}.")
    click.echo(f"{username} can now read the audit log.")
