import click
from flask import Blueprint, abort, g, render_template

from .audit import audit
from .auth import login_required
from .db import get_db
from .identity import write_crl

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/log")
@login_required
def log():
    # the decoy account is never an administrator
    if not g.user["is_admin"] or g.duress:
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


@bp.cli.command("revoke")
@click.argument("username")
def revoke_command(username):
    """Revoke USERNAME's certificate and publish a new revocation list.

    Files signed with it stop passing verification; the user's next upload
    gives them a new key and certificate.
    """
    db = get_db()
    cur = db.execute(
        "UPDATE certificates SET revoked_at = datetime('now')"
        " WHERE revoked_at IS NULL AND user_id = (SELECT id FROM users WHERE username = ?)",
        (username,),
    )
    if cur.rowcount == 0:
        raise click.ClickException(f"{username} has no certificate to revoke.")
    db.commit()
    try:
        path = write_crl()
    except (OSError, ValueError) as e:
        raise click.ClickException(f"revoked in the database, but the CRL was not written: {e}")
    click.echo(f"Revoked {username}'s certificate. Revocation list: {path}")
