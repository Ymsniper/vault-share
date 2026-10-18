import click
from flask import Blueprint, abort, flash, g, redirect, render_template, session, url_for

from .audit import audit
from .auth import login_required, password_limit
from .db import get_db
from .forms import TotpForm, first_error
from .identity import write_crl
from .invites import (
    ADMIN_DAILY_LIMIT,
    DAYS,
    cancel_invite,
    create_invite,
    list_invites,
    made_today,
)
from .totp import check_password_and_code, no_store, unseal

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_only(action):
    # the decoy account is never an administrator
    if not g.user["is_admin"] or g.duress:
        audit(action, "denied")
        abort(403)


@bp.route("/log")
@login_required
def log():
    admin_only("read_log")
    entries = get_db().execute(
        "SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.user_id"
        " ORDER BY a.id DESC LIMIT 200"
    ).fetchall()
    return render_template("admin/log.html", entries=entries)


@bp.route("/invites")
@login_required
def invites():
    admin_only("invite")
    page = render_template(
        "admin/invites.html",
        invites=list_invites(created_by=g.user["id"]),
        # shown on this one page only: just its hash is stored
        new_code=session.pop("new_invite_code", None),
        left=ADMIN_DAILY_LIMIT - made_today(g.user["id"]),
        limit=ADMIN_DAILY_LIMIT,
        days=DAYS,
    )
    return no_store(page)


@bp.route("/invites/new", methods=("POST",))
@login_required
@password_limit(lambda: g.user["username"] if g.user else "")
def new_invite():
    """An admin makes a code with their password and a code from their phone,
    so a stolen password alone, or a stolen session, cannot let anyone in."""
    admin_only("invite")
    if g.user["totp_secret"] is None:
        flash("Turn on two-factor login first: admins need it to make invite codes.")
        return redirect(url_for("admin.invites"))
    form = TotpForm()
    if not form.validate_on_submit():
        flash(first_error(form))
        return redirect(url_for("admin.invites"))
    if made_today(g.user["id"]) >= ADMIN_DAILY_LIMIT:
        audit("invite", "refused", detail=f"{ADMIN_DAILY_LIMIT} codes a day")
        flash(f"You made {ADMIN_DAILY_LIMIT} codes in the last 24 hours, the most allowed.")
        return redirect(url_for("admin.invites"))
    secret = unseal(g.user["id"], g.user["totp_secret"])
    step = check_password_and_code(form, secret, g.user["totp_last_step"])
    if step is None:
        audit("invite", "refused", detail="wrong password or code")
        return redirect(url_for("admin.invites"))
    db = get_db()
    # this code from the phone cannot be used again
    db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, g.user["id"]))
    db.commit()
    session["new_invite_code"] = create_invite(created_by=g.user["id"])
    return redirect(url_for("admin.invites"))


@bp.route("/invites/<int:invite_id>/cancel", methods=("POST",))
@login_required
def cancel_code(invite_id):
    admin_only("invite")
    try:
        cancel_invite(invite_id, created_by=g.user["id"])
    except ValueError as e:
        flash(str(e))
    else:
        flash(f"Invite {invite_id} cancelled.", "success")
    return redirect(url_for("admin.invites"))


def grant_admin(username):
    """Let username read the audit log. Raises ValueError for an unknown user."""
    db = get_db()
    cur = db.execute("UPDATE users SET is_admin = 1 WHERE username = ?", (username,))
    db.commit()
    if cur.rowcount == 0:
        raise ValueError(f"No user named {username}.")


def revoke_certificate(username):
    """Revoke the user's certificate and publish a new revocation list.

    Returns the list's path. Raises ValueError when there is nothing to
    revoke or the list cannot be written.
    """
    db = get_db()
    cur = db.execute(
        "UPDATE certificates SET revoked_at = datetime('now')"
        " WHERE revoked_at IS NULL AND user_id = (SELECT id FROM users WHERE username = ?)",
        (username,),
    )
    if cur.rowcount == 0:
        raise ValueError(f"{username} has no certificate to revoke.")
    db.commit()
    try:
        return write_crl()
    except OSError as e:
        raise ValueError(f"revoked in the database, but the CRL was not written: {e}") from None


@bp.cli.command("grant")
@click.argument("username")
def grant_command(username):
    """Let USERNAME read the audit log."""
    try:
        grant_admin(username)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"{username} can now read the audit log.")


@bp.cli.command("revoke")
@click.argument("username")
def revoke_command(username):
    """Revoke USERNAME's certificate and publish a new revocation list.

    Files signed with it stop passing verification; the user's next upload
    gives them a new key and certificate.
    """
    try:
        path = revoke_certificate(username)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"Revoked {username}'s certificate. Revocation list: {path}")
