import click
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    session,
    url_for,
)

from .audit import audit
from .auth import current_account, login_required, password_limit
from .db import get_db
from .forms import TotpForm, first_error
from .identity import write_crl
from .invites import (
    ANY,
    cancel_invite,
    create_admin_invite,
    defaults,
    from_local,
    invite_cli,
    list_invites,
    people,
    places_today,
    plural,
    show_duration,
    to_local,
)
from .totp import check_password_and_code, no_store, unseal

bp = Blueprint("admin", __name__, url_prefix="/admin")


DECOY_REFUSAL = "This could not be saved. Try again later."


def admin_only(action):
    if not g.user["is_admin"]:
        audit(action, "denied")
        abort(403)


def refuse_decoy(tried):
    """An admin's decoy session shows the admin pages, since a 403 would give
    it away, but it cannot act. The attempt is logged as a duress event,
    which the decoy's own view of the log never shows."""
    audit("duress", "refused", detail=tried)
    flash(DECOY_REFUSAL)
    return redirect(url_for("admin.invites"))


def log_entries(hide_duress=False):
    """The latest 200 audit entries. A decoy session never sees the duress
    events: the silent alarm, and what the decoy itself was refused."""
    sql = "SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id = a.user_id"
    if hide_duress:
        sql += " WHERE a.action != 'duress'"
    return get_db().execute(sql + " ORDER BY a.id DESC LIMIT 200").fetchall()


@bp.route("/log")
@login_required
def log():
    admin_only("read_log")
    return render_template("admin/log.html", entries=log_entries(hide_duress=g.duress))


def accounts_left():
    """How many more accounts this admin's codes may create today."""
    return max(0, defaults()["admin_per_day"] - places_today(g.user["id"]))


def over_the_limit(d, left):
    return (f"Not today: your codes may create {plural(left, 'more account')} in the next"
            f" 24 hours, and a code lets {people(d['uses'])} register.")


@bp.route("/invites")
@login_required
def invites():
    admin_only("invite")
    d = defaults()
    left = accounts_left()
    page = render_template(
        "admin/invites.html",
        invites=list_invites(created_by=g.user["id"]),
        # shown on this one page only: just its hash is stored
        new_code=session.pop("new_invite_code", None),
        defaults=d,
        people=people(d["uses"]),
        valid=show_duration(d["valid_minutes"]),
        per_day=plural(d["admin_per_day"], "account"),
        left=left,
        more=plural(left, "more account"),
        over=over_the_limit(d, left),
    )
    return no_store(page)


@bp.route("/invites/new", methods=("POST",))
@login_required
@password_limit(current_account)
def new_invite():
    """An admin makes a code with their password and a code from their phone,
    so a stolen password alone, or a stolen session, cannot let anyone in."""
    admin_only("invite")
    if g.duress:
        return refuse_decoy("making an invite code")
    if g.user["totp_secret"] is None:
        flash("Turn on two-factor login first: admins need it to make invite codes.")
        return redirect(url_for("admin.invites"))
    form = TotpForm()
    if not form.validate_on_submit():
        flash(first_error(form))
        return redirect(url_for("admin.invites"))
    d = defaults()
    if not d["admin_per_day"]:
        audit("invite", "refused", detail="admin codes switched off")
        flash("Making invite codes is switched off at the server.")
        return redirect(url_for("admin.invites"))
    if accounts_left() < d["uses"]:
        audit("invite", "refused", detail="daily limit")
        flash(over_the_limit(d, accounts_left()))
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
    code = create_admin_invite(g.user["id"])
    if code is None:  # another request took the last of today's places
        flash(over_the_limit(d, accounts_left()))
    else:
        session["new_invite_code"] = code
    return redirect(url_for("admin.invites"))


@bp.route("/invites/<int:invite_id>/cancel", methods=("POST",))
@login_required
def cancel_code(invite_id):
    admin_only("invite")
    if g.duress:
        return refuse_decoy(f"cancelling invite {invite_id}")
    try:
        cancel_invite(invite_id, created_by=g.user["id"])
    except ValueError as e:
        flash(str(e))
    else:
        flash(f"Invite {invite_id} cancelled.", "success")
    return redirect(url_for("admin.invites"))


def user_by_handle(username):
    """The user with exactly this username. Raises ValueError."""
    user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        raise ValueError(f"No user named {username}.")
    return user


def grant_admin(username):
    """Let username read the audit log and make invite codes. Raises
    ValueError for an unknown or banned user."""
    user = user_by_handle(username)
    if user["banned_at"] is not None:
        raise ValueError(f"{username} is banned: unban them first.")
    db = get_db()
    db.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user["id"],))
    db.commit()


def ban_accounts(user_ids):
    """Lock these accounts out until unbanned. They cannot log in, their
    sessions end, their files are hidden from everyone they shared with, and
    they lose admin rights and their open invite codes. Nothing is deleted.
    Returns how many were banned."""
    db = get_db()
    banned = 0
    for user_id in user_ids:
        cur = db.execute(
            "UPDATE users SET banned_at = datetime('now'), is_admin = 0"
            " WHERE id = ? AND banned_at IS NULL",
            (user_id,),
        )
        if cur.rowcount == 0:
            continue
        banned += 1
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        db.execute(
            "UPDATE invites SET cancelled_at = datetime('now')"
            " WHERE created_by = ? AND uses < max_uses AND cancelled_at IS NULL",
            (user_id,),
        )
        audit("ban", "ok", user_id=user_id)
    db.commit()
    return banned


def unban_accounts(user_ids):
    """Let these accounts log in again. Admin rights and cancelled codes do
    not come back. Returns how many were unbanned."""
    db = get_db()
    unbanned = 0
    for user_id in user_ids:
        cur = db.execute(
            "UPDATE users SET banned_at = NULL WHERE id = ? AND banned_at IS NOT NULL",
            (user_id,),
        )
        if cur.rowcount:
            unbanned += 1
            audit("unban", "ok", user_id=user_id)
    db.commit()
    return unbanned


def ban_user(username):
    if not ban_accounts([user_by_handle(username)["id"]]):
        raise ValueError(f"{username} is already banned.")


def unban_user(username):
    if not unban_accounts([user_by_handle(username)["id"]]):
        raise ValueError(f"{username} is not banned.")


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


# After a stolen admin login: find what was done with their invite codes, in a
# time window, and undo it in one go. Every action shows a preview first.

FAR_PAST, FAR_FUTURE = "0000-01-01 00:00:00", "9999-12-31 23:59:59"
# names listed in a preview; the rest are only counted
SHOWN = 20


def accounts_made(since=None, until=None, inviter=ANY, banned=False):
    """Accounts created from since up to until (UTC texts, None for no limit)
    with a code made by inviter: a user id, None for the server's own codes,
    or ANY. banned=True picks the banned ones instead, to unban them."""
    sql = (
        "SELECT u.id, u.username, u.created_at, m.username AS inviter FROM users u"
        " JOIN invites i ON i.id = u.invite_id LEFT JOIN users m ON m.id = i.created_by"
        " WHERE u.created_at >= ? AND u.created_at < ?"
    )
    sql += " AND u.banned_at IS NOT NULL" if banned else " AND u.banned_at IS NULL"
    params = [since or FAR_PAST, until or FAR_FUTURE]
    if inviter is not ANY:
        sql += " AND i.created_by IS ?"
        params.append(inviter)
    return get_db().execute(sql + " ORDER BY u.created_at", params).fetchall()


def codes_made(since=None, until=None, inviter=ANY):
    """Invite codes made from since up to until by inviter, with places left."""
    sql = (
        "SELECT i.id, i.created_at, m.username AS made_by FROM invites i"
        " LEFT JOIN users m ON m.id = i.created_by"
        " WHERE i.created_at >= ? AND i.created_at < ?"
        " AND i.uses < i.max_uses AND i.cancelled_at IS NULL"
    )
    params = [since or FAR_PAST, until or FAR_FUTURE]
    if inviter is not ANY:
        sql += " AND i.created_by IS ?"
        params.append(inviter)
    return get_db().execute(sql + " ORDER BY i.created_at", params).fetchall()


def cancel_codes(codes):
    cancelled = 0
    for c in codes:
        try:
            cancel_invite(c["id"])
            cancelled += 1
        except ValueError:  # used or cancelled since the preview
            pass
    return cancelled


def inviter_from(text):
    """A cleanup's "codes from": empty for anyone, "server" for the server's
    own codes, else a username. Raises ValueError."""
    text = text.strip()
    if not text:
        return ANY
    if text == "server":
        return None
    return user_by_handle(text)["id"]


def plan_cleanup(since, until=None, inviter=ANY, unban=False):
    """The accounts and codes a cleanup would touch, as (accounts, codes).
    since and until are local times; until defaults to now."""
    since, until = from_local(since), from_local(until) if until else None
    accounts = accounts_made(since, until, inviter, banned=unban)
    codes = [] if unban else codes_made(since, until, inviter)
    return accounts, codes


def apply_cleanup(accounts, codes, unban=False):
    ids = [a["id"] for a in accounts]
    if unban:
        return f"{plural(unban_accounts(ids), 'account')} unbanned."
    cancelled = cancel_codes(codes)
    banned = ban_accounts(ids)
    return f"{plural(banned, 'account')} banned, {plural(cancelled, 'open code')} cancelled."


def account_lines(accounts, verb, shown):
    lines = [f"Accounts to {verb}: {len(accounts)}"]
    for a in accounts[:shown]:
        lines.append(f"  {a['username']}, created {to_local(a['created_at'])},"
                     f" code from {a['inviter'] or 'the server'}")
    if len(accounts) > shown:
        lines.append(f"  and {len(accounts) - shown} more")
    return lines


def describe(accounts, codes, unban=False, shown=SHOWN):
    """A cleanup's preview, as lines of text."""
    lines = account_lines(accounts, "unban" if unban else "ban", shown)
    if not unban:
        lines.append(f"Open invite codes to cancel: {len(codes)}")
        for c in codes[:shown]:
            lines.append(f"  no. {c['id']}, made {to_local(c['created_at'])}"
                         f" by {c['made_by'] or 'the server'}")
        if len(codes) > shown:
            lines.append(f"  and {len(codes) - shown} more")
    return lines


def accounts_made_with(invite_id):
    """The accounts, not banned, made with this invite code. Raises
    ValueError when there is no such code."""
    db = get_db()
    if db.execute("SELECT 1 FROM invites WHERE id = ?", (invite_id,)).fetchone() is None:
        raise ValueError(f"No invite numbered {invite_id}.")
    return db.execute(
        "SELECT u.id, u.username, u.created_at, m.username AS inviter FROM users u"
        " JOIN invites i ON i.id = u.invite_id LEFT JOIN users m ON m.id = i.created_by"
        " WHERE u.invite_id = ? AND u.banned_at IS NULL ORDER BY u.created_at",
        (invite_id,),
    ).fetchall()


def describe_cancel(invite_id, accounts, shown=SHOWN):
    return [f"Invite {invite_id} is cancelled if it still has places.",
            *account_lines(accounts, "ban", shown)]


def cancel_and_ban(invite_id, accounts):
    """For a code that leaked: cancel it if it is still open, and ban the
    accounts made with it."""
    try:
        cancel_invite(invite_id)
        state = "cancelled"
    except ValueError:  # no places left, expired or cancelled before
        state = "already closed"
    banned = ban_accounts([a["id"] for a in accounts])
    return f"Invite {invite_id} {state}; {plural(banned, 'account')} banned."


def plan_revoke_admin(username, invited_since=None, all_invited=False):
    """What revoking an admin would touch, as (admin, accounts, codes): the
    accounts made with their codes since invited_since (local time), all of
    them, or none, and their open codes. Raises ValueError."""
    admin = user_by_handle(username)
    if not admin["is_admin"]:
        raise ValueError(f"{username} is not an admin.")
    if all_invited:
        accounts = accounts_made(inviter=admin["id"])
    elif invited_since:
        accounts = accounts_made(from_local(invited_since), inviter=admin["id"])
    else:
        accounts = []
    return admin, accounts, codes_made(inviter=admin["id"])


def describe_revoke(admin, accounts, codes, ban=False, revoke_cert=False, shown=SHOWN):
    lines = [f"{admin['username']} loses admin rights.", *describe(accounts, codes, shown=shown)]
    if ban:
        lines.append(f"{admin['username']} is banned too.")
    if revoke_cert:
        lines.append("Their certificate is revoked: files they signed stop passing verification.")
    return lines


def apply_revoke_admin(admin, accounts, codes, ban=False, revoke_cert=False):
    db = get_db()
    db.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (admin["id"],))
    db.commit()
    audit("admin", "revoked", user_id=admin["id"])
    done = [
        f"{admin['username']} is no longer an admin",
        f"{plural(cancel_codes(codes), 'open code')} cancelled",
        f"{plural(ban_accounts([a['id'] for a in accounts]), 'account')} banned",
    ]
    if ban and ban_accounts([admin["id"]]):
        done.append(f"{admin['username']} banned")
    if revoke_cert:
        # last: the rest already holds if this fails
        try:
            revoke_certificate(admin["username"])
            done.append("their certificate revoked")
        except ValueError as e:
            done.append(f"certificate not revoked: {e}")
    return "; ".join(done) + "."


@bp.cli.command("grant")
@click.argument("username")
def grant_command(username):
    """Make USERNAME an admin: they can read the audit log, and make invite
    codes once their two-factor login is on."""
    try:
        grant_admin(username)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"{username} is now an admin: they can read the audit log and make invite codes.")


@bp.cli.command("ban")
@click.argument("username")
def ban_command(username):
    """Lock USERNAME out until unbanned.

    They cannot log in, their sessions end, their files are hidden from
    everyone, and their admin rights and open invite codes go. Nothing is
    deleted.
    """
    try:
        ban_user(username)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"{username} is banned.")


@bp.cli.command("unban")
@click.argument("username")
def unban_command(username):
    """Let USERNAME log in again."""
    try:
        unban_user(username)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"{username} can log in again.")


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


TIME = "YYYY-MM-DD HH:MM, local time"


def show_and_confirm(lines, yes):
    for line in lines:
        click.echo(line)
    if not yes:
        click.confirm("Go ahead?", abort=True)


@bp.cli.command("revoke-admin")
@click.argument("username")
@click.option("--ban-invited-since", metavar="TIME",
              help=f"Also ban the accounts made with their codes since TIME ({TIME}).")
@click.option("--ban-all-invited", is_flag=True,
              help="Also ban every account made with their codes.")
@click.option("--ban", is_flag=True, help="Ban the admin too.")
@click.option("--revoke-certificate", "revoke_cert", is_flag=True,
              help="Revoke their certificate too: with their password, a thief could sign "
                   "files as them. Needs CA_PASSPHRASE.")
@click.option("--yes", is_flag=True, help="Do not ask before going ahead.")
def revoke_admin_command(username, ban_invited_since, ban_all_invited, ban, revoke_cert, yes):
    """Take admin rights from USERNAME and cancel their open invite codes.

    Shows what it will do first.
    """
    if ban_invited_since and ban_all_invited:
        raise click.UsageError("Use --ban-invited-since or --ban-all-invited, not both.")
    if revoke_cert and not current_app.config.get("CA_PASSPHRASE"):
        raise click.ClickException("Revoking the certificate needs CA_PASSPHRASE.")
    try:
        admin, accounts, codes = plan_revoke_admin(username, ban_invited_since, ban_all_invited)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    show_and_confirm(describe_revoke(admin, accounts, codes, ban, revoke_cert), yes)
    click.echo(apply_revoke_admin(admin, accounts, codes, ban, revoke_cert))


@bp.cli.command("cleanup")
@click.option("--from", "since", required=True, metavar="TIME",
              help=f"Start of the time window ({TIME}).")
@click.option("--to", "until", metavar="TIME", help="End of the window; now when left out.")
@click.option("--admin", "admin_name", metavar="USERNAME",
              help="Only what came from this admin's invite codes.")
@click.option("--server", is_flag=True, help="Only what came from the server's own codes.")
@click.option("--unban", is_flag=True, help="Unban the accounts instead.")
@click.option("--yes", is_flag=True, help="Do not ask before going ahead.")
def cleanup_command(since, until, admin_name, server, unban, yes):
    """Ban the accounts created in a time window and cancel the open invite
    codes made in it, or unban those accounts. Shows what it will do first."""
    if admin_name and server:
        raise click.UsageError("Use --admin or --server, not both.")
    try:
        inviter = inviter_from("server" if server else admin_name or "")
        accounts, codes = plan_cleanup(since, until, inviter, unban)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    if not accounts and not codes:
        click.echo("Nothing in that window.")
        return
    show_and_confirm(describe(accounts, codes, unban), yes)
    click.echo(apply_cleanup(accounts, codes, unban))


@invite_cli.command("cancel")
@click.argument("number", type=int)
@click.option("--ban-accounts", "ban_too", is_flag=True,
              help="Also ban the accounts made with it, for a code that leaked.")
@click.option("--yes", is_flag=True, help="Do not ask before banning.")
def cancel_command(number, ban_too, yes):
    """Cancel invite NUMBER (from "invite list") while it still has places.

    With --ban-accounts, also ban the accounts made with it, even when the
    code has no places left. Shows them first.
    """
    try:
        if not ban_too:
            cancel_invite(number)
            click.echo(f"Invite {number} cancelled.")
            return
        accounts = accounts_made_with(number)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    show_and_confirm(describe_cancel(number, accounts), yes)
    click.echo(cancel_and_ban(number, accounts))

