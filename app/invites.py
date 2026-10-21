"""Invite codes: registering needs one, and each lets a set number of
people register, once each.

Only a SHA-256 of each code is stored. The codes are random, 100 bits, so
the hash cannot be turned back into a code that still works.
"""
import hashlib
import secrets
from datetime import datetime, timezone

import click
from flask.cli import AppGroup

from .audit import audit
from .db import get_db

# letters and digits without 0, O, 1 and I, which are easy to mix up when a
# code is read out: 32 symbols, 5 bits each, 20 of them
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
DAYS = 7
USES = 1
INVALID = "This invite code is not valid."
# for admins on the website: a stolen admin login hands out only so many
ADMIN_DAILY_LIMIT = 5

# for "made by": anyone at all, as opposed to None, the server itself
ANY = object()


def new_code():
    raw = "".join(secrets.choice(ALPHABET) for _ in range(20))
    return "-".join(raw[i : i + 5] for i in range(0, 20, 5))


def code_hash(code):
    # typed in any case, with or without the dashes
    plain = "".join(c for c in code.upper() if c.isalnum())
    return hashlib.sha256(plain.encode()).hexdigest()


def create_invite(created_by=None, days=DAYS, uses=USES):
    """Store a new invite and return its code, which is shown only this once.

    created_by is the admin who made it, or None when it is made at the server.
    """
    code = new_code()
    db = get_db()
    cur = db.execute(
        "INSERT INTO invites (code_hash, created_by, expires_at, max_uses)"
        " VALUES (?, ?, datetime('now', ?), ?)",
        (code_hash(code), created_by, f"+{int(days)} days", uses),
    )
    db.commit()
    where = "" if created_by else ", at the server"
    audit("invite", "ok", detail=f"code {cur.lastrowid}{where}", user_id=created_by)
    return code


def made_today(user_id):
    """How many codes this admin made in the last 24 hours."""
    return get_db().execute(
        "SELECT COUNT(*) FROM invites WHERE created_by = ?"
        " AND created_at > datetime('now', '-1 day')",
        (user_id,),
    ).fetchone()[0]


def usable_invite(code):
    """The id of the invite with this code if it can still be used, or None."""
    row = get_db().execute(
        "SELECT id FROM invites WHERE code_hash = ? AND uses < max_uses"
        " AND cancelled_at IS NULL AND expires_at > datetime('now')",
        (code_hash(code),),
    ).fetchone()
    return row["id"] if row else None


def use_invite(invite_id):
    """Take one of the invite's places, in the caller's transaction. False
    when the last one went, or it was cancelled or expired, since it was
    checked: one statement, so two people cannot both take the last place."""
    cur = get_db().execute(
        "UPDATE invites SET uses = uses + 1"
        " WHERE id = ? AND uses < max_uses AND cancelled_at IS NULL"
        " AND expires_at > datetime('now')",
        (invite_id,),
    )
    return cur.rowcount == 1


def cancel_invite(invite_id, created_by=ANY):
    """Cancel an invite that still has places, so nobody else registers with
    it; the accounts it made stay. An admin passes their own id as
    created_by, so they can only cancel their own. Raises ValueError."""
    sql = (
        "UPDATE invites SET cancelled_at = datetime('now')"
        " WHERE id = ? AND uses < max_uses AND cancelled_at IS NULL"
    )
    params = [invite_id]
    if created_by is not ANY:
        sql += " AND created_by IS ?"
        params.append(created_by)
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    if cur.rowcount == 0:
        raise ValueError(f"No open invite numbered {invite_id}.")
    actor = None if created_by is ANY else created_by
    audit("invite", "cancelled", detail=f"code {invite_id}", user_id=actor)


def list_invites(created_by=ANY):
    """Invites, newest first, with their state and the accounts made with
    each, as "name#tag, name#tag" (usernames never hold a comma)."""
    sql = (
        "SELECT i.id, i.created_at, i.expires_at, i.uses, i.max_uses, m.username AS made_by,"
        " (SELECT GROUP_CONCAT(u.username, ', ') FROM users u WHERE u.invite_id = i.id)"
        "  AS used_by,"
        " CASE WHEN i.uses >= i.max_uses THEN 'used'"
        "  WHEN i.cancelled_at IS NOT NULL THEN 'cancelled'"
        "  WHEN i.expires_at <= datetime('now') THEN 'expired' ELSE 'open' END AS state"
        " FROM invites i LEFT JOIN users m ON m.id = i.created_by"
    )
    params = []
    if created_by is not ANY:
        sql += " WHERE i.created_by IS ?"
        params.append(created_by)
    return get_db().execute(sql + " ORDER BY i.id DESC", params).fetchall()


def to_local(utc_text):
    """A time from the database, which keeps UTC, in this machine's time zone."""
    t = datetime.strptime(utc_text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return t.astimezone().strftime("%Y-%m-%d %H:%M")


def from_local(text):
    """'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD' in this machine's time zone, as the
    UTC text the database compares with. Raises ValueError."""
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            t = datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
        return t.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    raise ValueError(f"Not a date and time: {text!r}. Use YYYY-MM-DD HH:MM, in local time.")


invite_cli = AppGroup("invite", help="Make, list and cancel invite codes.")


@invite_cli.command("new")
@click.option("--days", default=DAYS, show_default=True, type=click.IntRange(1, 90),
              help="Days before the code expires.")
def new_command(days):
    """Make an invite code. It is shown only now: send it to the person."""
    click.echo(create_invite(days=days))


@invite_cli.command("list")
def list_command():
    """List the invite codes, newest first. Times are local."""
    for r in list_invites():
        line = (f"{r['id']:>4}  {r['state']:<9}  {r['uses']} of {r['max_uses']} used,"
                f" made {to_local(r['created_at'])} by {r['made_by'] or 'the server'},"
                f" expires {to_local(r['expires_at'])}")
        if r["used_by"]:
            line += f", used by {r['used_by']}"
        click.echo(line)


@invite_cli.command("cancel")
@click.argument("number", type=int)
def cancel_command(number):
    """Cancel invite NUMBER (from "invite list") while it still has places."""
    try:
        cancel_invite(number)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(f"Invite {number} cancelled.")
