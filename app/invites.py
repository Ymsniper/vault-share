"""Invite codes: registering needs one, and each lets a set number of
people register, once each.

Only a SHA-256 of each code is stored. The codes are random, 100 bits, so
the hash cannot be turned back into a code that still works.
"""
import hashlib
import re
import secrets
from datetime import datetime, timezone

import click
from flask.cli import AppGroup

from . import levels
from .audit import audit
from .db import get_db

# letters and digits without 0, O, 1 and I, which are easy to mix up when a
# code is read out: 32 symbols, 5 bits each, 20 of them
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
INVALID = "This invite code is not valid."

# the most the server's defaults, or a special code, may ask for; the
# database checks the same limits
MAX_USES = 100
MIN_MINUTES, MAX_MINUTES = 10, 90 * 24 * 60
MAX_ADMIN_PER_DAY = 50

# for "made by": anyone at all, as opposed to None, the server itself
ANY = object()


def new_code():
    raw = "".join(secrets.choice(ALPHABET) for _ in range(20))
    return "-".join(raw[i : i + 5] for i in range(0, 20, 5))


def code_hash(code):
    # typed in any case, with or without the dashes
    plain = "".join(c for c in code.upper() if c.isalnum())
    return hashlib.sha256(plain.encode()).hexdigest()


def people(n):
    return "1 person" if n == 1 else f"{n} people"


def plural(n, word):
    """n and word, with an s unless n is 1: 1 account, 3 more accounts."""
    return f"{n} {word}" + ("" if n == 1 else "s")


def parse_duration(text):
    """Minutes in "30m", "12h" or "7d", from 10 minutes to 90 days.
    Raises ValueError."""
    m = re.fullmatch(r"(\d+)([mhd])", text.strip().lower())
    if m is None:
        raise ValueError(f"Not a time limit: {text!r}. Use 30m, 12h or 7d.")
    minutes = int(m.group(1)) * {"m": 1, "h": 60, "d": 1440}[m.group(2)]
    check_minutes(minutes)
    return minutes


def show_duration(minutes):
    for size, unit in ((1440, "day"), (60, "hour"), (1, "minute")):
        if minutes % size == 0:
            n = minutes // size
            return f"{n} {unit}" + ("" if n == 1 else "s")


def short_duration(minutes):
    """minutes as parse_duration reads them: 7d, 12h or 90m."""
    for size, unit in ((1440, "d"), (60, "h"), (1, "m")):
        if minutes % size == 0:
            return f"{minutes // size}{unit}"


def check_uses(uses):
    if not 1 <= uses <= MAX_USES:
        raise ValueError(f"A code lets 1 to {MAX_USES} people register.")


def check_minutes(minutes):
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError("A time limit must be between 10 minutes and 90 days.")


def defaults():
    """What a new code gets, set at the server: uses, valid_minutes, and
    admin_per_day, the accounts an admin's codes may create in 24 hours."""
    return get_db().execute(
        "SELECT uses, valid_minutes, admin_per_day FROM invite_defaults WHERE id = 1"
    ).fetchone()


def describe_defaults(d):
    text = (f"New codes let {people(d['uses'])} register and work for"
            f" {show_duration(d['valid_minutes'])}.")
    if d["admin_per_day"]:
        return text + f" Admins' codes may create {plural(d['admin_per_day'], 'account')} a day."
    return text + " Admins cannot make codes."


def set_defaults(uses=None, minutes=None, admin_per_day=None):
    """Change what codes made from now on get; codes already made keep their
    values. Logged with the old and new values. Returns a warning when admins
    can no longer make codes, else None. Raises ValueError."""
    old = defaults()
    new = {
        "uses": old["uses"] if uses is None else uses,
        "valid_minutes": old["valid_minutes"] if minutes is None else minutes,
        "admin_per_day": old["admin_per_day"] if admin_per_day is None else admin_per_day,
    }
    check_uses(new["uses"])
    check_minutes(new["valid_minutes"])
    if not 0 <= new["admin_per_day"] <= MAX_ADMIN_PER_DAY:
        raise ValueError(f"Admins' codes may create 0 to {MAX_ADMIN_PER_DAY} accounts a day.")
    db = get_db()
    db.execute(
        "UPDATE invite_defaults SET uses = ?, valid_minutes = ?, admin_per_day = ? WHERE id = 1",
        (new["uses"], new["valid_minutes"], new["admin_per_day"]),
    )
    db.commit()
    shown = {"valid_minutes": show_duration}
    names = {"uses": "uses", "valid_minutes": "time limit", "admin_per_day": "admin accounts a day"}
    changes = [
        f"{names[k]} {shown.get(k, str)(old[k])} to {shown.get(k, str)(new[k])}"
        for k in names if old[k] != new[k]
    ]
    if changes:
        audit("invite", "defaults", detail="; ".join(changes), user_id=None)
    if 0 < new["admin_per_day"] < new["uses"]:
        return (f"Admins cannot make codes now: a code lets {people(new['uses'])} register,"
                f" more than the {plural(new['admin_per_day'], 'account')} a day their codes may"
                " create.")
    return None


def create_invite(created_by=None, uses=None, minutes=None):
    """Store a new invite and return its code, which is shown only this once.

    created_by is the admin who made it, or None when it is made at the
    server. uses and minutes default to the server's defaults; only the
    server passes others, for a special code. Raises ValueError.
    """
    d = defaults()
    uses = d["uses"] if uses is None else uses
    minutes = d["valid_minutes"] if minutes is None else minutes
    check_uses(uses)
    check_minutes(minutes)
    return insert_invite(created_by, uses, minutes)


def create_admin_invite(admin_id):
    """An admin's code, with the server's defaults, or None when the accounts
    their codes of the last 24 hours may create, this one's included, would
    go over the daily limit. Checked and stored in one statement, so two
    requests at once cannot both slip under it. The code belongs to the
    session's level, which counts only the codes it sees."""
    d = defaults()
    return insert_invite(admin_id, d["uses"], d["valid_minutes"], limit=d["admin_per_day"])


def insert_invite(created_by, uses, minutes, limit=None):
    code = new_code()
    level = levels.session_level()
    sql = (
        "INSERT INTO invites (code_hash, created_by, expires_at, max_uses, level)"
        " SELECT ?, ?, datetime('now', ?), ?, ?"
    )
    params = [code_hash(code), created_by, f"+{int(minutes)} minutes", uses, level]
    if limit is not None:
        sql += (
            " WHERE (SELECT COALESCE(SUM(max_uses), 0) FROM invites"
            "  WHERE created_by = ? AND level >= ? AND created_at > datetime('now', '-1 day'))"
            " + ? <= ?"
        )
        params += [created_by, level, uses, limit]
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    if cur.rowcount == 0:
        return None
    where = "" if created_by else " at the server"
    audit(
        "invite",
        "ok",
        detail=f"code {cur.lastrowid}{where}, {people(uses)}, {show_duration(minutes)}",
        user_id=created_by,
    )
    return code


def places_today(user_id):
    """How many accounts this admin's codes of the last 24 hours may create,
    cancelled ones included, so cancelling and making new ones gains nothing.
    A session counts the codes it sees, made at its level or below, so the
    allowance never shows codes it cannot list."""
    return get_db().execute(
        "SELECT COALESCE(SUM(max_uses), 0) FROM invites WHERE created_by = ? AND level >= ?"
        " AND created_at > datetime('now', '-1 day')",
        (user_id, levels.session_level()),
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
        " WHERE id = ? AND uses < max_uses AND cancelled_at IS NULL AND level >= ?"
    )
    params = [invite_id, levels.session_level()]
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
        # a session lists the codes made at its level or below
        " WHERE i.level >= ?"
    )
    params = [levels.session_level()]
    if created_by is not ANY:
        sql += " AND i.created_by IS ?"
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
@click.option("--uses", type=int,
              help=f"People this code lets register, 1 to {MAX_USES}, instead of the default.")
@click.option("--valid", metavar="TIME",
              help="How long this code works, 30m, 12h or 7d (10 minutes to 90 days),"
                   " instead of the default.")
def new_command(uses, valid):
    """Make an invite code. It is shown only now: send it to the person.

    Without options it gets the defaults (see "invite defaults"). The options
    make a special code: they apply to this one code only.
    """
    try:
        code = create_invite(uses=uses, minutes=parse_duration(valid) if valid else None)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    click.echo(code)


@invite_cli.command("defaults")
@click.option("--uses", type=int, help=f"People each new code lets register, 1 to {MAX_USES}.")
@click.option("--valid", metavar="TIME",
              help="How long a new code works: 30m, 12h or 7d, from 10 minutes to 90 days.")
@click.option("--admin-per-day", type=int,
              help=f"Accounts an admin's codes may create in 24 hours, 0 to {MAX_ADMIN_PER_DAY};"
                   " 0 stops admin codes.")
def defaults_command(uses, valid, admin_per_day):
    """Show the defaults for new invite codes, or change them.

    Codes already made keep the values they were made with.
    """
    if (uses, valid, admin_per_day) != (None, None, None):
        try:
            warning = set_defaults(uses, parse_duration(valid) if valid else None, admin_per_day)
        except ValueError as e:
            raise click.ClickException(str(e)) from None
        if warning:
            click.echo(warning)
    click.echo(describe_defaults(defaults()))


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


# "invite cancel" is in admin.py, next to the bans it can also make
