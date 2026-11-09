import ipaddress

from flask import current_app, g, has_request_context, request

from .db import get_db

_current_user = object()


def network_of(address):
    """The /24 (IPv4) or /48 (IPv6) network of an address, or None.

    Enough to see that attempts come from one network, without keeping
    anyone's exact address.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def audit(action, outcome, file_id=None, detail=None, user_id=_current_user, level=_current_user):
    """Record an event. Never pass passwords, keys or file contents.

    The event is tied to the logged-in user unless user_id is given;
    pass user_id=None for events nobody can be held responsible for. It is
    written at the level of the current session, or the level given (a
    login, before its session exists); with neither it has no level, as
    the server's own acts. For a file, the row also keeps its owner and the
    level of the owner's copy, which the log's level rule judges by once
    the file is gone (app/levels.py).
    Entries older than AUDIT_LOG_DAYS are deleted as new ones arrive.
    """
    if user_id is _current_user:
        user_id = g.user["id"] if g.get("user") is not None else None
    if level is _current_user:
        level = g.level if g.get("user") is not None else None
    # actions taken at the server, from the console or the command line,
    # come with no address
    address = request.remote_addr if has_request_context() else None
    db = get_db()
    subject = (None, None)
    if file_id is not None:
        row = db.execute(
            "SELECT f.owner_id, c.level FROM files f LEFT JOIN file_keys c"
            " ON c.file_id = f.id AND c.user_id = f.owner_id WHERE f.id = ?",
            (file_id,),
        ).fetchone()
        if row is not None:
            subject = (row["owner_id"], row["level"])
    db.execute(
        "INSERT INTO audit_log"
        " (user_id, action, file_id, outcome, detail, ip, level, subject_id, subject_level)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, action, file_id, outcome, detail, network_of(address or ""), level, *subject),
    )
    db.execute(
        "DELETE FROM audit_log WHERE at < datetime('now', ?)",
        (f"-{current_app.config['AUDIT_LOG_DAYS']} days",),
    )
    db.commit()
