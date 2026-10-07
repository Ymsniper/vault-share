import ipaddress

from flask import current_app, g, request

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


def audit(action, outcome, file_id=None, detail=None, user_id=_current_user):
    """Record an event. Never pass passwords, keys or file contents.

    The event is tied to the logged-in user unless user_id is given;
    pass user_id=None for events nobody can be held responsible for.
    Entries older than AUDIT_LOG_DAYS are deleted as new ones arrive.
    """
    if user_id is _current_user:
        user_id = g.user["id"] if g.get("user") is not None else None
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, action, file_id, outcome, detail, ip)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, action, file_id, outcome, detail, network_of(request.remote_addr or "")),
    )
    db.execute(
        "DELETE FROM audit_log WHERE at < datetime('now', ?)",
        (f"-{current_app.config['AUDIT_LOG_DAYS']} days",),
    )
    db.commit()
