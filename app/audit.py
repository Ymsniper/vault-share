from flask import g, request

from .db import get_db

_current_user = object()


def audit(action, outcome, file_id=None, detail=None, user_id=_current_user):
    """Record an event. Never pass passwords, keys or file contents.

    The event is tied to the logged-in user unless user_id is given;
    pass user_id=None for events nobody can be held responsible for.
    """
    if user_id is _current_user:
        user_id = g.user["id"] if g.get("user") is not None else None
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, action, file_id, outcome, detail, ip)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, action, file_id, outcome, detail, request.remote_addr),
    )
    db.commit()
