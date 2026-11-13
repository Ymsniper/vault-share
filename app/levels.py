"""An account's levels: the duress password opens a second vault that is
real, kept from the first by keys.

Level 0 opens with the real password, level 1 with the duress password,
and level 2 with the duress password set from a level 1 session. Each level
has its own X25519 key pair: a password opens its level's private key, and
that key opens the ones below it (a higher number), never the one above.
Every session works at one level and believes it is the top: it sees and
opens the copies of file keys at its own level and below. One more key
pair, linked down from level 2's and opened by no password, keeps level 2's
cover files, so moving files to cover works there as it does above.

This module reads the session's level; so do auth.py, which loads it,
audit.py, which writes it into the log, and invites.py, which sorts codes
by it. No view asks whether a session is a duress one.
"""
import datetime
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from flask import current_app, g

from security.crypto import decrypt, encrypt
from security.hybrid import generate_encryption_key, public_bytes, unwrap_file_key, wrap_file_key
from security.keychain import (
    follow_link,
    link_key,
    lock_key,
    unlock_key,
    unlock_signing_key,
    unused_lock,
)
from security.keys import subkey
from security.passwords import (
    check_password,
    check_password_of_unknown_user,
    derive_key,
    hash_password,
)

from .audit import audit
from .db import get_db
from .keyring import master_key
from .storage import storage_path

LEVELS = 3
# key pairs: one per level, and the one under level 2 for its cover files
KEY_LEVELS = LEVELS + 1
COVER, WIPE = b"C", b"W"
MODES = {"cover": COVER, "wipe": WIPE}

# The sealed record of an account's levels, always the same length: which
# credential row is each level's, then for every level its mode, when its
# password starts to work, since when its window is open, and since when it
# owes a review of the windows below it that its logins closed (epoch
# seconds, 0 for never), and the hash of the duress password saved at the
# last level, padded. Level 0's mode and times are never used.
_HASH_SPACE = 128
_FORMAT = f"<{LEVELS}q{LEVELS}c{LEVELS}q{LEVELS}q{LEVELS}q{_HASH_SPACE}s"


@dataclass
class Policy:
    rows: list
    modes: list
    active_from: list
    window_since: list
    unreviewed_since: list
    # the duress password saved at level 2, the last a password opens, or
    # "": it opens nothing, and the Password page alone reads it, to refuse
    # it as a new password there as the levels above refuse theirs
    beneath: str


def _aad(username):
    # as before the levels, so keyring.reencrypt moves it unchanged
    return f"duress:{username}".encode()


def seal_policy(username, policy):
    beneath = policy.beneath.encode()
    if len(beneath) > _HASH_SPACE:
        # struct would cut it short without a word
        raise ValueError("the password hash does not fit the policy")
    data = struct.pack(
        _FORMAT, *policy.rows, *policy.modes, *policy.active_from, *policy.window_since,
        *policy.unreviewed_since, beneath,
    )
    return encrypt(subkey(master_key(), "duress-policy"), data, _aad(username))


def open_policy(user):
    data = decrypt(subkey(master_key(), "duress-policy"), user["duress_policy"], _aad(user["username"]))
    values = struct.unpack(_FORMAT, data)
    parts = [list(values[i * LEVELS:(i + 1) * LEVELS]) for i in range(5)]
    return Policy(*parts, values[5 * LEVELS].rstrip(b"\0").decode())


def update_policy(user_id, change):
    """Open the account's policy, let change() edit it, and write it back
    unless another request wrote it in between; then start over, so no
    change is lost. change() may write other rows: they are kept only with
    the policy. Returns what change() returned."""
    db = get_db()
    for _ in range(20):
        row = db.execute(
            "SELECT username, duress_policy FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        policy = open_policy(row)
        result = change(policy)
        cur = db.execute(
            "UPDATE users SET duress_policy = ? WHERE id = ? AND duress_policy = ?",
            (seal_policy(row["username"], policy), user_id, row["duress_policy"]),
        )
        if cur.rowcount == 1:
            db.commit()
            return result
        db.rollback()
    raise RuntimeError("the account's levels kept changing")


def lock_aad(user_id, level):
    return f"lock|{user_id}|{level}".encode()


def link_aad(user_id, level):
    return f"link|{user_id}|{level}".encode()


def new_account(user_id, username, password):
    """Three levels for a new account. Each has a real key pair from the
    start, linked down from the one above, so a duress password can be set
    later; the password opens level 0, and levels 1 and 2 hold the hash of
    a random secret and an unused lock. The key pair for level 2's cover
    files hangs below them, with no password of its own. Returns level 2's
    private key, for the signing key; the caller commits."""
    db = get_db()
    keys = [generate_encryption_key() for _ in range(KEY_LEVELS)]
    rows = [0] * LEVELS
    # the rows go in in random order: their ids say nothing about levels
    order = list(range(LEVELS))
    secrets.SystemRandom().shuffle(order)
    for level in order:
        salt = os.urandom(16)
        if level == 0:
            row = (hash_password(password), salt, lock_key(keys[0], password, salt, lock_aad(user_id, 0)))
        else:
            row = (hash_password(secrets.token_urlsafe(32)), salt, unused_lock())
        rows[level] = db.execute(
            "INSERT INTO credentials (user_id, password_hash, kdf_salt, lock) VALUES (?, ?, ?, ?)",
            (user_id, *row),
        ).lastrowid
    for level, key in enumerate(keys):
        link = link_key(keys[level - 1], key, link_aad(user_id, level)) if level else None
        db.execute(
            "INSERT INTO level_keys (user_id, level, public_key, link) VALUES (?, ?, ?, ?)",
            (user_id, level, public_bytes(key), link),
        )
    policy = Policy(rows, [COVER] * LEVELS, [0] * LEVELS, [0] * LEVELS, [0] * LEVELS, "")
    db.execute(
        "UPDATE users SET duress_policy = ? WHERE id = ?", (seal_policy(username, policy), user_id)
    )
    # two-factor login off at level 0, and inherited by the levels below
    for level in range(LEVELS):
        db.execute(
            "INSERT INTO two_factor (user_id, level, sealed) VALUES (?, ?, ?)",
            (user_id, level, _seal_factor(user_id, level, OFF if level == 0 else INHERIT)),
        )
    return keys[LEVELS - 1]


def login_level(user, password):
    """The level password opens for user, or None. All three passwords are
    checked every time, for unknown usernames too, so neither the time a
    login takes nor its work shows which one matched."""
    rows = [] if user is None else get_db().execute(
        "SELECT id, password_hash FROM credentials WHERE user_id = ? ORDER BY id", (user["id"],)
    ).fetchall()
    matched = {r["id"] for r in rows if check_password(r["password_hash"], password)}
    for _ in range(LEVELS - len(rows)):
        check_password_of_unknown_user(password)
    if not matched:
        return None
    policy, now = open_policy(user), time.time()
    found = [
        level for level in range(LEVELS)
        if policy.rows[level] in matched and (level == 0 or 0 < policy.active_from[level] <= now)
    ]
    return min(found, default=None)


def session_level():
    """The current session's level, or 0 at the server (the console and the
    command line), which sees everything."""
    return g.level if g.get("user") is not None else 0


def wipes(user, level):
    """Whether a login at this level is a duress login in wipe mode."""
    return level > 0 and open_policy(user).modes[level] == WIPE


def alarm_detail(user, level, waits=False):
    """What a login row says about its level: nothing at level 0; for a
    duress login, its mode, shown only to those who see it as the alarm."""
    if level == 0:
        return None
    if not wipes(user, level):
        return "cover"
    return "wipe after the code" if waits else "wipe"


TRASH_DAYS = 30


def note_login(user, level):
    """At every completed login: a duress login opens its level's window,
    keeping its start if it is open already, and any login closes the
    windows of the levels below its own (a higher number). A login that
    closed some owes a review of them from then on, kept in the policy
    until it says done; what those levels trashed or dismissed starts its
    30 days now, when the review first shows it. The policy is written
    again whatever the level, so every login makes the same writes."""
    now = int(time.time())

    def change(policy):
        closed = []
        for lower in range(level + 1, LEVELS):
            if policy.window_since[lower]:
                closed.append(policy.window_since[lower])
                policy.window_since[lower] = 0
        if level and not policy.window_since[level]:
            policy.window_since[level] = now
        if closed:
            due = policy.unreviewed_since[level]
            policy.unreviewed_since[level] = min([*closed, due] if due else closed)
        return bool(closed)

    if update_policy(user["id"], change):
        _start_the_clock(user["id"], level)
    purge_trash()


def _start_the_clock(uid, level):
    db = get_db()
    db.execute(
        "UPDATE files SET review_from = datetime('now')"
        " WHERE owner_id = ? AND trashed_level > ? AND review_from IS NULL",
        (uid, level),
    )
    db.execute(
        "UPDATE file_keys SET review_from = datetime('now')"
        " WHERE user_id = ? AND dismissed_level > ? AND review_from IS NULL",
        (uid, level),
    )
    db.commit()


def _utc(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")


def review_due_at(user, level):
    """Whether logins at this level owe a review: they go to it until the
    owner says done."""
    return bool(open_policy(user).unreviewed_since[level])


def review_due():
    """Whether the session's level owes a review, for the link every page
    shows its sessions until then."""
    return g.get("user") is not None and review_due_at(g.user, g.level)


def review():
    """What happened in the duress windows the session's level owes a review
    of, or None when it owes none: what the levels below it (a higher
    number) did since the earliest of them opened."""
    due = open_policy(g.user).unreviewed_since[g.level]
    if not due:
        return None
    db, uid, level, since = get_db(), g.user["id"], g.level, _utc(due)
    params = (uid, level, since)
    return {
        "since": since,
        "logins": db.execute(
            "SELECT at, ip FROM audit_log WHERE user_id = ? AND level > ? AND at >= ?"
            " AND action = 'login' AND outcome = 'ok' ORDER BY id",
            params,
        ).fetchall(),
        "events": db.execute(
            "SELECT at, action, outcome, file_id, detail FROM audit_log"
            " WHERE user_id = ? AND level > ? AND at >= ? AND action != 'login' ORDER BY id",
            params,
        ).fetchall(),
        "trashed": _trashed(uid, level),
        "dismissed": _dismissed(uid, level),
        "planted": _planted(*params),
        "arrived": _arrived(*params),
    }


def _trashed(uid, level):
    # whatever the levels below trashed and is still kept, however long ago
    return get_db().execute(
        "SELECT id, filename, trashed_at FROM files"
        " WHERE owner_id = ? AND trashed_level > ? ORDER BY trashed_at",
        (uid, level),
    ).fetchall()


def _dismissed(uid, level):
    return get_db().execute(
        "SELECT f.id, f.filename, u.username AS owner FROM file_keys c"
        " JOIN files f ON f.id = c.file_id JOIN users u ON u.id = f.owner_id"
        " WHERE c.user_id = ? AND c.dismissed_level > ? AND f.trashed_at IS NULL"
        " ORDER BY f.filename",
        (uid, level),
    ).fetchall()


def _planted(uid, level, since):
    return get_db().execute(
        "SELECT f.id, f.filename, f.uploaded_at FROM files f"
        " JOIN file_keys c ON c.file_id = f.id AND c.user_id = f.owner_id"
        " WHERE f.owner_id = ? AND c.level > ? AND f.uploaded_at >= ? AND f.trashed_at IS NULL"
        " ORDER BY f.uploaded_at",
        (uid, level, since),
    ).fetchall()


def _arrived(uid, level, since):
    return get_db().execute(
        "SELECT f.id, f.filename, u.username AS owner, c.level FROM file_keys c"
        " JOIN files f ON f.id = c.file_id JOIN users u ON u.id = f.owner_id"
        " JOIN shares s ON s.file_id = f.id AND s.recipient_id = c.user_id"
        " WHERE c.user_id = ? AND c.level > ? AND s.created_at >= ? AND f.owner_id != c.user_id"
        " AND s.revoked_at IS NULL AND s.dismissed_at IS NULL AND f.trashed_at IS NULL",
        (uid, level, since),
    ).fetchall()


def _reviewed(rows, file_ids):
    wanted = set(file_ids)
    return [r for r in rows if r["id"] in wanted]


def restore(file_ids):
    """Bring back files a duress session trashed in the reviewed windows."""
    data = review()
    found = _reviewed(data["trashed"], file_ids) if data else []
    db = get_db()
    for r in found:
        db.execute(
            "UPDATE files SET trashed_at = NULL, trashed_level = NULL, review_from = NULL"
            " WHERE id = ?",
            (r["id"],),
        )
    db.commit()
    return len(found)


def remove_planted(file_ids):
    """Delete files a duress session uploaded in the reviewed windows, as
    the session deletes anything."""
    data = review()
    found = _reviewed(data["planted"], file_ids) if data else []
    for r in found:
        # logged first, while the row still says whose file it was
        audit("delete", "ok", file_id=r["id"], detail="from the review")
        discard(r["id"])
    return len(found)


def bring_back(keys, file_ids):
    """Move files shared with the account in the reviewed windows to the
    session's own level, encrypting their key copies again."""
    data = review()
    found = _reviewed(data["arrived"], file_ids) if data else []
    for r in found:
        _lift(keys, r["id"])
    get_db().commit()
    return len(found)


def _lift(keys, file_id):
    """The current user's copy of a file's key, opened with the keys the
    password opened and encrypted again to the session's own level."""
    uid = g.user["id"]
    copy = get_db().execute(
        "SELECT wrapped_key, level FROM file_keys WHERE file_id = ? AND user_id = ?",
        (file_id, uid),
    ).fetchone()
    key = unwrap_file_key(keys.private[copy["level"]], copy["wrapped_key"], file_id, uid,
                          copy["level"])
    _store(file_id, uid, key, g.level)


def put_back(keys, file_ids):
    """Files a duress session dismissed in the reviewed windows, back on the
    session's own list: the copy kept for them is encrypted again to its
    level, so the duress session still finds them dismissed."""
    data = review()
    found = _reviewed(data["dismissed"], file_ids) if data else []
    db = get_db()
    for r in found:
        _lift(keys, r["id"])
        db.execute(
            "UPDATE shares SET dismissed_at = NULL WHERE file_id = ? AND recipient_id = ?",
            (r["id"], g.user["id"]),
        )
    db.commit()
    return len(found)


def review_done(keys, leftover):
    """The owner is done with the review: what is still trashed or dismissed
    is restored or put back ("restore"), or let go now ("let-go"), and the
    logins at this level stop going to the review."""
    data = review()
    if data is None:
        return
    if leftover == "restore":
        restore([r["id"] for r in data["trashed"]])
        put_back(keys, [r["id"] for r in data["dismissed"]])
    else:
        _let_go([r["id"] for r in data["trashed"]], [r["id"] for r in data["dismissed"]])
    level = g.level

    def change(policy):
        policy.unreviewed_since[level] = 0

    update_policy(g.user["id"], change)


def _let_go(trashed, dismissed):
    db = get_db()
    db.execute("PRAGMA secure_delete = ON")
    paths = [storage_path(file_id) for file_id in trashed]
    for file_id in trashed:
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    for file_id in dismissed:
        db.execute(
            "DELETE FROM file_keys WHERE file_id = ? AND user_id = ?", (file_id, g.user["id"])
        )
    db.commit()
    _remove(paths)


def purge_trash():
    """Remove what duress sessions trashed or dismissed, 30 days after a
    review first showed it: an owner who never logs in loses nothing."""
    db = get_db()
    cutoff = f"-{TRASH_DAYS} days"
    gone = [r["id"] for r in db.execute(
        "SELECT id FROM files WHERE review_from < datetime('now', ?)", (cutoff,)
    )]
    db.execute("PRAGMA secure_delete = ON")
    dropped = db.execute(
        "DELETE FROM file_keys WHERE dismissed_level IS NOT NULL"
        " AND review_from < datetime('now', ?)", (cutoff,)
    ).rowcount
    if not gone and not dropped:
        return
    paths = [storage_path(file_id) for file_id in gone]
    for file_id in gone:
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    _remove(paths)


def dismiss(file_id):
    """A recipient takes a shared file off their own list. From level 0 their
    copy of its key goes; from a duress session it is kept, marked, so the
    review can put the file back, while the file is gone from every list
    as after any dismiss. The caller commits."""
    db, uid, level = get_db(), g.user["id"], g.level
    db.execute(
        "UPDATE shares SET dismissed_at = datetime('now') WHERE file_id = ? AND recipient_id = ?",
        (file_id, uid),
    )
    if level == 0:
        db.execute("DELETE FROM file_keys WHERE file_id = ? AND user_id = ?", (file_id, uid))
    else:
        db.execute(
            "UPDATE file_keys SET dismissed_level = ? WHERE file_id = ? AND user_id = ?",
            (level, file_id, uid),
        )


def seal_pending(user_id, level):
    """The level of a login that still owes its two-factor code, sealed so
    the cookie that carries it gives nothing away."""
    return encrypt(subkey(master_key(), "login-mode"), bytes([level]), f"login:{user_id}".encode())


def pending_level(user_id, blob):
    return decrypt(subkey(master_key(), "login-mode"), blob, f"login:{user_id}".encode())[0]


@dataclass
class Keys:
    """The private keys a session's password opens: its own level's and
    every one below it."""
    user_id: int
    private: dict

    def signing_key(self):
        row = get_db().execute(
            "SELECT enc_private_key FROM signing_keys WHERE user_id = ?", (self.user_id,)
        ).fetchone()
        return unlock_signing_key(self.bottom, row["enc_private_key"], signing_aad(self.user_id))

    @property
    def bottom(self):
        """Level 2's private key, the last a password opens, which the
        signing key hangs off."""
        return self.private[LEVELS - 1]


def signing_aad(user_id):
    return f"signing|{user_id}".encode()


def unlock(password):
    """The keys the password opens in the current session, or None when it
    is not this session's password. Every password asked inside a session
    is checked here, against its own level's lock only, so no form at one
    level can test the password of another."""
    user, level = g.user, g.level
    db = get_db()
    row = db.execute(
        "SELECT kdf_salt, lock FROM credentials WHERE id = ?", (open_policy(user).rows[level],)
    ).fetchone()
    try:
        key = unlock_key(row["lock"], password, row["kdf_salt"], lock_aad(user["id"], level))
    except InvalidTag:
        return None
    links = dict(db.execute(
        "SELECT level, link FROM level_keys WHERE user_id = ?", (user["id"],)
    ).fetchall())
    private = {level: key}
    for lower in range(level + 1, KEY_LEVELS):
        key = follow_link(key, links[lower], link_aad(user["id"], lower))
        private[lower] = key
    return Keys(user["id"], private)


def my_copy(file_id):
    """The current user's copy of a file's key, if the session sees it."""
    return get_db().execute(
        "SELECT wrapped_key, level FROM file_keys WHERE file_id = ? AND user_id = ? AND level >= ?",
        (file_id, g.user["id"], g.level),
    ).fetchone()


def hidden(file_id):
    """Whether the current user holds a copy of this file's key that the
    session does not see: kept at a level above the session's."""
    return get_db().execute(
        "SELECT 1 FROM file_keys WHERE file_id = ? AND user_id = ? AND level < ?",
        (file_id, g.user["id"], g.level),
    ).fetchone() is not None


def file_key(file_id, keys):
    """The file's key, from the current user's copy opened with keys, or
    None without a copy the session sees. Raises InvalidTag when the copy
    was modified."""
    copy = my_copy(file_id)
    if copy is None:
        return None
    return unwrap_file_key(
        keys.private[copy["level"]], copy["wrapped_key"], file_id, g.user["id"], copy["level"]
    )


def _store(file_id, user_id, key, level):
    public = get_db().execute(
        "SELECT public_key FROM level_keys WHERE user_id = ? AND level = ?", (user_id, level)
    ).fetchone()["public_key"]
    get_db().execute(
        "INSERT INTO file_keys (file_id, user_id, wrapped_key, level) VALUES (?, ?, ?, ?)"
        " ON CONFLICT (file_id, user_id) DO UPDATE"
        " SET wrapped_key = excluded.wrapped_key, level = excluded.level, since = datetime('now'),"
        " dismissed_level = NULL, review_from = NULL",
        (file_id, user_id, wrap_file_key(public, key, file_id, user_id, level), level),
    )


def keep_own_copy(file_id, key):
    """At upload, the owner's copy of the file key, at the session's level.
    The caller commits."""
    _store(file_id, g.user["id"], key, g.level)


def arrival_level(user_id):
    """The level a file shared with this user arrives at: the highest
    numbered level whose window is open, so whoever holds that duress
    session sees it arrive, as on a real account; else their top."""
    user = get_db().execute(
        "SELECT username, duress_policy FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    policy = open_policy(user)
    return max((lvl for lvl in range(1, LEVELS) if policy.window_since[lvl]), default=0)


def give_copy(file_id, user_id, key):
    """A recipient's copy of the file key, at the level a share arrives at.
    The caller commits."""
    _store(file_id, user_id, key, arrival_level(user_id))


def discard(file_id):
    """Delete a file for its owner. From level 0 it goes for good; from a
    duress session it is trashed instead, hidden from everyone exactly as
    if it were gone and kept 30 days, so a coercer cannot destroy what the
    real owner might want back. The caller removes nothing else."""
    db = get_db()
    if g.level == 0:
        _remove([storage_path(file_id)])
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    else:
        db.execute(
            "UPDATE files SET trashed_at = datetime('now'), trashed_level = ? WHERE id = ?",
            (g.level, file_id),
        )
    db.commit()


def file_lists(q):
    """The current user's files as the session sees them: its own at this
    level, those shared with it at this level, and the cover files, every
    copy at a level below."""
    db, uid, level = get_db(), g.user["id"], g.level
    mine = db.execute(
        "SELECT f.id, f.filename, f.size, f.uploaded_at, f.checked FROM files f"
        " JOIN file_keys c ON c.file_id = f.id AND c.user_id = f.owner_id"
        " WHERE f.owner_id = ? AND c.level = ? AND f.trashed_at IS NULL"
        " AND instr(lower(f.filename), lower(?)) > 0"
        " ORDER BY f.uploaded_at DESC, f.rowid DESC",
        (uid, level, q),
    ).fetchall()
    shared = db.execute(
        "SELECT f.*, u.username AS owner FROM files f"
        " JOIN shares s ON s.file_id = f.id"
        " JOIN users u ON u.id = f.owner_id"
        " JOIN file_keys c ON c.file_id = f.id AND c.user_id = s.recipient_id"
        " WHERE s.recipient_id = ? AND s.revoked_at IS NULL AND s.dismissed_at IS NULL"
        " AND u.banned_at IS NULL AND c.level = ? AND f.trashed_at IS NULL"
        " ORDER BY f.uploaded_at DESC, f.rowid DESC",
        (uid, level),
    ).fetchall()
    cover = db.execute(
        "SELECT f.*, u.username AS owner FROM files f"
        " JOIN file_keys c ON c.file_id = f.id AND c.user_id = ?"
        " JOIN users u ON u.id = f.owner_id"
        " LEFT JOIN shares s ON s.file_id = f.id AND s.recipient_id = c.user_id"
        " WHERE c.level > ? AND f.trashed_at IS NULL AND (f.owner_id = c.user_id"
        "  OR (s.file_id IS NOT NULL AND s.revoked_at IS NULL AND s.dismissed_at IS NULL"
        "   AND u.banned_at IS NULL))"
        " ORDER BY f.uploaded_at DESC, f.rowid DESC",
        (uid, level),
    ).fetchall()
    return mine, shared, cover


def cover_lists():
    """For the Duress page: the current user's files at the session's level,
    owned or received, and the cover files one level down, which are the
    ones it can move between."""
    db, uid, level = get_db(), g.user["id"], g.level

    def at(lvl):
        return db.execute(
            "SELECT f.id, f.filename, u.username AS owner FROM files f"
            " JOIN file_keys c ON c.file_id = f.id AND c.user_id = ?"
            " JOIN users u ON u.id = f.owner_id"
            " LEFT JOIN shares s ON s.file_id = f.id AND s.recipient_id = c.user_id"
            " WHERE c.level = ? AND f.trashed_at IS NULL AND (f.owner_id = c.user_id"
            "  OR (s.file_id IS NOT NULL AND s.revoked_at IS NULL AND s.dismissed_at IS NULL))"
            " ORDER BY f.filename",
            (uid, lvl),
        ).fetchall()

    return at(level), at(level + 1)


def cover_changed():
    """When the cover files last changed, as UTC text, or None: a cover
    vault that never changes is a tell of its own."""
    return get_db().execute(
        "SELECT MAX(since) FROM file_keys WHERE user_id = ? AND level > ?",
        (g.user["id"], g.level),
    ).fetchone()[0]


def move_files(keys, file_ids, down):
    """Move the current user's copies of these files' keys from the
    session's level to the next one down, or back up. Each copy is opened
    and encrypted again to the other level's public key, so it takes the
    keys the password opened, and only copies at the level they move from
    are touched. Level 2's go to the key pair below it, which no password
    opens, so it moves files like the levels above. Returns how many
    moved."""
    level, uid, db = g.level, g.user["id"], get_db()
    source, target = (level, level + 1) if down else (level + 1, level)
    moved = 0
    for file_id in file_ids:
        copy = db.execute(
            "SELECT wrapped_key FROM file_keys WHERE file_id = ? AND user_id = ? AND level = ?",
            (file_id, uid, source),
        ).fetchone()
        if copy is None:
            continue
        key = unwrap_file_key(keys.private[source], copy["wrapped_key"], file_id, uid, source)
        _store(file_id, uid, key, target)
        moved += 1
    db.commit()
    return moved


def _unused_row():
    """What a level without a password holds: the hash of a random secret,
    a salt, and random bytes the length of a lock."""
    return (hash_password(secrets.token_urlsafe(32)), os.urandom(16), unused_lock())


def _clear(policy, level, row):
    get_db().execute(
        "UPDATE credentials SET password_hash = ?, kdf_salt = ?, lock = ? WHERE id = ?",
        (*row, policy.rows[level]),
    )
    policy.modes[level] = COVER
    policy.active_from[level] = 0


def set_duress(keys, password, mode):
    """Give the level below the session's (from level 0, level 1; from
    level 1, level 2) the duress password, locking that level's own key,
    which keys reach, and clear any password further down: the chain below
    starts anew, so a password a coercer set there does not outlive this
    one. mode is "cover" or "wipe". At level 2, the last a password opens,
    the password opens nothing: only its hash is kept, for the Password
    page, and the page answers the same. Every level does the same Argon2
    work, so the time taken says nothing either."""
    user, lower = g.user, g.level + 1
    salt = os.urandom(16)
    password_hash = hash_password(password)
    if lower < LEVELS:
        lock = lock_key(keys.private[lower], password, salt, lock_aad(user["id"], lower))
    else:
        derive_key(password, salt)
    spares = [_unused_row() for _ in range(LEVELS - 2)]

    def change(policy):
        _end_sessions_below(user["id"])
        if lower >= LEVELS:
            policy.beneath = password_hash
            return
        policy.beneath = ""
        get_db().execute(
            "UPDATE credentials SET password_hash = ?, kdf_salt = ?, lock = ? WHERE id = ?",
            (password_hash, salt, lock, policy.rows[lower]),
        )
        policy.modes[lower] = MODES[mode]
        # it starts to work later, at every level alike, so nobody can test
        # on the spot what setting one did
        policy.active_from[lower] = int(time.time()) + current_app.config["DURESS_DELAY"]
        for below, row in zip(range(lower + 1, LEVELS), spares):
            _clear(policy, below, row)

    update_policy(user["id"], change)


def _end_sessions_below(user_id):
    """End the account's sessions at the levels below the session's: their
    passwords just changed, and a session must never be told its own
    password is wrong. Ending is what a session does anyway."""
    get_db().execute(
        "DELETE FROM sessions WHERE user_id = ? AND level > ?", (user_id, g.level)
    )


def remove_duress():
    """Take the password of every level below the session's away: each holds
    the hash of a random secret and an unused lock again, and the one saved
    at level 2 goes. Their keys and files stay, under the levels above. The
    same work at every level."""
    user = g.user
    spares = [_unused_row() for _ in range(LEVELS - 1)]

    def change(policy):
        for below, row in zip(range(g.level + 1, LEVELS), spares):
            _clear(policy, below, row)
        policy.beneath = ""
        _end_sessions_below(user["id"])

    update_policy(user["id"], change)


def opens_below(password):
    """Whether password is the duress password of a level below the
    session's (a higher number), the one saved at level 2 included: a new
    password must not be one, or the duress password would open this level,
    and level 2 refuses the one saved there as the levels above refuse
    theirs. The levels above are never tried, so no form can test their
    passwords."""
    policy = open_policy(g.user)
    hashes = dict(get_db().execute(
        "SELECT id, password_hash FROM credentials WHERE user_id = ?", (g.user["id"],)
    ).fetchall())
    below = [hashes[policy.rows[lvl]] for lvl in range(g.level + 1, LEVELS)]
    if policy.beneath:
        below.append(policy.beneath)
    found = [check_password(stored, password) for stored in below]
    # the same number of checks at every level, so the time says nothing
    for _ in range(LEVELS - len(found)):
        check_password_of_unknown_user(password)
    return any(found)


def change_password(keys, password):
    """Lock the session's own level's key under a new password. The keys
    and every copy of a file key stay as they are. The account's other
    sessions at this level and below it end, those opened with the old
    password among them; the levels above are not touched."""
    user, level = g.user, g.level
    salt = os.urandom(16)
    row = (hash_password(password), salt,
           lock_key(keys.private[level], password, salt, lock_aad(user["id"], level)))
    db = get_db()
    db.execute(
        "UPDATE credentials SET password_hash = ?, kdf_salt = ?, lock = ? WHERE id = ?",
        (*row, open_policy(user).rows[level]),
    )
    db.execute(
        "DELETE FROM sessions WHERE user_id = ? AND level >= ? AND token_hash != ?",
        (user["id"], level, g.session_hash),
    )
    db.commit()


def _remove(paths):
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def wipe(user, level):
    """What a duress password in wipe mode does: destroy the files and the
    copies of file keys of the level just above its own, the level whose
    session set it. The keys stay: with the copies gone they open nothing
    of that level, and the levels below keep working, signing included.
    The rows go at once; the stored files are removed in the background,
    so a wipe takes no longer than a login."""
    target = level - 1
    db = get_db()
    # overwrite deleted rows with zeros instead of leaving them in free pages
    db.execute("PRAGMA secure_delete = ON")
    owned = [r["id"] for r in db.execute(
        "SELECT f.id FROM files f JOIN file_keys c ON c.file_id = f.id AND c.user_id = f.owner_id"
        " WHERE f.owner_id = ? AND c.level = ? AND f.trashed_at IS NULL",
        (user["id"], target),
    )]
    paths = []
    if target == 0:
        paths = [storage_path(file_id) for file_id in owned]
        for file_id in owned:
            db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    else:
        # armed by a duress session: trashed like its own deletes, so a
        # coercer cannot destroy for good what the real owner keeps there
        for file_id in owned:
            db.execute(
                "UPDATE files SET trashed_at = datetime('now'), trashed_level = ? WHERE id = ?",
                (level, file_id),
            )
    # copies of other people's file keys: the shares end with them. Never
    # the user's own: a trashed file keeps its key, to be restored
    for r in db.execute(
        "SELECT c.file_id FROM file_keys c JOIN files f ON f.id = c.file_id"
        " WHERE c.user_id = ? AND c.level = ? AND f.owner_id != c.user_id",
        (user["id"], target),
    ).fetchall():
        db.execute(
            "DELETE FROM file_keys WHERE file_id = ? AND user_id = ?", (r["file_id"], user["id"])
        )
        db.execute(
            "UPDATE shares SET revoked_at = datetime('now')"
            " WHERE file_id = ? AND recipient_id = ? AND revoked_at IS NULL",
            (r["file_id"], user["id"]),
        )
    db.commit()
    threading.Thread(target=_remove, args=(paths,), name="wipe", daemon=True).start()


def audit_rows(problems=False, before=None, limit=200):
    """Audit entries, newest first, as the current session sees them, or
    all of them at the server (console, command line).

    A session at level k > 0 does not see the rows its own account's
    sessions wrote at a level above (a smaller number), nor the rows others
    wrote about a file the account holds at a level above: the current
    copy says so, or the level recorded on the row once the file is gone.
    Rows no session wrote (registering, the server's commands) show at
    every level. A login at a level below the viewer's is its duress
    alarm; at level 0 and at the server, every duress login is one."""
    viewer = g.user["id"] if g.get("user") is not None else None
    level = g.level if viewer is not None else 0
    rows = get_db().execute(
        "SELECT a.*, u.username FROM audit_log a"
        " LEFT JOIN users u ON u.id = a.user_id"
        " LEFT JOIN files f ON f.id = a.file_id"
        " LEFT JOIN file_keys c ON c.file_id = f.id AND c.user_id = f.owner_id"
        # IS rather than =, so a row without a user or a file is not lost
        # to a NULL comparison
        " WHERE (:level = 0 OR NOT ("
        "  (a.user_id IS :viewer AND a.level IS NOT NULL AND a.level < :level)"
        "  OR (a.user_id IS NOT :viewer AND COALESCE(f.owner_id, a.subject_id) IS :viewer"
        "   AND COALESCE(c.level, a.subject_level, 0) < :level)))"
        " AND (:problems = 0 OR a.outcome IN ('failed', 'refused', 'denied', 'locked', 'mismatch')"
        "  OR (a.action = 'login' AND a.level > CASE WHEN a.user_id IS :viewer THEN :level ELSE 0 END))"
        " AND (:before IS NULL OR a.id < :before)"
        " ORDER BY a.id DESC LIMIT :limit",
        {"level": level, "viewer": viewer, "problems": int(problems), "before": before,
         "limit": limit},
    ).fetchall()
    return [_shown(dict(r), viewer, level) for r in rows]


def _shown(row, viewer, level):
    """A row as the viewer sees it. A duress login below the viewer's own
    level, or any duress login of someone else, is the alarm, with its mode
    and never its level number, which would tell a session that it is not
    the top. Any other login says nothing about its level."""
    if row["action"] == "login" and row["level"]:
        own_top = level if row["user_id"] == viewer else 0
        if row["level"] > own_top:
            row["outcome"] = "duress"
        else:
            row["detail"] = None
    return row


# --- two-factor login, kept per level (design revision 2, A1)
#
# Each level has its own: on, off, or inherited from the level above. A
# change in a session writes its own level only, so a duress session can
# turn it on, off, or replace the recovery codes without touching a real
# login. Level 0 is never inherited, and never reads the levels below it.

INHERIT, OFF, ON = 0, 1, 2
# mode, whether the level has recovery codes of its own, the secret in
# base32 (zero bytes when there is none) and the last time step used (0 for
# none): the same length for every level and account
_FACTOR = struct.Struct("<BB32sq")


def _factor_aad(user_id, level):
    return f"totp|{user_id}|{level}".encode()


def _seal_factor(user_id, level, mode, own=False, secret=None, step=None):
    data = _FACTOR.pack(mode, 1 if own else 0, (secret or "").encode(), step or 0)
    return encrypt(subkey(master_key(), "totp-secret"), data, _factor_aad(user_id, level))


def _factors(user_id):
    """Every level's two-factor record, all read and opened each time, so
    finding one level's costs the same at every level."""
    out = {}
    for row in get_db().execute(
        "SELECT level, sealed FROM two_factor WHERE user_id = ?", (user_id,)
    ).fetchall():
        data = decrypt(subkey(master_key(), "totp-secret"), row["sealed"],
                       _factor_aad(user_id, row["level"]))
        mode, own, secret, step = _FACTOR.unpack(data)
        out[row["level"]] = {
            "mode": mode, "own": bool(own), "secret": secret.rstrip(b"\0").decode() or None,
            "step": step or None, "sealed": row["sealed"],
        }
    return out


def _holder(factors, level, codes=False):
    """The level whose record decides for this one: its own, unless it
    inherits, then the nearest level above that does not. Recovery codes go
    the same way, but a level that asked for codes of its own uses those
    while still inheriting the secret."""
    for lvl in range(level, 0, -1):
        f = factors[lvl]
        if f["mode"] != INHERIT or (codes and f["own"]):
            return lvl
    return 0


def _factor_state(user_id, level):
    factors = _factors(user_id)
    holder = _holder(factors, level)
    f = factors[holder]
    return {"on": f["mode"] == ON, "secret": f["secret"], "step": f["step"]}


def two_factor():
    """The session's two-factor login as it sees it: whether it is on, the
    secret and the last time step used."""
    return _factor_state(g.user["id"], g.level)


def two_factor_at(user_id, level):
    """The two-factor login a login at this level must pass."""
    return _factor_state(user_id, level)


def two_factor_of(user_id):
    """The account's own two-factor login, the real password's: for the
    console and the server's commands."""
    return _factor_state(user_id, 0)


def pending_two_factor(user_id, blob):
    """The two-factor login of a login waiting for its code."""
    return _factor_state(user_id, pending_level(user_id, blob))


def _write_factor(user_id, level, old, mode, own, secret, step):
    """Write a level's record only over the one read: compare and swap, so
    two requests can never both use one code. Returns whether it wrote."""
    cur = get_db().execute(
        "UPDATE two_factor SET sealed = ? WHERE user_id = ? AND level = ? AND sealed = ?",
        (_seal_factor(user_id, level, mode, own, secret, step), user_id, level, old),
    )
    return cur.rowcount == 1


def _store_codes(user_id, level, code_hashes):
    db = get_db()
    db.execute("DELETE FROM totp_recovery WHERE user_id = ? AND level = ?", (user_id, level))
    db.executemany(
        "INSERT INTO totp_recovery (user_id, level, code_hash) VALUES (?, ?, ?)",
        [(user_id, level, h) for h in code_hashes],
    )


def turn_two_factor_on(secret, step, code_hashes):
    """Two-factor login on for the session's own level, with this secret
    and these recovery codes; no other level changes. The caller commits."""
    uid, level = g.user["id"], g.level
    f = _factors(uid)[level]
    _write_factor(uid, level, f["sealed"], ON, True, secret, step)
    _store_codes(uid, level, code_hashes)


def turn_two_factor_off():
    """Off for the session's own level only, its recovery codes gone. The
    caller commits."""
    uid, level = g.user["id"], g.level
    f = _factors(uid)[level]
    _write_factor(uid, level, f["sealed"], OFF, False, None, None)
    get_db().execute("DELETE FROM totp_recovery WHERE user_id = ? AND level = ?", (uid, level))


def replace_two_factor_codes(code_hashes):
    """New recovery codes for the session's own level, which keeps
    inheriting the secret if it did. The caller commits."""
    uid, level = g.user["id"], g.level
    f = _factors(uid)[level]
    if not f["own"]:
        _write_factor(uid, level, f["sealed"], f["mode"], True, f["secret"], f["step"])
    _store_codes(uid, level, code_hashes)


def _use_step(user_id, level, step):
    """Record a code's time step on the level that holds the secret, unless
    it or a later one was used there already. Commits."""
    for _ in range(5):
        factors = _factors(user_id)
        holder = _holder(factors, level)
        f = factors[holder]
        if f["step"] is not None and f["step"] >= step:
            return False
        if _write_factor(user_id, holder, f["sealed"], f["mode"], f["own"], f["secret"], step):
            get_db().commit()
            return True
    return False


def use_step(step):
    return _use_step(g.user["id"], g.level, step)


def pending_use_step(user_id, blob, step):
    return _use_step(user_id, pending_level(user_id, blob), step)


def pending_use_code(user_id, blob, code_hash):
    """Use one of the recovery codes a login waiting for its code may take:
    its level's own set, or the one it inherits. Once each. Commits."""
    holder = _holder(_factors(user_id), pending_level(user_id, blob), codes=True)
    db = get_db()
    cur = db.execute(
        "UPDATE totp_recovery SET used_at = datetime('now')"
        " WHERE user_id = ? AND level = ? AND code_hash = ? AND used_at IS NULL",
        (user_id, holder, code_hash),
    )
    db.commit()
    return cur.rowcount == 1


def clear_two_factor(user_id):
    """At the server, for a lost phone: off at level 0, inherited again at
    every other level, no recovery codes left. Returns whether any level
    had it on or codes of its own. The caller commits."""
    factors = _factors(user_id)
    was_on = any(f["mode"] == ON or f["own"] for f in factors.values())
    for level, f in factors.items():
        _write_factor(user_id, level, f["sealed"], OFF if level == 0 else INHERIT, False, None, None)
    get_db().execute("DELETE FROM totp_recovery WHERE user_id = ?", (user_id,))
    return was_on


def reseal_factors(db, old, new):
    """For keyring.reencrypt: every two-factor record of the database being
    built, attached as fresh, sealed again under the new master key."""
    old_key, new_key = subkey(old, "totp-secret"), subkey(new, "totp-secret")
    for row in db.execute("SELECT user_id, level, sealed FROM fresh.two_factor").fetchall():
        aad = _factor_aad(row["user_id"], row["level"])
        db.execute(
            "UPDATE fresh.two_factor SET sealed = ? WHERE user_id = ? AND level = ?",
            (encrypt(new_key, decrypt(old_key, row["sealed"], aad), aad),
             row["user_id"], row["level"]),
        )

