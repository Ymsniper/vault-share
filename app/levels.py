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
# password starts to work and since when its window is open (epoch seconds,
# 0 for never). Level 0's mode and times are never used.
_FORMAT = "<3q3c3q3q"


@dataclass
class Policy:
    rows: list
    modes: list
    active_from: list
    window_since: list


def _aad(username):
    # as before the levels, so keyring.reencrypt moves it unchanged
    return f"duress:{username}".encode()


def seal_policy(username, policy):
    data = struct.pack(
        _FORMAT, *policy.rows, *policy.modes, *policy.active_from, *policy.window_since
    )
    return encrypt(subkey(master_key(), "duress-policy"), data, _aad(username))


def open_policy(user):
    data = decrypt(subkey(master_key(), "duress-policy"), user["duress_policy"], _aad(user["username"]))
    values = struct.unpack(_FORMAT, data)
    return Policy(list(values[0:3]), list(values[3:6]), list(values[6:9]), list(values[9:12]))


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
    policy = Policy(rows, [COVER] * LEVELS, [0] * LEVELS, [0] * LEVELS)
    db.execute(
        "UPDATE users SET duress_policy = ? WHERE id = ?", (seal_policy(username, policy), user_id)
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
    windows of the levels below its own (a higher number). Returns the
    earliest start among those it closed, as UTC text, or None. The policy
    is written again whatever the level, so every login makes the same
    writes."""
    now = int(time.time())

    def change(policy):
        closed = []
        for lower in range(level + 1, LEVELS):
            if policy.window_since[lower]:
                closed.append(policy.window_since[lower])
                policy.window_since[lower] = 0
        if level and not policy.window_since[level]:
            policy.window_since[level] = now
        return min(closed, default=None)

    since = update_policy(user["id"], change)
    purge_trash()
    if since is None:
        return None
    return datetime.datetime.fromtimestamp(since, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S")


def review():
    """What happened in the duress windows the session's login closed, or
    None when it closed none: what the levels below it (a higher number) did
    since the earliest of them opened."""
    since = g.user["session_review_since"]
    if since is None:
        return None
    db, uid, level = get_db(), g.user["id"], g.level
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
        "trashed": db.execute(
            "SELECT id, filename, trashed_at FROM files"
            " WHERE owner_id = ? AND trashed_level > ? AND trashed_at >= ? ORDER BY trashed_at",
            params,
        ).fetchall(),
        "planted": _planted(*params),
        "arrived": _arrived(*params),
    }


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
        db.execute("UPDATE files SET trashed_at = NULL, trashed_level = NULL WHERE id = ?", (r["id"],))
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
        copy = my_copy(r["id"])
        key = unwrap_file_key(
            keys.private[copy["level"]], copy["wrapped_key"], r["id"], g.user["id"], copy["level"]
        )
        _store(r["id"], g.user["id"], key, g.level)
    get_db().commit()
    return len(found)


def purge_trash():
    """Remove the files duress sessions deleted more than 30 days ago."""
    db = get_db()
    gone = [r["id"] for r in db.execute(
        "SELECT id FROM files WHERE trashed_at < datetime('now', ?)", (f"-{TRASH_DAYS} days",)
    )]
    if not gone:
        return
    db.execute("PRAGMA secure_delete = ON")
    paths = [storage_path(file_id) for file_id in gone]
    for file_id in gone:
        db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    _remove(paths)


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
        " SET wrapped_key = excluded.wrapped_key, level = excluded.level, since = datetime('now')",
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
    nothing changes, and the page answers the same. Every level does the
    same Argon2 work, so the time taken says nothing either."""
    user, lower = g.user, g.level + 1
    salt = os.urandom(16)
    password_hash = hash_password(password)
    if lower < LEVELS:
        lock = lock_key(keys.private[lower], password, salt, lock_aad(user["id"], lower))
    else:
        derive_key(password, salt)
    spares = [_unused_row() for _ in range(LEVELS - 2)]
    if lower >= LEVELS:
        return

    def change(policy):
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
        _end_sessions_below(user["id"])

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
    the hash of a random secret and an unused lock again. Their keys and
    files stay, under the levels above. The same work at every level."""
    user = g.user
    spares = [_unused_row() for _ in range(LEVELS - 1)]

    def change(policy):
        for below, row in zip(range(g.level + 1, LEVELS), spares):
            _clear(policy, below, row)
        _end_sessions_below(user["id"])

    update_policy(user["id"], change)


def opens_below(password):
    """Whether password opens one of the levels below the session's (a
    higher number): a new password must not be a duress password, or the
    duress password would open this level. The levels above are never
    tried, so no form can test their passwords."""
    policy = open_policy(g.user)
    rows = get_db().execute(
        "SELECT id, password_hash FROM credentials WHERE user_id = ?", (g.user["id"],)
    ).fetchall()
    below = {policy.rows[lvl] for lvl in range(g.level + 1, LEVELS)}
    found = [check_password(r["password_hash"], password) for r in rows if r["id"] in below]
    # the same number of checks at every level, so the time says nothing
    for _ in range(LEVELS - 1 - len(found)):
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
