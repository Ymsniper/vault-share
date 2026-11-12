DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS file_keys;
DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS level_keys;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS totp_recovery;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS invite_defaults;

-- the version of this layout, for vault-share migrate
PRAGMA user_version = 1;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    is_admin INTEGER NOT NULL DEFAULT 0,
    -- TOTP secret encrypted under a key derived from the master key, NULL
    -- while two-factor login is off; last_step stops a code being reused
    totp_secret BLOB,
    totp_last_step INTEGER,
    -- sealed under the master key, always the same length (app/levels.py):
    -- which of the account's credentials is which level, and what each
    -- duress level does, so the database does not show who set one
    duress_policy BLOB NOT NULL,
    -- the invite code the account was created with
    invite_id INTEGER NOT NULL REFERENCES invites (id),
    -- set while the account is banned: it cannot log in and its files are
    -- hidden from everyone; nothing is deleted, so a ban can be lifted
    banned_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- codes that stand in for the phone at login, once each, for a lost phone;
-- only their SHA-256 is kept, and they are random, 80 bits, so a copy of the
-- database gives none of them away
CREATE TABLE totp_recovery (
    user_id INTEGER NOT NULL REFERENCES users (id),
    code_hash TEXT NOT NULL,
    used_at TEXT,
    PRIMARY KEY (user_id, code_hash)
);

-- one-time codes needed to register; only a SHA-256 of each code is kept,
-- so a copy of the database gives nobody a code that still works
CREATE TABLE invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL UNIQUE,
    -- the admin who made it, NULL when made at the server
    created_by INTEGER REFERENCES users (id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    -- how many accounts it may create, and how many it did
    max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 100),
    uses INTEGER NOT NULL DEFAULT 0 CHECK (uses <= max_uses),
    cancelled_at TEXT,
    -- the level of the session that made it; a session sees the codes made
    -- at its own level and the ones below it (a higher number)
    level INTEGER NOT NULL DEFAULT 0 CHECK (level BETWEEN 0 AND 2)
);

-- what a new code gets unless the server asks for other values; changed
-- only from the console or the command line, and only for codes made
-- afterwards: every code keeps the values it was made with
CREATE TABLE invite_defaults (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    uses INTEGER NOT NULL CHECK (uses BETWEEN 1 AND 100),
    -- 10 minutes to 90 days
    valid_minutes INTEGER NOT NULL CHECK (valid_minutes BETWEEN 10 AND 129600),
    -- accounts an admin's codes may create in 24 hours; 0 stops admin codes
    admin_per_day INTEGER NOT NULL CHECK (admin_per_day BETWEEN 0 AND 50)
);
INSERT INTO invite_defaults (id, uses, valid_minutes, admin_per_day) VALUES (1, 1, 10080, 5);

-- only the SHA-256 of each session token is stored, so a copy of the
-- database does not give anyone a working session
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    -- the level the session was opened at: 0 with the real password, 1 and
    -- 2 with a duress password (app/levels.py)
    level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 2),
    -- a two-factor secret this session is enrolling, sealed; it belongs to
    -- the session, so no other session of the account can read it
    totp_pending BLOB,
    -- when the login that opened this session closed duress windows: the
    -- earliest one's start, for the review of what happened in them
    review_since TEXT
);

-- the password of each of an account's three levels, in random order; the
-- sealed users.duress_policy says which row is which level. lock is the
-- level's X25519 private key, encrypted under Argon2id(password, kdf_salt).
-- A level without a password holds the hash of a random secret and random
-- bytes the length of a lock, so in here it looks like one with a password
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id),
    password_hash TEXT NOT NULL,
    kdf_salt BLOB NOT NULL,
    lock BLOB NOT NULL
);

-- each level's X25519 key pair (security/keychain.py), and at 3 the one
-- that keeps level 2's cover files, which no password opens; link is the
-- level's private key encrypted under the one above it, so a level's
-- password opens the levels below it and never the one above
CREATE TABLE level_keys (
    user_id INTEGER NOT NULL REFERENCES users (id),
    level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 3),
    public_key BLOB NOT NULL,
    link BLOB,
    PRIMARY KEY (user_id, level)
);

-- the ECDSA private key, encrypted under level 2's private key, which
-- every level's password reaches: all of them sign with one certificate
CREATE TABLE signing_keys (
    user_id INTEGER PRIMARY KEY REFERENCES users (id),
    enc_private_key BLOB NOT NULL
);

CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id),
    serial TEXT NOT NULL UNIQUE,
    pem TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    revoked_at TEXT,
    -- files uploaded from this time on fail; earlier ones, signed while the
    -- key was trusted, stay valid. Set with revoked_at, often to the same time
    invalid_from TEXT
);

CREATE TABLE files (
    -- random UUID, also the file's name on disk
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users (id),
    filename TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mime TEXT NOT NULL,
    -- 0 for an archive: its signature was checked, not what it holds
    checked INTEGER NOT NULL CHECK (checked IN (0, 1)),
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    -- HMAC of the columns above and below but the trash marks, which
    -- change (security/integrity.py), so editing any of them is detected
    record_mac BLOB NOT NULL,
    signature BLOB NOT NULL,
    cert_id INTEGER NOT NULL REFERENCES certificates (id),
    -- the signature is judged at this time; the app writes it, so the
    -- HMAC covers exactly what is stored
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- set when a duress session deleted the file: hidden from everyone,
    -- kept 30 days for the real owner, then removed (app/levels.py)
    trashed_at TEXT,
    trashed_level INTEGER
);

CREATE TABLE shares (
    file_id TEXT NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users (id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    -- set when the recipient took the file off their own list: the owner
    -- still sees the share, and sharing again brings it back
    dismissed_at TEXT,
    PRIMARY KEY (file_id, recipient_id)
);

-- the file's own AES key, encrypted with HPKE to each person who may open
-- the file: its owner and every recipient of an active share. Only that
-- person's private key opens their copy; the master key does not.
CREATE TABLE file_keys (
    file_id TEXT NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id),
    wrapped_key BLOB NOT NULL,
    -- the level whose public key the copy is encrypted to: a session sees
    -- and opens the copies at its own level and the ones below it
    level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 3),
    -- when the copy was made or moved to its level
    since TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (file_id, user_id)
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL DEFAULT (datetime('now')),
    user_id INTEGER REFERENCES users (id),
    action TEXT NOT NULL,
    file_id TEXT,
    outcome TEXT NOT NULL,
    detail TEXT,
    ip TEXT,
    -- the level of the session that wrote it, NULL when no session did
    -- (registering, the server's commands); a login row at level 1 or 2 is
    -- the silent alarm
    level INTEGER,
    -- for a file, its owner and the level of the owner's copy then: the
    -- level log rule judges by them once the file is gone (app/levels.py)
    subject_id INTEGER,
    subject_level INTEGER
);
