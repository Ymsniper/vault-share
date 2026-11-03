DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS file_keys;
DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS encryption_keys;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS invites;
DROP TABLE IF EXISTS invite_defaults;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    -- TOTP secret encrypted under a key derived from the master key, NULL
    -- while two-factor login is off; last_step stops a code being reused
    totp_secret BLOB,
    totp_last_step INTEGER,
    -- every account has a duress slot, set or not: an unused one holds the
    -- hash of a random secret, and the mode is encrypted, so the database
    -- does not show who set a duress password or what it does
    duress_hash TEXT NOT NULL,
    duress_policy BLOB NOT NULL,
    -- the invite code the account was created with
    invite_id INTEGER NOT NULL REFERENCES invites (id),
    -- set while the account is banned: it cannot log in and its files are
    -- hidden from everyone; nothing is deleted, so a ban can be lifted
    banned_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
    cancelled_at TEXT
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
    -- opened with the duress password: the account shows as empty
    duress INTEGER NOT NULL DEFAULT 0,
    -- a two-factor secret this session is enrolling, sealed; it belongs to
    -- the session, so no other session of the account can read it
    totp_pending BLOB
);

-- the ECDSA private key, encrypted with AES-256-GCM under a key derived
-- from the user's password (Argon2id with kdf_salt)
CREATE TABLE user_keys (
    user_id INTEGER PRIMARY KEY REFERENCES users (id),
    kdf_salt BLOB NOT NULL,
    enc_private_key BLOB NOT NULL
);

-- the X25519 key pair that receives file keys (security/hybrid.py), kept
-- apart from the signing key; its private key is locked the same way
CREATE TABLE encryption_keys (
    user_id INTEGER PRIMARY KEY REFERENCES users (id),
    public_key BLOB NOT NULL,
    kdf_salt BLOB NOT NULL,
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
    -- HMAC of id, owner_id, sha256, size, mime, checked and uploaded_at,
    -- so editing them is detected
    record_mac BLOB NOT NULL,
    signature BLOB NOT NULL,
    cert_id INTEGER NOT NULL REFERENCES certificates (id),
    -- the signature is judged at this time; the app writes it, so the
    -- HMAC covers exactly what is stored
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE shares (
    file_id TEXT NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users (id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    PRIMARY KEY (file_id, recipient_id)
);

-- the file's own AES key, encrypted with HPKE to each person who may open
-- the file: its owner and every recipient of an active share. Only that
-- person's private key opens their copy; the master key does not.
CREATE TABLE file_keys (
    file_id TEXT NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id),
    wrapped_key BLOB NOT NULL,
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
    ip TEXT
);
