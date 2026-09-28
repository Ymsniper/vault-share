DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS login_failures;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- only the SHA-256 of each session token is stored, so a copy of the
-- database does not give anyone a working session
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

-- recent failed logins, for the lockout; the full history is in audit_log
CREATE TABLE login_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip TEXT,
    at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- the ECDSA private key, encrypted with AES-256-GCM under a key derived
-- from the user's password (Argon2id with kdf_salt)
CREATE TABLE user_keys (
    user_id INTEGER PRIMARY KEY REFERENCES users (id),
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
    revoked_at TEXT
);

CREATE TABLE files (
    -- random UUID, also the file's name on disk
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users (id),
    filename TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    -- the file's own AES key, encrypted under the wrap key
    wrapped_key BLOB NOT NULL,
    -- HMAC of id, owner_id, sha256 and size, so editing them is detected
    record_mac BLOB NOT NULL,
    signature BLOB NOT NULL,
    cert_id INTEGER NOT NULL REFERENCES certificates (id),
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE shares (
    file_id TEXT NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users (id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT,
    PRIMARY KEY (file_id, recipient_id)
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
