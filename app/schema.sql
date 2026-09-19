DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users (id),
    filename TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE shares (
    file_id INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
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
    file_id INTEGER,
    outcome TEXT NOT NULL,
    detail TEXT,
    ip TEXT
);
