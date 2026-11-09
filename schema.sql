-- TrustVault schema (SQLite). Idempotent: safe to run on every start.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  display_name  TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  active        INTEGER NOT NULL DEFAULT 1,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until  TEXT,
  created_at    TEXT NOT NULL
);

-- Only a SHA-256 of the bearer token is stored, so a DB leak does not leak live sessions.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS documents (
  id              TEXT PRIMARY KEY,            -- random uuid4 hex, never sequential
  name            TEXT NOT NULL,
  category        TEXT NOT NULL,
  owner_id        INTEGER NOT NULL REFERENCES users(id),
  current_version INTEGER NOT NULL,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  deleted_at      TEXT,                        -- soft delete
  deleted_by      INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS document_versions (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id       TEXT NOT NULL REFERENCES documents(id),
  version           INTEGER NOT NULL,
  storage_key       TEXT NOT NULL UNIQUE,      -- random; never derived from user input
  size              INTEGER NOT NULL,
  sha256            TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  uploaded_by       INTEGER NOT NULL REFERENCES users(id),
  created_at        TEXT NOT NULL,
  UNIQUE (document_id, version)
);

-- A grant is a row. Revoking sets revoked_at; history is kept.
CREATE TABLE IF NOT EXISTS grants (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id TEXT NOT NULL REFERENCES documents(id),
  user_id     INTEGER NOT NULL REFERENCES users(id),
  level       TEXT NOT NULL CHECK (level IN ('read','edit')),
  granted_by  INTEGER NOT NULL REFERENCES users(id),
  created_at  TEXT NOT NULL,
  revoked_at  TEXT,
  revoked_by  INTEGER REFERENCES users(id)
);
-- At most one ACTIVE grant per (document, user).
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_grant
  ON grants(document_id, user_id) WHERE revoked_at IS NULL;

-- Append-only, hash-chained (HMAC) audit log.
CREATE TABLE IF NOT EXISTS audit_log (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             TEXT NOT NULL,
  actor_id       INTEGER,
  actor_name     TEXT,
  action         TEXT NOT NULL,
  outcome        TEXT NOT NULL CHECK (outcome IN ('success','denied','failure')),
  document_id    TEXT,
  target_user_id INTEGER,
  ip             TEXT,
  detail         TEXT NOT NULL,
  prev_hash      TEXT NOT NULL,
  hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action, outcome);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
