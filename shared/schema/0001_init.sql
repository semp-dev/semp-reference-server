-- semp-reference-server: SQLite schema (v0001 / initial)
--
-- Source of truth for both impl/go and impl/ts. The Go impl carries
-- an inline copy in impl/go/internal/store/schema.go because Go's
-- go:embed cannot reach outside its module; that copy MUST stay
-- byte-identical to this file. The TS impl loads this file directly
-- via fs.readFileSync.
--
-- Migration tracking:
--   schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT)
-- Both impls create this table on first init and record (1, now())
-- after applying this file.

CREATE TABLE IF NOT EXISTS domain_keys (
    domain      TEXT NOT NULL,
    key_type    TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    public_key  BLOB NOT NULL,
    private_key BLOB,
    key_salt    BLOB,
    key_nonce   BLOB,
    key_id      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT,
    revocation_reason  TEXT,
    replacement_key_id TEXT,
    PRIMARY KEY (domain, key_type)
);

CREATE TABLE IF NOT EXISTS user_keys (
    address     TEXT NOT NULL,
    key_type    TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    public_key  BLOB NOT NULL,
    private_key BLOB,
    key_salt    BLOB,
    key_nonce   BLOB,
    key_id      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT,
    revocation_reason  TEXT,
    replacement_key_id TEXT,
    PRIMARY KEY (address, key_type, key_id)
);

CREATE TABLE IF NOT EXISTS device_certificates (
    device_key_id       TEXT NOT NULL PRIMARY KEY,
    user_id             TEXT NOT NULL,
    device_id           TEXT NOT NULL,
    issuing_device_key_id TEXT NOT NULL,
    scope_json          TEXT NOT NULL,
    issued_at           TEXT NOT NULL,
    expires_at          TEXT,
    signature_json      TEXT NOT NULL,
    device_public_key   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS block_entries (
    id           TEXT NOT NULL PRIMARY KEY,
    user_id      TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    entity_value TEXT NOT NULL,
    acknowledgment TEXT NOT NULL DEFAULT 'rejected',
    reason       TEXT,
    scope        TEXT NOT NULL DEFAULT 'all',
    created_at   TEXT NOT NULL,
    expires_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_block_user ON block_entries(user_id);

CREATE TABLE IF NOT EXISTS inbox (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    address   TEXT NOT NULL,
    payload   BLOB NOT NULL,
    stored_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_inbox_address ON inbox(address);

CREATE TABLE IF NOT EXISTS delivered_ids (
    address      TEXT NOT NULL,
    envelope_id  TEXT NOT NULL,
    delivered_at TEXT NOT NULL,
    PRIMARY KEY (address, envelope_id)
);
