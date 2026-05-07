package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
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
-- Defensive ADD COLUMN for databases created before semp-go v0.4.0 added
-- DevicePublicKey to the DeviceCertificate struct. SQLite ignores
-- duplicates of an already-present column at this guard's level so the
-- statement is safe to re-run on every startup; we tolerate the error
-- raised on existing schemas via the InitDB wrapper.

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
`

// InitDB opens or creates a SQLite database at path, applies the schema,
// and returns the handle. The database uses WAL mode for concurrent reads.
func InitDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema init: %w", err)
	}
	// Apply post-schema migrations. ALTER TABLE ADD COLUMN is the
	// minimal-disruption way to grow existing databases; SQLite raises a
	// "duplicate column name" error when the column already exists, which
	// we swallow.
	for _, alter := range []string{
		`ALTER TABLE device_certificates ADD COLUMN device_public_key TEXT NOT NULL DEFAULT ''`,
	} {
		if _, err := db.Exec(alter); err != nil && !isDuplicateColumnErr(err) {
			db.Close()
			return nil, fmt.Errorf("store: migration %q: %w", alter, err)
		}
	}
	return db, nil
}

// isDuplicateColumnErr returns true when err is the SQLite error raised
// for an ALTER TABLE ADD COLUMN whose column already exists. The error
// text is matched by substring because modernc.org/sqlite does not
// surface the underlying SQLITE_ERROR code as a typed constant.
func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "duplicate column name") || contains(msg, "already exists")
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return needle == ""
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
