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
    signature_json      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inbox (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    address   TEXT NOT NULL,
    payload   BLOB NOT NULL,
    stored_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_inbox_address ON inbox(address);
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
	return db, nil
}
