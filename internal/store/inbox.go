package store

import (
	"database/sql"

	"semp.dev/semp-go/delivery"
)

// SQLiteInbox provides crash-recovery durability around the in-memory
// delivery.Inbox that inboxd.Server requires. Envelopes stored through
// this wrapper are written to both SQLite and the in-memory inbox.
//
// The library's inboxd.Server writes directly to *delivery.Inbox via its
// Inbox field. Those writes hit the in-memory queue only. On startup
// LoadPending rehydrates the in-memory queue from SQLite.
type SQLiteInbox struct {
	db  *sql.DB
	mem *delivery.Inbox
}

// NewSQLiteInbox creates a new inbox backed by the given database.
func NewSQLiteInbox(db *sql.DB) *SQLiteInbox {
	return &SQLiteInbox{
		db:  db,
		mem: delivery.NewInbox(),
	}
}

// MemInbox returns the in-memory inbox to pass to inboxd.Server.Inbox.
func (i *SQLiteInbox) MemInbox() *delivery.Inbox { return i.mem }

// Store persists an envelope to SQLite and the in-memory inbox.
func (i *SQLiteInbox) Store(address string, payload []byte) {
	_, _ = i.db.Exec(
		`INSERT INTO inbox (address, payload) VALUES (?, ?)`,
		address, payload)
	i.mem.Store(address, payload)
}

// Drain returns all queued envelopes from the in-memory inbox and
// removes the corresponding rows from SQLite.
func (i *SQLiteInbox) Drain(address string) [][]byte {
	out := i.mem.Drain(address)
	_, _ = i.db.Exec(`DELETE FROM inbox WHERE address = ?`, address)
	return out
}

// LoadPending rehydrates the in-memory inbox from SQLite on startup.
func (i *SQLiteInbox) LoadPending() error {
	rows, err := i.db.Query(`SELECT address, payload FROM inbox ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var address string
		var payload []byte
		if err := rows.Scan(&address, &payload); err != nil {
			return err
		}
		i.mem.Store(address, payload)
	}
	return rows.Err()
}

// PersistPending writes all in-memory envelopes for the given addresses
// to SQLite. Called during graceful shutdown.
func (i *SQLiteInbox) PersistPending(addresses []string) {
	for _, addr := range addresses {
		items := i.mem.Drain(addr)
		for _, payload := range items {
			_, _ = i.db.Exec(
				`INSERT INTO inbox (address, payload) VALUES (?, ?)`,
				addr, payload)
		}
	}
}

// Close is a no-op; the database handle is owned by the caller.
func (i *SQLiteInbox) Close() error { return nil }
