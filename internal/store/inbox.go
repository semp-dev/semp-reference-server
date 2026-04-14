package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"semp.dev/semp-go/delivery"
)

// SQLiteInbox provides crash-recovery durability around the in-memory
// delivery.Inbox that inboxd.Server requires. Envelopes stored through
// this wrapper are written to both SQLite and the in-memory inbox.
//
// The library's inboxd.Server writes directly to *delivery.Inbox via its
// Inbox field. Those writes hit the in-memory queue only. On startup
// LoadPending rehydrates the in-memory queue from SQLite.
//
// A mutex serializes Store and Drain to prevent races on the same address
// (security audit finding 4.3).
type SQLiteInbox struct {
	mu  sync.Mutex
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
// Duplicate payloads (by hash) for the same address within the dedup
// window are silently dropped (security audit finding 3.3).
func (i *SQLiteInbox) Store(address string, payload []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()

	// Dedup check: compute a hash of the payload and reject duplicates
	// seen within the last 24 hours.
	hash := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(hash[:])
	if i.HasEnvelope(address, hashHex) {
		return
	}

	if _, err := i.db.Exec(
		`INSERT INTO inbox (address, payload) VALUES (?, ?)`,
		address, payload); err != nil {
		log.Printf("store: inbox insert %s: %v", address, err)
	}
	i.mem.Store(address, payload)

	// Record the envelope hash for dedup.
	if _, err := i.db.Exec(
		`INSERT OR IGNORE INTO delivered_ids (address, envelope_id, delivered_at) VALUES (?, ?, ?)`,
		address, hashHex, time.Now().UTC().Format(time.RFC3339)); err != nil {
		log.Printf("store: delivered_ids insert %s: %v", address, err)
	}
}

// Drain returns all queued envelopes from the in-memory inbox and
// removes the corresponding rows from SQLite.
func (i *SQLiteInbox) Drain(address string) [][]byte {
	i.mu.Lock()
	defer i.mu.Unlock()

	out := i.mem.Drain(address)
	if _, err := i.db.Exec(`DELETE FROM inbox WHERE address = ?`, address); err != nil {
		log.Printf("store: inbox drain %s: %v", address, err)
	}
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
			if _, err := i.db.Exec(
				`INSERT INTO inbox (address, payload) VALUES (?, ?)`,
				addr, payload); err != nil {
				log.Printf("store: persist pending %s: %v", addr, err)
			}
		}
	}
}

// HasEnvelope reports whether an envelope with the given ID (payload hash)
// has already been delivered to address within the dedup window.
// Caller must hold i.mu.
func (i *SQLiteInbox) HasEnvelope(address, envelopeID string) bool {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	var count int
	err := i.db.QueryRow(
		`SELECT COUNT(*) FROM delivered_ids WHERE address = ? AND envelope_id = ? AND delivered_at > ?`,
		address, envelopeID, cutoff).Scan(&count)
	if err != nil {
		log.Printf("store: HasEnvelope query %s: %v", address, err)
		return false
	}
	return count > 0
}

// CleanupDeliveredIDs removes dedup entries older than 24 hours.
func (i *SQLiteInbox) CleanupDeliveredIDs() {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	if _, err := i.db.Exec(`DELETE FROM delivered_ids WHERE delivered_at <= ?`, cutoff); err != nil {
		log.Printf("store: cleanup delivered_ids: %v", err)
	}
}

// Close is a no-op; the database handle is owned by the caller.
func (i *SQLiteInbox) Close() error { return nil }
