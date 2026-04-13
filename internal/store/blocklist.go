package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/delivery"
)

// SQLiteBlockList implements delivery.BlockListLookup backed by SQLite.
type SQLiteBlockList struct {
	db *sql.DB
}

// NewSQLiteBlockList wraps an initialised database.
func NewSQLiteBlockList(db *sql.DB) *SQLiteBlockList {
	return &SQLiteBlockList{db: db}
}

// Lookup returns the block list for recipient.
func (bl *SQLiteBlockList) Lookup(ctx context.Context, recipient string) (*delivery.BlockList, error) {
	rows, err := bl.db.QueryContext(ctx,
		`SELECT id, entity_type, entity_value, acknowledgment, reason, scope, created_at, expires_at
		   FROM block_entries WHERE user_id = ?`, recipient)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := &delivery.BlockList{UserID: recipient}
	for rows.Next() {
		var (
			id, entType, entValue, ack, scope, createdStr string
			reason, expiresStr                            sql.NullString
		)
		if err := rows.Scan(&id, &entType, &entValue, &ack, &reason, &scope, &createdStr, &expiresStr); err != nil {
			return nil, err
		}
		created, _ := time.Parse(time.RFC3339, createdStr)
		entity := delivery.Entity{Type: delivery.EntityType(entType)}
		switch entity.Type {
		case delivery.EntityUser:
			entity.Address = entValue
		case delivery.EntityDomain:
			entity.Domain = entValue
		case delivery.EntityServer:
			entity.Hostname = entValue
		}
		entry := delivery.BlockEntry{
			ID:     id,
			Entity: entity,
			Acknowledgment: semp.Acknowledgment(ack),
			Scope:          delivery.Scope(scope),
			CreatedAt:      created,
		}
		if reason.Valid {
			entry.Reason = reason.String
		}
		if expiresStr.Valid {
			t, _ := time.Parse(time.RFC3339, expiresStr.String)
			entry.ExpiresAt = &t
		}
		list.Entries = append(list.Entries, entry)
	}
	return list, rows.Err()
}

// AddEntry adds a block entry for a user.
func (bl *SQLiteBlockList) AddEntry(ctx context.Context, userID string, entry delivery.BlockEntry) (string, error) {
	if entry.ID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		entry.ID = hex.EncodeToString(b)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var expires *string
	if entry.ExpiresAt != nil {
		s := entry.ExpiresAt.Format(time.RFC3339)
		expires = &s
	}
	var entityValue string
	switch entry.Entity.Type {
	case delivery.EntityUser:
		entityValue = entry.Entity.Address
	case delivery.EntityDomain:
		entityValue = entry.Entity.Domain
	case delivery.EntityServer:
		entityValue = entry.Entity.Hostname
	}
	_, err := bl.db.ExecContext(ctx,
		`INSERT INTO block_entries (id, user_id, entity_type, entity_value, acknowledgment, reason, scope, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, userID, string(entry.Entity.Type), entityValue,
		string(entry.Acknowledgment), entry.Reason, string(entry.Scope), now, expires)
	return entry.ID, err
}

// RemoveEntry removes a block entry by ID.
func (bl *SQLiteBlockList) RemoveEntry(ctx context.Context, entryID string) error {
	_, err := bl.db.ExecContext(ctx, `DELETE FROM block_entries WHERE id = ?`, entryID)
	return err
}

// ListEntries returns all block entries for a user.
func (bl *SQLiteBlockList) ListEntries(ctx context.Context, userID string) ([]delivery.BlockEntry, error) {
	list, err := bl.Lookup(ctx, userID)
	if err != nil {
		return nil, err
	}
	return list.Entries, nil
}
