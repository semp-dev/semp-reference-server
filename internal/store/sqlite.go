package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"time"

	"semp.dev/semp-go/keys"
)

// SQLiteStore implements keys.Store and inboxd.SharedStore backed by SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore wraps an initialised database.
func NewSQLiteStore(db *sql.DB) *SQLiteStore {
	return &SQLiteStore{db: db}
}

// LookupDomainKey returns the current signing key for domain.
func (s *SQLiteStore) LookupDomainKey(ctx context.Context, domain string) (*keys.Record, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT algorithm, public_key, key_id, created_at, expires_at,
		        revoked_at, revocation_reason, replacement_key_id
		   FROM domain_keys
		  WHERE domain = ? AND key_type = 'signing'`,
		domain)
	return scanDomainRow(row, domain)
}

// LookupDomainEncryptionKey returns the domain encryption key.
func (s *SQLiteStore) LookupDomainEncryptionKey(ctx context.Context, domain string) (*keys.Record, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT algorithm, public_key, key_id, created_at, expires_at,
		        revoked_at, revocation_reason, replacement_key_id
		   FROM domain_keys
		  WHERE domain = ? AND key_type = 'encryption'`,
		domain)
	return scanDomainRow(row, domain)
}

func scanDomainRow(row *sql.Row, domain string) (*keys.Record, error) {
	var (
		algorithm, keyID, createdStr, expiresStr string
		pubBytes                                 []byte
		revokedAt, revokeReason, replacementID   sql.NullString
	)
	err := row.Scan(&algorithm, &pubBytes, &keyID, &createdStr, &expiresStr,
		&revokedAt, &revokeReason, &replacementID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	created, _ := time.Parse(time.RFC3339, createdStr)
	expires, _ := time.Parse(time.RFC3339, expiresStr)
	rec := &keys.Record{
		Type:      keys.TypeDomain,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		KeyID:     keys.Fingerprint(keyID),
		Created:   created,
		Expires:   expires,
	}
	if revokedAt.Valid {
		revAt, _ := time.Parse(time.RFC3339, revokedAt.String)
		rec.Revocation = &keys.Revocation{
			Reason:           keys.Reason(revokeReason.String),
			RevokedAt:        revAt,
			ReplacementKeyID: keys.Fingerprint(replacementID.String),
		}
	}
	return rec, nil
}

// LookupUserKeys returns all current key records for address.
func (s *SQLiteStore) LookupUserKeys(ctx context.Context, address string, types ...keys.Type) ([]*keys.Record, error) {
	query := `SELECT key_type, algorithm, public_key, key_id, created_at, expires_at,
	                 revoked_at, revocation_reason, replacement_key_id
	            FROM user_keys WHERE address = ?`
	args := []any{address}
	if len(types) > 0 {
		placeholders := ""
		for i, t := range types {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, string(t))
		}
		query += " AND key_type IN (" + placeholders + ")"
	}
	query += " AND revoked_at IS NULL"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*keys.Record
	for rows.Next() {
		var (
			keyType, algorithm, keyID, createdStr, expiresStr string
			pubBytes                                          []byte
			revokedAt, revokeReason, replacementID            sql.NullString
		)
		if err := rows.Scan(&keyType, &algorithm, &pubBytes, &keyID,
			&createdStr, &expiresStr, &revokedAt, &revokeReason, &replacementID); err != nil {
			return nil, err
		}
		created, _ := time.Parse(time.RFC3339, createdStr)
		expires, _ := time.Parse(time.RFC3339, expiresStr)
		rec := &keys.Record{
			Address:   address,
			Type:      keys.Type(keyType),
			Algorithm: algorithm,
			PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
			KeyID:     keys.Fingerprint(keyID),
			Created:   created,
			Expires:   expires,
		}
		if revokedAt.Valid {
			revAt, _ := time.Parse(time.RFC3339, revokedAt.String)
			rec.Revocation = &keys.Revocation{
				Reason:           keys.Reason(revokeReason.String),
				RevokedAt:        revAt,
				ReplacementKeyID: keys.Fingerprint(replacementID.String),
			}
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// PutRecord persists a user key record.
func (s *SQLiteStore) PutRecord(ctx context.Context, rec *keys.Record) error {
	if rec.Type == keys.TypeDomain {
		return nil // domain keys managed separately
	}
	pubBytes, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO user_keys
		 (address, key_type, algorithm, public_key, key_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rec.Address, string(rec.Type), rec.Algorithm, pubBytes,
		string(rec.KeyID), rec.Created.Format(time.RFC3339), rec.Expires.Format(time.RFC3339))
	return err
}

// PutRevocation records a key revocation.
func (s *SQLiteStore) PutRevocation(ctx context.Context, keyID keys.Fingerprint, rev *keys.Revocation) error {
	revokedAt := rev.RevokedAt.Format(time.RFC3339)
	reason := string(rev.Reason)
	replacement := string(rev.ReplacementKeyID)
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
		revokedAt, reason, replacement, string(keyID))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE domain_keys SET revoked_at = ?, revocation_reason = ?, replacement_key_id = ? WHERE key_id = ?`,
		revokedAt, reason, replacement, string(keyID))
	return err
}

// LookupDeviceCertificate returns the device certificate for deviceKeyID.
func (s *SQLiteStore) LookupDeviceCertificate(ctx context.Context, deviceKeyID keys.Fingerprint) (*keys.DeviceCertificate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT user_id, device_id, issuing_device_key_id, scope_json, issued_at, expires_at, signature_json
		   FROM device_certificates WHERE device_key_id = ?`,
		string(deviceKeyID))

	var (
		userID, deviceID, issuingKeyID, scopeJSON, issuedAtStr, sigJSON string
		expiresAt                                                       sql.NullString
	)
	err := row.Scan(&userID, &deviceID, &issuingKeyID, &scopeJSON, &issuedAtStr, &expiresAt, &sigJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cert := &keys.DeviceCertificate{
		UserID:             userID,
		DeviceID:           deviceID,
		DeviceKeyID:        deviceKeyID,
		IssuingDeviceKeyID: keys.Fingerprint(issuingKeyID),
	}
	cert.IssuedAt, _ = time.Parse(time.RFC3339, issuedAtStr)
	if expiresAt.Valid {
		cert.Expires, _ = time.Parse(time.RFC3339, expiresAt.String)
	}
	_ = json.Unmarshal([]byte(scopeJSON), &cert.Scope)
	_ = json.Unmarshal([]byte(sigJSON), &cert.Signature)
	return cert, nil
}

// PutDeviceCertificate stores a device certificate.
func (s *SQLiteStore) PutDeviceCertificate(ctx context.Context, cert *keys.DeviceCertificate) error {
	scopeJSON, _ := json.Marshal(cert.Scope)
	sigJSON, _ := json.Marshal(cert.Signature)
	expiresAt := ""
	if !cert.Expires.IsZero() {
		expiresAt = cert.Expires.Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO device_certificates
		 (device_key_id, user_id, device_id, issuing_device_key_id, scope_json, issued_at, expires_at, signature_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		string(cert.DeviceKeyID), cert.UserID, cert.DeviceID,
		string(cert.IssuingDeviceKeyID), string(scopeJSON),
		cert.IssuedAt.Format(time.RFC3339), expiresAt, string(sigJSON))
	return err
}

// --- SharedStore methods (for inboxd.Forwarder) ---

// PutDomainKey stores a peer domain's signing public key and returns its fingerprint.
func (s *SQLiteStore) PutDomainKey(domain string, pub []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO domain_keys
		 (domain, key_type, algorithm, public_key, key_id, created_at, expires_at)
		 VALUES (?, 'signing', 'ed25519', ?, ?, ?, ?)`,
		domain, pub, string(fp), now, expires)
	return fp
}

// --- Server-specific helpers ---

// PutDomainKeyPair stores a domain key with its private key.
func (s *SQLiteStore) PutDomainKeyPair(domain, keyType, algorithm string, pub, priv []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(2 * 365 * 24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO domain_keys
		 (domain, key_type, algorithm, public_key, private_key, key_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		domain, keyType, algorithm, pub, priv, string(fp), now, expires)
	return fp
}

// LoadDomainPrivateKey retrieves the private key for a domain key type.
func (s *SQLiteStore) LoadDomainPrivateKey(domain, keyType string) ([]byte, keys.Fingerprint, error) {
	var priv []byte
	var keyID string
	err := s.db.QueryRow(
		`SELECT private_key, key_id FROM domain_keys WHERE domain = ? AND key_type = ?`,
		domain, keyType).Scan(&priv, &keyID)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	return priv, keys.Fingerprint(keyID), err
}

// PutUserKeyPair stores a user key with its private key.
func (s *SQLiteStore) PutUserKeyPair(address string, kt keys.Type, algorithm string, pub, priv []byte) keys.Fingerprint {
	fp := keys.Compute(pub)
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO user_keys
		 (address, key_type, algorithm, public_key, private_key, key_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		address, string(kt), algorithm, pub, priv, string(fp), now, expires)
	return fp
}

// LoadUserPrivateKey retrieves a user's private key by address and type.
func (s *SQLiteStore) LoadUserPrivateKey(address string, kt keys.Type) ([]byte, keys.Fingerprint, error) {
	var priv []byte
	var keyID string
	err := s.db.QueryRow(
		`SELECT private_key, key_id FROM user_keys WHERE address = ? AND key_type = ? AND revoked_at IS NULL`,
		address, string(kt)).Scan(&priv, &keyID)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	return priv, keys.Fingerprint(keyID), err
}

// LoadUserPublicKey retrieves a user's public key by address and type.
func (s *SQLiteStore) LoadUserPublicKey(address string, kt keys.Type) ([]byte, keys.Fingerprint, error) {
	var pub []byte
	var keyID string
	err := s.db.QueryRow(
		`SELECT public_key, key_id FROM user_keys WHERE address = ? AND key_type = ? AND revoked_at IS NULL`,
		address, string(kt)).Scan(&pub, &keyID)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	return pub, keys.Fingerprint(keyID), err
}

// HasDomainKeys reports whether signing and encryption keys exist for domain.
func (s *SQLiteStore) HasDomainKeys(domain string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM domain_keys WHERE domain = ?`, domain).Scan(&count)
	return count >= 2, err
}

// HasUserKeys reports whether any keys exist for address.
func (s *SQLiteStore) HasUserKeys(address string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM user_keys WHERE address = ?`, address).Scan(&count)
	return count > 0, err
}

// DB returns the underlying database handle.
func (s *SQLiteStore) DB() *sql.DB { return s.db }
