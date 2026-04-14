package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per KEY.md section 9.2.
const (
	argonMemory     = 131072 // 128 MiB
	argonIterations = 4
	argonParallel   = 4
	argonKeyLen     = 32 // AES-256
	saltLen         = 16
)

// zeroize overwrites b with zeros.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// DeriveKey derives a 256-bit encryption key from a master key and salt
// using Argon2id.
func DeriveKey(masterKey string, salt []byte) []byte {
	return argon2.IDKey([]byte(masterKey), salt, argonIterations, argonMemory, argonParallel, argonKeyLen)
}

// EncryptPrivateKey encrypts plaintext using AES-256-GCM with a key
// derived from masterKey via Argon2id. The keyID is passed as AAD to
// bind the ciphertext to its storage slot. Returns ciphertext, salt,
// and nonce.
func EncryptPrivateKey(masterKey string, plaintext []byte, aad []byte) (ciphertext, salt, nonce []byte, err error) {
	if masterKey == "" {
		return nil, nil, nil, errors.New("encrypt: empty master key")
	}
	salt = make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt: generate salt: %w", err)
	}

	key := DeriveKey(masterKey, salt)
	defer zeroize(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt: gcm: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("encrypt: generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, salt, nonce, nil
}

// DecryptPrivateKey decrypts ciphertext using AES-256-GCM with a key
// derived from masterKey and the stored salt. The aad must match what
// was used during encryption.
func DecryptPrivateKey(masterKey string, ciphertext, salt, nonce, aad []byte) ([]byte, error) {
	if masterKey == "" {
		return nil, errors.New("decrypt: empty master key")
	}
	key := DeriveKey(masterKey, salt)
	defer zeroize(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt: gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: open: %w", err)
	}
	return plaintext, nil
}
