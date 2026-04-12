package keygen

import (
	"fmt"
	"log/slog"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-reference-server/internal/config"
	"semp.dev/semp-reference-server/internal/store"
)

// EnsureDomainKeys generates domain signing (Ed25519) and encryption key
// pairs on first run, or loads existing keys from the store.
func EnsureDomainKeys(s *store.SQLiteStore, suite crypto.Suite, domain string, logger *slog.Logger) (
	signFP keys.Fingerprint, signPriv []byte,
	encFP keys.Fingerprint, encPriv []byte,
	err error,
) {
	has, err := s.HasDomainKeys(domain)
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("keygen: check domain keys: %w", err)
	}

	if has {
		signPriv, signFP, err = s.LoadDomainPrivateKey(domain, "signing")
		if err != nil {
			return "", nil, "", nil, fmt.Errorf("keygen: load signing key: %w", err)
		}
		encPriv, encFP, err = s.LoadDomainPrivateKey(domain, "encryption")
		if err != nil {
			return "", nil, "", nil, fmt.Errorf("keygen: load encryption key: %w", err)
		}
		logger.Info("loaded existing domain keys", "domain", domain, "sign_fp", signFP, "enc_fp", encFP)
		return signFP, signPriv, encFP, encPriv, nil
	}

	// Generate signing key (Ed25519).
	signPub, signPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("keygen: generate signing key: %w", err)
	}
	signFP = s.PutDomainKeyPair(domain, "signing", "ed25519", signPub, signPriv)

	// Generate encryption key (KEM).
	encPub, encPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		return "", nil, "", nil, fmt.Errorf("keygen: generate encryption key: %w", err)
	}
	encFP = s.PutDomainKeyPair(domain, "encryption", string(suite.ID()), encPub, encPriv)

	logger.Info("generated new domain keys", "domain", domain, "sign_fp", signFP, "enc_fp", encFP)
	return signFP, signPriv, encFP, encPriv, nil
}

// EnsureUserKeys generates identity and encryption key pairs for each
// configured user that doesn't already have keys.
func EnsureUserKeys(s *store.SQLiteStore, suite crypto.Suite, users []config.UserConfig, logger *slog.Logger) error {
	for _, u := range users {
		has, err := s.HasUserKeys(u.Address)
		if err != nil {
			return fmt.Errorf("keygen: check user keys %s: %w", u.Address, err)
		}
		if has {
			logger.Info("user keys exist", "address", u.Address)
			continue
		}

		// Identity key (Ed25519).
		idPub, idPriv, err := suite.Signer().GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("keygen: identity key for %s: %w", u.Address, err)
		}
		idFP := s.PutUserKeyPair(u.Address, keys.TypeIdentity, "ed25519", idPub, idPriv)

		// Encryption key (KEM).
		encPub, encPriv, err := suite.KEM().GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("keygen: encryption key for %s: %w", u.Address, err)
		}
		encFP := s.PutUserKeyPair(u.Address, keys.TypeEncryption, string(suite.ID()), encPub, encPriv)

		logger.Info("generated user keys", "address", u.Address, "identity_fp", idFP, "encryption_fp", encFP)
	}
	return nil
}
