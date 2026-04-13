package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the top-level server configuration parsed from a TOML file.
type Config struct {
	Domain     string           `toml:"domain"`
	ListenAddr string           `toml:"listen_addr"`
	TLS        TLSConfig        `toml:"tls"`
	Crypto     CryptoConfig     `toml:"crypto"`
	Database   DatabaseConfig   `toml:"database"`
	Users      []UserConfig     `toml:"users"`
	Federation FederationConfig `toml:"federation"`
	Policy     PolicyConfig     `toml:"policy"`
	Logging    LoggingConfig    `toml:"logging"`
}

// CryptoConfig selects the algorithm suite.
type CryptoConfig struct {
	Suite string `toml:"suite"`
}

// TLSConfig holds TLS certificate paths. Both fields must be set or both empty.
type TLSConfig struct {
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`

	// ExternalTLS indicates TLS is terminated by a reverse proxy (e.g.
	// Cloudflare, Traefik, Caddy). The server runs plain HTTP but
	// advertises wss:// and https:// in discovery responses.
	ExternalTLS bool `toml:"external_tls"`
}

// DatabaseConfig specifies the SQLite database location.
type DatabaseConfig struct {
	Path string `toml:"path"`
}

// UserConfig defines a provisioned user account.
type UserConfig struct {
	Address  string `toml:"address"`
	Password string `toml:"password"`
}

// FederationConfig controls cross-domain federation behaviour.
type FederationConfig struct {
	SessionTTL int          `toml:"session_ttl"`
	Retention  string       `toml:"retention"`
	Peers      []PeerConfig `toml:"peers"`
}

// PeerConfig is a statically configured federation peer.
type PeerConfig struct {
	Domain           string `toml:"domain"`
	Endpoint         string `toml:"endpoint"`
	DomainSigningKey string `toml:"domain_signing_key"`
}

// PolicyConfig holds operator policy for client sessions.
type PolicyConfig struct {
	SessionTTL     int      `toml:"session_ttl"`
	BlockedDomains []string `toml:"blocked_domains"`
	Permissions    []string `toml:"permissions"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

// Load reads a TOML configuration file, applies defaults, and validates it.
func Load(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(c *Config) {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8443"
	}
	if c.Database.Path == "" {
		c.Database.Path = "semp.db"
	}
	if c.Policy.SessionTTL <= 0 {
		c.Policy.SessionTTL = 300
	}
	if len(c.Policy.Permissions) == 0 {
		c.Policy.Permissions = []string{"send", "receive"}
	}
	if c.Federation.SessionTTL <= 0 {
		c.Federation.SessionTTL = 3600
	}
	if c.Federation.Retention == "" {
		c.Federation.Retention = "7d"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if c.Crypto.Suite == "" {
		c.Crypto.Suite = "pq-kyber768-x25519"
	}
}

func validate(c *Config) error {
	if c.Domain == "" {
		return fmt.Errorf("config: domain is required")
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("config: at least one user is required")
	}
	for _, u := range c.Users {
		if u.Address == "" {
			return fmt.Errorf("config: user address is empty")
		}
		if u.Password == "" {
			return fmt.Errorf("config: user %q has no password", u.Address)
		}
		parts := strings.SplitN(u.Address, "@", 2)
		if len(parts) != 2 || parts[1] != c.Domain {
			return fmt.Errorf("config: user %q must be on domain %q", u.Address, c.Domain)
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf("config: tls.cert_file and tls.key_file must both be set or both empty")
	}
	return nil
}
