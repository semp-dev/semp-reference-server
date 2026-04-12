package server

import (
	"fmt"
	"log/slog"

	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-reference-server/internal/config"
)

// Policy implements handshake.Policy with operator-configurable settings.
type Policy struct {
	sessionTTL     int
	blockedDomains map[string]bool
	permissions    []string
}

var _ handshake.Policy = (*Policy)(nil)

// NewPolicy constructs a Policy from the parsed config.
func NewPolicy(cfg config.PolicyConfig) *Policy {
	blocked := make(map[string]bool, len(cfg.BlockedDomains))
	for _, d := range cfg.BlockedDomains {
		blocked[d] = true
	}
	perms := cfg.Permissions
	if len(perms) == 0 {
		perms = []string{"send", "receive"}
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 300
	}
	return &Policy{
		sessionTTL:     ttl,
		blockedDomains: blocked,
		permissions:    perms,
	}
}

func (p *Policy) RequireChallenge(_, _ string) *handshake.Challenge { return nil }
func (p *Policy) BlockedDomain(domain string) bool                 { return p.blockedDomains[domain] }
func (p *Policy) SessionTTL(_ string) int                          { return p.sessionTTL }
func (p *Policy) Permissions(_ string) []string                    { return p.permissions }

// slogAdapter adapts *slog.Logger to the inboxd.Logger Printf interface.
type slogAdapter struct {
	l *slog.Logger
}

var _ inboxd.Logger = slogAdapter{}

func (a slogAdapter) Printf(format string, args ...any) {
	a.l.Info(fmt.Sprintf(format, args...))
}
