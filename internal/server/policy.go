package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/reputation"
	"semp.dev/semp-reference-server/internal/config"
)

// Policy implements handshake.Policy with operator-configurable settings.
type Policy struct {
	sessionTTL     int
	blockedDomains map[string]bool
	permissions    []string
	powEnabled     bool
	powDifficulty  int
	powTTL         time.Duration
	ledger         *reputation.ChallengeLedger
	metrics        *Metrics
}

var _ handshake.Policy = (*Policy)(nil)

// NewPolicy constructs a Policy from the parsed config.
func NewPolicy(cfg config.PolicyConfig, metrics *Metrics) *Policy {
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
	powDiff := cfg.PoW.Difficulty
	if powDiff <= 0 {
		powDiff = 20
	}
	powTTL := cfg.PoW.TTL
	if powTTL <= 0 {
		powTTL = 300
	}
	return &Policy{
		sessionTTL:     ttl,
		blockedDomains: blocked,
		permissions:    perms,
		powEnabled:     cfg.PoW.Enabled,
		powDifficulty:  powDiff,
		powTTL:         time.Duration(powTTL) * time.Second,
		ledger:         reputation.NewChallengeLedger(time.Minute),
		metrics:        metrics,
	}
}

func (p *Policy) RequireChallenge(_, _ string) *handshake.Challenge {
	if !p.powEnabled {
		return nil
	}
	ch, err := reputation.IssueChallenge(p.powDifficulty, p.powTTL)
	if err != nil {
		return nil
	}
	_ = p.ledger.Record(ch)
	if p.metrics != nil {
		p.metrics.ChallengesIssued.Add(1)
	}
	params, _ := json.Marshal(map[string]any{
		"prefix":     ch.PrefixBase64(),
		"difficulty": ch.Difficulty,
		"id":         ch.ID,
	})
	return &handshake.Challenge{
		ChallengeType: "pow-sha256",
		Parameters:    json.RawMessage(params),
		Expires:       ch.Expires,
	}
}

func (p *Policy) BlockedDomain(domain string) bool { return p.blockedDomains[domain] }
func (p *Policy) SessionTTL(_ string) int          { return p.sessionTTL }
func (p *Policy) Permissions(_ string) []string     { return p.permissions }

// slogAdapter adapts *slog.Logger to the inboxd.Logger Printf interface.
type slogAdapter struct {
	l *slog.Logger
}

var _ inboxd.Logger = slogAdapter{}

func (a slogAdapter) Printf(format string, args ...any) {
	a.l.Info(fmt.Sprintf(format, args...))
}
