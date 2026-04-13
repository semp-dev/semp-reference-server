package server

import (
	"encoding/json"
	"expvar"
	"net/http"
	"sync/atomic"
)

// Metrics holds operational counters for the SEMP server.
type Metrics struct {
	HandshakesSuccess  atomic.Int64
	HandshakesFailure  atomic.Int64
	Registrations      atomic.Int64
	EnvelopesDelivered atomic.Int64
	EnvelopesRejected  atomic.Int64
	EnvelopesFetched   atomic.Int64
	FederationSuccess  atomic.Int64
	FederationFailure  atomic.Int64
	ChallengesIssued   atomic.Int64
	ChallengesSolved   atomic.Int64
	ScopeViolations    atomic.Int64
}

func newMetrics() *Metrics {
	m := &Metrics{}
	expvar.NewInt("semp_handshakes_success")
	expvar.NewInt("semp_handshakes_failure")
	expvar.NewInt("semp_registrations")
	expvar.NewInt("semp_envelopes_delivered")
	expvar.NewInt("semp_envelopes_rejected")
	expvar.NewInt("semp_envelopes_fetched")
	expvar.NewInt("semp_federation_success")
	expvar.NewInt("semp_federation_failure")
	expvar.NewInt("semp_challenges_issued")
	expvar.NewInt("semp_challenges_solved")
	expvar.NewInt("semp_scope_violations")
	return m
}

func (m *Metrics) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats := map[string]int64{
			"handshakes_success":  m.HandshakesSuccess.Load(),
			"handshakes_failure":  m.HandshakesFailure.Load(),
			"registrations":      m.Registrations.Load(),
			"envelopes_delivered": m.EnvelopesDelivered.Load(),
			"envelopes_rejected":  m.EnvelopesRejected.Load(),
			"envelopes_fetched":   m.EnvelopesFetched.Load(),
			"federation_success":  m.FederationSuccess.Load(),
			"federation_failure":  m.FederationFailure.Load(),
			"challenges_issued":   m.ChallengesIssued.Load(),
			"challenges_solved":   m.ChallengesSolved.Load(),
			"scope_violations":    m.ScopeViolations.Load(),
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(stats)
	})
}
