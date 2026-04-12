package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/transport"
)

func (s *Server) handleClient(ctx context.Context, conn transport.Conn) {
	defer conn.Close()
	s.logger.Info("client connected", "peer", conn.Peer())

	srv := handshake.NewServer(handshake.ServerConfig{
		Suite:            s.suite,
		Store:            s.store,
		Policy:           s.policy,
		Domain:           s.domain,
		DomainKeyID:      s.domainSignFP,
		DomainPrivateKey: s.domainSignPriv,
	})
	defer srv.Erase()

	sess, err := handshake.RunServer(ctx, conn, srv)
	if err != nil {
		s.logger.Error("client handshake failed", "peer", conn.Peer(), "err", err)
		return
	}
	s.logger.Info("client session established",
		"peer", conn.Peer(),
		"session", sess.ID,
		"identity", srv.ClientIdentity(),
		"ttl", sess.TTL,
	)

	loop := &inboxd.Server{
		Mode:           inboxd.ModeClient,
		Suite:          s.suite,
		Store:          s.store,
		Inbox:          s.inbox,
		Forwarder:      s.forwarder,
		LocalDomain:    s.domain,
		DomainSignFP:   s.domainSignFP,
		DomainSignPriv: s.domainSignPriv,
		DomainEncFP:    s.domainEncFP,
		DomainEncPriv:  s.domainEncPriv,
		Identity:       srv.ClientIdentity(),
		DeviceKeyID:    srv.ClientDeviceKeyID(),
		Session:        sess,
		Logger:         slogAdapter{s.logger},
	}
	if err := loop.Serve(ctx, conn); err != nil && err != io.EOF {
		s.logger.Error("client loop ended", "peer", conn.Peer(), "err", err)
		return
	}
	s.logger.Info("client disconnected", "peer", conn.Peer())
}

func (s *Server) handleFederation(ctx context.Context, conn transport.Conn) {
	defer conn.Close()
	s.logger.Info("federation peer connected", "peer", conn.Peer())

	resp := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 s.suite,
		Store:                 s.store,
		Verifier:              handshake.TrustingDomainVerifier{},
		LocalDomain:           s.domain,
		LocalDomainKeyID:      s.domainSignFP,
		LocalDomainPrivateKey: s.domainSignPriv,
		Policy: handshake.FederationPolicy{
			MessageRetention: s.fedRetention,
			UserDiscovery:    "allowed",
			RelayAllowed:     true,
		},
		SessionTTL: s.fedSessionTTL,
	})
	defer resp.Erase()

	sess, err := handshake.RunResponder(ctx, conn, resp)
	if err != nil {
		s.logger.Error("federation handshake failed", "peer", conn.Peer(), "err", err)
		return
	}
	s.logger.Info("federation session established",
		"peer", conn.Peer(),
		"session", sess.ID,
		"peer_domain", resp.PeerDomain(),
		"ttl", sess.TTL,
	)

	loop := &inboxd.Server{
		Mode:           inboxd.ModeFederation,
		Suite:          s.suite,
		Store:          s.store,
		Inbox:          s.inbox,
		LocalDomain:    s.domain,
		DomainSignFP:   s.domainSignFP,
		DomainSignPriv: s.domainSignPriv,
		DomainEncFP:    s.domainEncFP,
		DomainEncPriv:  s.domainEncPriv,
		Identity:       resp.PeerDomain(),
		Session:        sess,
		Logger:         slogAdapter{s.logger},
	}
	if err := loop.Serve(ctx, conn); err != nil && err != io.EOF {
		s.logger.Error("federation loop ended", "peer", conn.Peer(), "err", err)
		return
	}
	s.logger.Info("federation peer disconnected", "peer", conn.Peer())
}

func (s *Server) handleWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	scheme := "wss"
	if s.tlsCert == "" {
		scheme = "ws"
	}
	cfg := discovery.Configuration{
		Version: semp.ProtocolVersion,
		Endpoints: map[string]string{
			"ws": scheme + "://" + r.Host + "/v1/ws",
		},
		Features:        []string{},
		PostQuantum:     "hybrid",
		MaxEnvelopeSize: 25 * 1024 * 1024,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(cfg)
}

func (s *Server) handleWellKnownKeys(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimPrefix(r.URL.Path, "/.well-known/semp/keys/")
	if address == "" {
		http.Error(w, "missing address", http.StatusBadRequest)
		return
	}
	records, err := s.store.LookupUserKeys(r.Context(), address)
	if err != nil {
		s.logger.Error("key lookup failed", "address", address, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(records) == 0 {
		http.NotFound(w, r)
		return
	}

	type keyResponse struct {
		Type    string `json:"type"`
		Version string `json:"version"`
		Keys    any    `json:"keys"`
	}

	resp := keyResponse{
		Type:    "SEMP_KEYS",
		Version: semp.ProtocolVersion,
		Keys:    records,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}
