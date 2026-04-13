package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	if s.tlsCert == "" && !s.externalTLS {
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

// handleWellKnownDomainKeys serves the domain's signing and encryption
// public keys at /.well-known/semp/domain-keys. Federation peers fetch
// this over HTTPS to bootstrap trust without manual key exchange.
func (s *Server) handleWellKnownDomainKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signRec, _ := s.store.LookupDomainKey(ctx, s.domain)
	encRec := s.store.LookupDomainEncryptionKey(s.domain)

	type domainKeysResponse struct {
		Type          string `json:"type"`
		Version       string `json:"version"`
		Domain        string `json:"domain"`
		SigningKey    *domainKeyEntry `json:"signing_key,omitempty"`
		EncryptionKey *domainKeyEntry `json:"encryption_key,omitempty"`
	}
	type_ := "SEMP_DOMAIN_KEYS"

	resp := domainKeysResponse{
		Type:    type_,
		Version: semp.ProtocolVersion,
		Domain:  s.domain,
	}
	if signRec != nil {
		resp.SigningKey = &domainKeyEntry{
			Algorithm: signRec.Algorithm,
			PublicKey: signRec.PublicKey,
			KeyID:     string(signRec.KeyID),
		}
	}
	if encRec != nil {
		resp.EncryptionKey = &domainKeyEntry{
			Algorithm: encRec.Algorithm,
			PublicKey: encRec.PublicKey,
			KeyID:     string(encRec.KeyID),
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

type domainKeyEntry struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
}

// fetchPeerDomainSigningKey fetches a peer's domain signing key from
// their well-known endpoint over HTTPS.
func fetchPeerDomainSigningKey(peerDomain, peerEndpoint string) ([]byte, error) {
	// Derive the HTTPS host from the WSS endpoint.
	host := peerDomain
	if peerEndpoint != "" {
		h := peerEndpoint
		h = strings.TrimPrefix(h, "wss://")
		h = strings.TrimPrefix(h, "ws://")
		if idx := strings.Index(h, "/"); idx > 0 {
			h = h[:idx]
		}
		host = h
	}

	url := "https://" + host + "/.well-known/semp/domain-keys"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch domain keys from %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch domain keys from %s: status %d", url, resp.StatusCode)
	}

	var result struct {
		SigningKey *struct {
			PublicKey string `json:"public_key"`
		} `json:"signing_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode domain keys from %s: %w", url, err)
	}
	if result.SigningKey == nil {
		return nil, fmt.Errorf("no signing key in domain keys response from %s", url)
	}
	pub, err := base64.StdEncoding.DecodeString(result.SigningKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode signing key from %s: %w", url, err)
	}
	return pub, nil
}
