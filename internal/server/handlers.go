package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
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

// handleRegister handles POST /v1/register — client key registration.
// The client generates keys locally and pushes its public keys here.
// The server returns its domain signing and encryption keys.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Verify address is a known user and password matches.
	expectedPassword, ok := s.users[req.Address]
	if !ok {
		s.logger.Warn("registration rejected: unknown user", "address", req.Address)
		http.Error(w, "unknown user", http.StatusForbidden)
		return
	}
	if req.Password != expectedPassword {
		s.logger.Warn("registration rejected: wrong password", "address", req.Address)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Decode and store identity public key.
	idPub, err := base64.StdEncoding.DecodeString(req.IdentityKey.PublicKey)
	if err != nil {
		http.Error(w, "invalid identity key", http.StatusBadRequest)
		return
	}
	idFP := keys.Compute(idPub)
	if err := s.store.PutRecord(r.Context(), &keys.Record{
		Address:   req.Address,
		Type:      keys.TypeIdentity,
		Algorithm: req.IdentityKey.Algorithm,
		PublicKey: req.IdentityKey.PublicKey,
		KeyID:     idFP,
	}); err != nil {
		s.logger.Error("store identity key failed", "address", req.Address, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Decode and store encryption public key.
	encPub, err := base64.StdEncoding.DecodeString(req.EncryptionKey.PublicKey)
	if err != nil {
		http.Error(w, "invalid encryption key", http.StatusBadRequest)
		return
	}
	encFP := keys.Compute(encPub)
	if err := s.store.PutRecord(r.Context(), &keys.Record{
		Address:   req.Address,
		Type:      keys.TypeEncryption,
		Algorithm: req.EncryptionKey.Algorithm,
		PublicKey: req.EncryptionKey.PublicKey,
		KeyID:     encFP,
	}); err != nil {
		s.logger.Error("store encryption key failed", "address", req.Address, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("user registered",
		"address", req.Address,
		"identity_fp", idFP,
		"encryption_fp", encFP,
	)

	// Return domain keys so the client can cache them for handshake verification.
	signRec, _ := s.store.LookupDomainKey(r.Context(), s.domain)
	encRec := s.store.LookupDomainEncryptionKey(s.domain)

	resp := registerResponse{Status: "registered"}
	if signRec != nil {
		resp.DomainSigningKey = &registerKeyEntry{
			Algorithm: signRec.Algorithm,
			PublicKey: signRec.PublicKey,
			KeyID:     string(signRec.KeyID),
		}
	}
	if encRec != nil {
		resp.DomainEncryptionKey = &registerKeyEntry{
			Algorithm: encRec.Algorithm,
			PublicKey: encRec.PublicKey,
			KeyID:     string(encRec.KeyID),
		}
	}

	_ = idPub
	_ = encPub

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

type registerRequest struct {
	Address       string        `json:"address"`
	Password      string        `json:"password"`
	IdentityKey   registerKey   `json:"identity_key"`
	EncryptionKey registerKey   `json:"encryption_key"`
}

type registerKey struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type registerResponse struct {
	Status             string            `json:"status"`
	DomainSigningKey   *registerKeyEntry `json:"domain_signing_key,omitempty"`
	DomainEncryptionKey *registerKeyEntry `json:"domain_encryption_key,omitempty"`
}

type registerKeyEntry struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
}

func (s *Server) handleWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	wsScheme := "wss"
	h2Scheme := "https"
	if s.tlsCert == "" && !s.externalTLS {
		wsScheme = "ws"
		h2Scheme = "http"
	}
	cfg := discovery.Configuration{
		Version: semp.ProtocolVersion,
		Endpoints: map[string]string{
			"h2": h2Scheme + "://" + r.Host + "/v1/h2",
			"ws": wsScheme + "://" + r.Host + "/v1/ws",
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

func (s *Server) handleWellKnownDomainKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	signRec, _ := s.store.LookupDomainKey(ctx, s.domain)
	encRec := s.store.LookupDomainEncryptionKey(s.domain)

	type domainKeysResponse struct {
		Type          string            `json:"type"`
		Version       string            `json:"version"`
		Domain        string            `json:"domain"`
		SigningKey    *registerKeyEntry  `json:"signing_key,omitempty"`
		EncryptionKey *registerKeyEntry  `json:"encryption_key,omitempty"`
	}

	resp := domainKeysResponse{
		Type:    "SEMP_DOMAIN_KEYS",
		Version: semp.ProtocolVersion,
		Domain:  s.domain,
	}
	if signRec != nil {
		resp.SigningKey = &registerKeyEntry{
			Algorithm: signRec.Algorithm,
			PublicKey: signRec.PublicKey,
			KeyID:     string(signRec.KeyID),
		}
	}
	if encRec != nil {
		resp.EncryptionKey = &registerKeyEntry{
			Algorithm: encRec.Algorithm,
			PublicKey: encRec.PublicKey,
			KeyID:     string(encRec.KeyID),
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}
