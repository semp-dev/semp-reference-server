package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/delivery"
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
		s.metrics.HandshakesFailure.Add(1)
		s.logger.Error("client handshake failed", "peer", conn.Peer(), "err", err)
		return
	}
	s.metrics.HandshakesSuccess.Add(1)
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
		BlockList:      s.blockList,
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
		BlockList:      s.blockList,
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

	s.metrics.Registrations.Add(1)
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
	host := r.Host
	clientEndpoints := map[string]string{
		"h2": h2Scheme + "://" + host + "/v1/h2",
		"ws": wsScheme + "://" + host + "/v1/ws",
	}
	fedEndpoints := map[string]string{
		"h2": h2Scheme + "://" + host + "/v1/h2/federate",
		"ws": wsScheme + "://" + host + "/v1/federate",
	}
	if s.quicAddr != "" {
		clientEndpoints["quic"] = "https://" + host + "/v1/quic"
		fedEndpoints["quic"] = "https://" + host + "/v1/quic/federate"
	}
	cfg := discovery.Configuration{
		Version: semp.ProtocolVersion,
		Domain:  s.domain,
		Endpoints: discovery.ConfigEndpoints{
			Client:         clientEndpoints,
			Federation:     fedEndpoints,
			Register:       h2Scheme + "://" + host + "/v1/register",
			DeviceRegister: h2Scheme + "://" + host + "/v1/device/register",
			BlockList:      h2Scheme + "://" + host + "/v1/blocklist",
			Keys:           h2Scheme + "://" + host + "/.well-known/semp/keys/",
			DomainKeys:     h2Scheme + "://" + host + "/.well-known/semp/domain-keys",
		},
		Suites: s.advertisedSuites(),
		Limits: discovery.ConfigLimits{
			MaxEnvelopeSize: 25 * 1024 * 1024,
		},
		Extensions: []discovery.ConfigExtension{},
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

// handleBlockList handles GET/POST/DELETE /v1/blocklist for per-user block lists.
func (s *Server) handleBlockList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		address := r.URL.Query().Get("address")
		if address == "" {
			http.Error(w, "missing address parameter", http.StatusBadRequest)
			return
		}
		entries, err := s.blockList.ListEntries(r.Context(), address)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(entries)

	case http.MethodPost:
		var req struct {
			UserID         string `json:"user_id"`
			EntityType     string `json:"entity_type"`
			EntityValue    string `json:"entity_value"`
			Acknowledgment string `json:"acknowledgment"`
			Reason         string `json:"reason"`
			Scope          string `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if req.UserID == "" || req.EntityType == "" || req.EntityValue == "" {
			http.Error(w, "user_id, entity_type, and entity_value are required", http.StatusBadRequest)
			return
		}
		ack := semp.Acknowledgment(req.Acknowledgment)
		if ack == "" {
			ack = semp.AckRejected
		}
		scope := delivery.Scope(req.Scope)
		if scope == "" {
			scope = delivery.ScopeAll
		}
		entity := delivery.Entity{Type: delivery.EntityType(req.EntityType)}
		switch entity.Type {
		case delivery.EntityUser:
			entity.Address = req.EntityValue
		case delivery.EntityDomain:
			entity.Domain = req.EntityValue
		case delivery.EntityServer:
			entity.Hostname = req.EntityValue
		}
		entry := delivery.BlockEntry{
			Entity: entity,
			Acknowledgment: ack,
			Reason:         req.Reason,
			Scope:          scope,
		}
		id, err := s.blockList.AddEntry(r.Context(), req.UserID, entry)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.logger.Info("block entry added", "user", req.UserID, "entity", req.EntityValue, "id", id)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "status": "added"})

	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/v1/blocklist/")
		if id == "" || id == r.URL.Path {
			http.Error(w, "missing entry ID", http.StatusBadRequest)
			return
		}
		if err := s.blockList.RemoveEntry(r.Context(), id); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.logger.Info("block entry removed", "id", id)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "removed"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeviceRegister handles POST /v1/device/register for delegated
// device registration. The primary device issues a scoped certificate
// and the delegated device submits it along with its public keys.
func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Certificate      keys.DeviceCertificate `json:"certificate"`
		DeviceIdentityKey   registerKey          `json:"device_identity_key"`
		DeviceEncryptionKey registerKey          `json:"device_encryption_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cert := &req.Certificate
	if cert.UserID == "" || cert.DeviceKeyID == "" {
		http.Error(w, "certificate must include user_id and device_key_id", http.StatusBadRequest)
		return
	}

	// Verify the user exists on this server.
	if _, ok := s.users[cert.UserID]; !ok {
		http.Error(w, "unknown user", http.StatusForbidden)
		return
	}

	// Verify the certificate signature chain.
	if err := cert.VerifyChain(r.Context(), s.suite, s.store); err != nil {
		s.logger.Warn("device certificate verification failed", "user", cert.UserID, "device", cert.DeviceID, "err", err)
		http.Error(w, "certificate verification failed", http.StatusUnauthorized)
		return
	}

	// Store the certificate.
	if err := s.store.PutDeviceCertificate(r.Context(), cert); err != nil {
		s.logger.Error("store device certificate failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store the device's public keys.
	idPub, err := base64.StdEncoding.DecodeString(req.DeviceIdentityKey.PublicKey)
	if err != nil {
		http.Error(w, "invalid device identity key", http.StatusBadRequest)
		return
	}
	encPub, err := base64.StdEncoding.DecodeString(req.DeviceEncryptionKey.PublicKey)
	if err != nil {
		http.Error(w, "invalid device encryption key", http.StatusBadRequest)
		return
	}

	idFP := keys.Compute(idPub)
	if err := s.store.PutRecord(r.Context(), &keys.Record{
		Address:   cert.UserID,
		Type:      keys.TypeDevice,
		Algorithm: req.DeviceIdentityKey.Algorithm,
		PublicKey: req.DeviceIdentityKey.PublicKey,
		KeyID:     idFP,
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	encFP := keys.Compute(encPub)
	if err := s.store.PutRecord(r.Context(), &keys.Record{
		Address:   cert.UserID,
		Type:      keys.TypeEncryption,
		Algorithm: req.DeviceEncryptionKey.Algorithm,
		PublicKey: req.DeviceEncryptionKey.PublicKey,
		KeyID:     encFP,
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.logger.Info("device registered",
		"user", cert.UserID,
		"device", cert.DeviceID,
		"device_key", cert.DeviceKeyID,
		"scope_send", cert.Scope.Send.Mode,
	)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "registered",
		"device_id": cert.DeviceID,
	})
}
