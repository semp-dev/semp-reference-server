package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/h2"
	"semp.dev/semp-go/transport/ws"
	"semp.dev/semp-reference-server/impl/go/internal/config"
	"semp.dev/semp-reference-server/impl/go/internal/keygen"
	"semp.dev/semp-reference-server/impl/go/internal/store"
)

// Server is the SEMP reference server.
type Server struct {
	domain        string
	listenAddr    string
	tlsCert       string
	tlsKey        string
	externalTLS   bool
	quicAddr      string
	fedSessionTTL int
	fedRetention  string

	suite          crypto.Suite
	domainSignFP   keys.Fingerprint
	domainSignPriv []byte
	domainEncFP    keys.Fingerprint
	domainEncPriv  []byte
	domainEncPub   []byte

	store     *store.SQLiteStore
	inbox     *delivery.Inbox
	sqlInbox  *store.SQLiteInbox
	forwarder *delivery.Forwarder
	blockList *store.SQLiteBlockList
	policy    *Policy
	users     map[string]string // address -> password

	registerRL *ipRateLimiter

	metrics *Metrics
	httpSrv *http.Server
	logger  *slog.Logger
	ctx     context.Context
}

// New constructs a Server from a parsed config.
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	db, err := store.InitDB(cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	sqlStore := store.NewSQLiteStore(db)
	if cfg.Database.MasterKey != "" {
		sqlStore.SetMasterKey(cfg.Database.MasterKey)
		logger.Info("private key encryption enabled")
	}

	suite := crypto.LookupSuite(crypto.SuiteID(cfg.Crypto.Suite))
	if suite == nil {
		return nil, fmt.Errorf("unknown crypto suite: %s", cfg.Crypto.Suite)
	}
	logger.Info("crypto suite", "suite", cfg.Crypto.Suite)

	signFP, signPriv, encFP, encPriv, encPub, err := keygen.EnsureDomainKeys(
		sqlStore, suite, cfg.Domain, logger)
	if err != nil {
		return nil, fmt.Errorf("domain keys: %w", err)
	}

	// Set up auto-fetch for remote domain signing keys.
	sqlStore.SetDomainKeyFetcher(cfg.Domain, func(domain string) []byte {
		pub, err := fetchDomainSigningKeyFromWellKnown(domain)
		if err != nil {
			logger.Warn("auto-fetch domain signing key failed", "domain", domain, "err", err)
			return nil
		}
		logger.Info("auto-fetched domain signing key", "domain", domain, "fingerprint", keys.Compute(pub))
		return pub
	})

	sqlInbox := store.NewSQLiteInbox(db)
	if err := sqlInbox.LoadPending(); err != nil {
		logger.Warn("loading pending inbox items", "err", err)
	}
	memInbox := sqlInbox.MemInbox()

	// Register federation peers. Statically configured signing keys
	// are pre-cached in the SQLiteStore so the forwarder's federation
	// initiator can verify the peer-domain signature without falling
	// through to the auto-fetch path on first contact.
	staticEndpoints := make(map[string]string, len(cfg.Federation.Peers))
	for _, p := range cfg.Federation.Peers {
		if p.Endpoint != "" {
			staticEndpoints[p.Domain] = p.Endpoint
		}
		if p.DomainSigningKey != "" {
			pubBytes, err := base64.StdEncoding.DecodeString(p.DomainSigningKey)
			if err != nil {
				return nil, fmt.Errorf("decode peer %s signing key: %w", p.Domain, err)
			}
			sqlStore.PutDomainKey(p.Domain, pubBytes)
		}
		logger.Info("registered federation peer", "domain", p.Domain, "endpoint", p.Endpoint)
	}

	allowInsecure := cfg.TLS.CertFile == "" && !cfg.TLS.ExternalTLS
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: allowInsecure})
	h2Transport := h2.NewWithConfig(h2.Config{AllowInsecure: allowInsecure})

	resolver := discovery.NewResolver(discovery.ResolverConfig{
		Cache: discovery.NewMemCache(),
	})

	// Build a static-first / discovery-fallback EndpointResolver. We
	// prefer operator-pinned endpoints when configured (cheap, and
	// avoids DNS round-trips); otherwise we resolve via DNS SRV plus
	// the well-known URI per DISCOVERY.md section 5.1.
	discoveryResolver := delivery.EndpointResolverFromDiscovery(resolver, federationEndpointFunc)
	endpointResolver := func(ctx context.Context, peerDomain string) (string, error) {
		if ep, ok := staticEndpoints[peerDomain]; ok && ep != "" {
			return ep, nil
		}
		return discoveryResolver(ctx, peerDomain)
	}

	forwarder := delivery.NewForwarder(delivery.ForwarderConfig{
		Suite:                 suite,
		LocalDomain:           cfg.Domain,
		LocalDomainKeyID:      signFP,
		LocalDomainPrivateKey: signPriv,
		Store:                 sqlStore,
		EndpointResolver:      endpointResolver,
		Dial: func(ctx context.Context, endpoint string) (transport.Conn, error) {
			// Try WebSocket first for wss:// endpoints (existing peers),
			// fall back to HTTP/2 for https:// endpoints (baseline transport).
			if strings.HasPrefix(endpoint, "wss://") || strings.HasPrefix(endpoint, "ws://") {
				return wsTransport.Dial(ctx, endpoint)
			}
			return h2Transport.Dial(ctx, endpoint)
		},
	})

	blockList := store.NewSQLiteBlockList(db)

	metrics := newMetrics()
	policy := NewPolicy(cfg.Policy, metrics)

	// Build user auth map.
	users := make(map[string]string, len(cfg.Users))
	for _, u := range cfg.Users {
		users[u.Address] = u.Password
	}

	// Rate limiter for /v1/register: 10 requests per minute per IP
	// (security audit finding 1.5).
	regRL := newIPRateLimiter(10, time.Minute)

	s := &Server{
		domain:         cfg.Domain,
		listenAddr:     cfg.ListenAddr,
		tlsCert:        cfg.TLS.CertFile,
		tlsKey:         cfg.TLS.KeyFile,
		externalTLS:    cfg.TLS.ExternalTLS,
		quicAddr:       cfg.TLS.QUICAddr,
		fedSessionTTL:  cfg.Federation.SessionTTL,
		fedRetention:   cfg.Federation.Retention,
		suite:          suite,
		domainSignFP:   signFP,
		domainSignPriv: signPriv,
		domainEncFP:    encFP,
		domainEncPriv:  encPriv,
		domainEncPub:   encPub,
		store:          sqlStore,
		inbox:          memInbox,
		sqlInbox:       sqlInbox,
		forwarder:      forwarder,
		blockList:      blockList,
		policy:         policy,
		users:          users,
		registerRL:     regRL,
		metrics:        metrics,
		logger:         logger,
	}
	return s, nil
}

// federationEndpointFunc is the operator's preferred discovery to
// federation-endpoint mapping. Per TRANSPORT.md, HTTP/2 is the
// mandatory baseline, so try federation.h2 before federation.ws and
// only fall back to DefaultFederationEndpointFunc when the peer did
// not publish a configuration (DNS-only resolution).
func federationEndpointFunc(result *discovery.Result) (string, error) {
	if result != nil && result.Configuration != nil {
		fed := result.Configuration.Endpoints.Federation
		if ep, ok := fed["h2"]; ok && ep != "" {
			return ep, nil
		}
		if ep, ok := fed["ws"]; ok && ep != "" {
			return ep, nil
		}
	}
	return delivery.DefaultFederationEndpointFunc(result)
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx

	wsCfg := wsServerConfig{
		OriginPatterns: []string{"*"},
	}
	h2Cfg := h2.Config{}

	mux := http.NewServeMux()

	// WebSocket transport (recommended).
	mux.Handle("/v1/ws", newWSHandler(wsCfg, func(conn transport.Conn) {
		go s.handleClient(s.ctx, conn)
	}))
	mux.Handle("/v1/federate", newWSHandler(wsCfg, func(conn transport.Conn) {
		go s.handleFederation(s.ctx, conn)
	}))

	// HTTP/2 transport (mandatory baseline per TRANSPORT.md section 4).
	mux.Handle("/v1/h2", newH2Handler(h2Cfg, func(conn transport.Conn) {
		go s.handleClient(s.ctx, conn)
	}))
	mux.Handle("/v1/h2/federate", newH2Handler(h2Cfg, func(conn transport.Conn) {
		go s.handleFederation(s.ctx, conn)
	}))
	mux.HandleFunc("/v1/register", s.handleRegister)
	mux.HandleFunc("/v1/device/register", s.handleDeviceRegister)
	mux.HandleFunc(discovery.WellKnownPath, s.handleWellKnownConfig)
	mux.HandleFunc("/.well-known/semp/keys/", s.handleWellKnownKeys)
	mux.HandleFunc("/.well-known/semp/domain-keys", s.handleWellKnownDomainKeys)
	mux.HandleFunc("/v1/blocklist", s.handleBlockList)
	mux.HandleFunc("/v1/blocklist/", s.handleBlockList)
	mux.Handle("/debug/metrics", s.metrics.handler())

	// Wrap the mux with panic recovery so that a handler panic does
	// not crash the entire server process (security audit finding 6.3).
	recovered := s.recoveryHandler(mux)

	var tlsCfgHTTP *tls.Config
	if s.tlsCert != "" && s.tlsKey != "" {
		tlsCfgHTTP, _ = loadTLSConfig(s.tlsCert, s.tlsKey, "h2", "http/1.1")
	}
	s.httpSrv = &http.Server{
		Addr:              s.listenAddr,
		Handler:           recovered,
		TLSConfig:         tlsCfgHTTP,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// QUIC server-side support is not available in semp-go v0.5.0:
	// the library now exposes only the client-side Dial path. Operators
	// that need a QUIC endpoint should pin to a future semp-go release
	// that restores the server-side listener.
	if s.quicAddr != "" {
		s.logger.Warn("quic listener requested but not supported in this release",
			"addr", s.quicAddr)
	}

	errCh := make(chan error, 1)
	go func() {
		if s.tlsCert != "" && s.tlsKey != "" {
			s.logger.Info("starting HTTPS server",
				"addr", s.listenAddr, "domain", s.domain)
			errCh <- s.httpSrv.ListenAndServeTLS(s.tlsCert, s.tlsKey)
		} else {
			s.logger.Info("starting HTTP server (no TLS)",
				"addr", s.listenAddr, "domain", s.domain)
			errCh <- s.httpSrv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server: %w", err)
		}
		return nil
	case <-ctx.Done():
		s.logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.forwarder.Close()
		return s.httpSrv.Shutdown(shutdownCtx)
	}
}

// advertisedSuites returns the suite list for the well-known
// configuration. The configured suite is listed first (preference
// order), followed by the baseline suite if it is not already the
// configured suite.
func (s *Server) advertisedSuites() []string {
	id := string(s.suite.ID())
	baseline := "x25519-chacha20-poly1305"
	if id == baseline {
		return []string{baseline}
	}
	return []string{id, baseline}
}

// Close releases resources.
func (s *Server) Close() error {
	s.forwarder.Close()
	_ = s.sqlInbox.Close()
	return s.store.DB().Close()
}

func loadTLSConfig(certFile, keyFile string, nextProtos ...string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   nextProtos,
	}, nil
}

// recoveryHandler returns an http.Handler that catches panics from
// the wrapped handler, logs them, and returns a generic 500 response
// without exposing stack traces to the client (security audit
// finding 6.3).
func (s *Server) recoveryHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				s.logger.Error("panic recovered in HTTP handler",
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(stack),
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// fetchDomainSigningKeyFromWellKnown fetches a domain's signing
// public key. It first resolves the SRV target for _semp._tcp.<domain>
// and fetches from that hostname. If SRV lookup fails, it falls back
// to the bare domain.
func fetchDomainSigningKeyFromWellKnown(domain string) ([]byte, error) {
	host := domain
	// Try DNS SRV to find the actual server hostname.
	_, addrs, err := net.DefaultResolver.LookupSRV(context.Background(), "semp", "tcp", domain)
	if err == nil && len(addrs) > 0 {
		target := strings.TrimSuffix(addrs[0].Target, ".")
		if target != "" {
			host = target
		}
	}

	url := "https://" + host + "/.well-known/semp/domain-keys"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", url, resp.StatusCode)
	}
	var result struct {
		SigningKey *struct {
			PublicKey string `json:"public_key"`
		} `json:"signing_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	if result.SigningKey == nil {
		return nil, fmt.Errorf("no signing key in response from %s", url)
	}
	return base64.StdEncoding.DecodeString(result.SigningKey.PublicKey)
}
