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
	"strings"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/h2"
	"semp.dev/semp-go/transport/quic"
	"semp.dev/semp-go/transport/ws"
	"semp.dev/semp-reference-server/internal/config"
	"semp.dev/semp-reference-server/internal/keygen"
	"semp.dev/semp-reference-server/internal/store"
)

// Server is the SEMP reference server.
type Server struct {
	domain         string
	listenAddr     string
	tlsCert        string
	tlsKey         string
	externalTLS    bool
	quicAddr       string
	fedSessionTTL  int
	fedRetention   string

	suite          crypto.Suite
	domainSignFP   keys.Fingerprint
	domainSignPriv []byte
	domainEncFP    keys.Fingerprint
	domainEncPriv  []byte

	store     *store.SQLiteStore
	inbox     *delivery.Inbox
	sqlInbox  *store.SQLiteInbox
	forwarder *inboxd.Forwarder
	blockList *store.SQLiteBlockList
	policy    *Policy
	users     map[string]string // address → password

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

	signFP, signPriv, encFP, encPriv, err := keygen.EnsureDomainKeys(
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

	// Register federation peers. Signing keys are fetched lazily
	// via the store's DomainKeyFetcher when the first handshake needs them.
	peerRegistry := inboxd.NewPeerRegistry()
	for _, p := range cfg.Federation.Peers {
		peerCfg := inboxd.PeerConfig{
			Domain:   p.Domain,
			Endpoint: p.Endpoint,
		}
		// If a signing key is explicitly configured, pre-cache it.
		if p.DomainSigningKey != "" {
			pubBytes, err := base64.StdEncoding.DecodeString(p.DomainSigningKey)
			if err != nil {
				return nil, fmt.Errorf("decode peer %s signing key: %w", p.Domain, err)
			}
			peerCfg.DomainSigningKey = pubBytes
			sqlStore.PutDomainKey(p.Domain, pubBytes)
		}
		peerRegistry.Put(peerCfg)
		logger.Info("registered federation peer", "domain", p.Domain, "endpoint", p.Endpoint)
	}

	allowInsecure := cfg.TLS.CertFile == "" && !cfg.TLS.ExternalTLS
	wsTransport := ws.NewWithConfig(ws.Config{
		AllowInsecure:  allowInsecure,
		OriginPatterns: []string{"*"},
	})
	h2Transport := h2.NewWithConfig(h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: allowInsecure},
	})

	resolver := discovery.NewResolver(discovery.ResolverConfig{
		Cache: discovery.NewMemCache(),
	})

	forwarder := inboxd.NewForwarder(inboxd.ForwarderConfig{
		Suite:                 suite,
		LocalDomain:           cfg.Domain,
		LocalDomainKeyID:      signFP,
		LocalDomainPrivateKey: signPriv,
		Peers:                 peerRegistry,
		Dial: func(ctx context.Context, endpoint string) (transport.Conn, error) {
			// Try WebSocket first for wss:// endpoints (existing peers),
			// fall back to HTTP/2 for https:// endpoints (baseline transport).
			if strings.HasPrefix(endpoint, "wss://") || strings.HasPrefix(endpoint, "ws://") {
				return wsTransport.Dial(ctx, endpoint)
			}
			return h2Transport.Dial(ctx, endpoint)
		},
		Store:    sqlStore,
		Resolver: resolver,
		FederationEndpointFunc: func(result *discovery.Result) (string, error) {
			ep, err := inboxd.DefaultFederationEndpointFunc(result)
			if err != nil {
				return "", err
			}
			// Convert ws:// endpoints to https:// for HTTP/2 federation.
			ep = strings.Replace(ep, "wss://", "https://", 1)
			ep = strings.Replace(ep, "ws://", "http://", 1)
			ep = strings.Replace(ep, "/v1/ws", "/v1/federate", 1)
			return ep, nil
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
		store:          sqlStore,
		inbox:          memInbox,
		sqlInbox:       sqlInbox,
		forwarder:      forwarder,
		blockList:      blockList,
		policy:         policy,
		users:          users,
		metrics:        metrics,
		logger:         logger,
	}
	return s, nil
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx

	allowInsecure := s.tlsCert == "" && !s.externalTLS
	wsCfg := ws.Config{
		AllowInsecure:  allowInsecure,
		OriginPatterns: []string{"*"},
	}
	h2Cfg := h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: allowInsecure},
	}

	mux := http.NewServeMux()

	// WebSocket transport (recommended).
	mux.Handle("/v1/ws", ws.NewHandler(wsCfg, func(conn transport.Conn) {
		go s.handleClient(s.ctx, conn)
	}))
	mux.Handle("/v1/federate", ws.NewHandler(wsCfg, func(conn transport.Conn) {
		go s.handleFederation(s.ctx, conn)
	}))

	// HTTP/2 transport (mandatory baseline per TRANSPORT.md section 4).
	mux.Handle("/v1/h2", h2.NewPersistentHandler(h2Cfg, func(conn transport.Conn) {
		go s.handleClient(s.ctx, conn)
	}))
	mux.Handle("/v1/h2/federate", h2.NewPersistentHandler(h2Cfg, func(conn transport.Conn) {
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

	s.httpSrv = &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Start QUIC listener if configured.
	if s.quicAddr != "" && s.tlsCert != "" && s.tlsKey != "" {
		tlsCfg, err := loadTLSConfig(s.tlsCert, s.tlsKey)
		if err != nil {
			return fmt.Errorf("quic tls: %w", err)
		}
		quicTransport := quic.NewWithConfig(quic.Config{
			TLSConfig: tlsCfg,
		})
		quicListener, err := quicTransport.Listen(ctx, s.quicAddr)
		if err != nil {
			return fmt.Errorf("quic listen: %w", err)
		}
		s.logger.Info("starting QUIC server", "addr", s.quicAddr)
		go func() {
			for {
				conn, err := quicListener.Accept(ctx)
				if err != nil {
					return
				}
				go s.handleClient(ctx, conn)
			}
		}()
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

// Close releases resources.
func (s *Server) Close() error {
	s.forwarder.Close()
	_ = s.sqlInbox.Close()
	return s.store.DB().Close()
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}, nil
}

// fetchDomainSigningKeyFromWellKnown fetches a domain's signing public key.
// It first resolves the SRV target for _semp._tcp.<domain> and fetches from
// that hostname. If SRV lookup fails, it falls back to the bare domain.
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
