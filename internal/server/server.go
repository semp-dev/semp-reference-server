package server

import (
	"context"
	"encoding/base64"
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
	policy    *Policy

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

	suite := crypto.SuiteBaseline

	signFP, signPriv, encFP, encPriv, err := keygen.EnsureDomainKeys(
		sqlStore, suite, cfg.Domain, logger)
	if err != nil {
		return nil, fmt.Errorf("domain keys: %w", err)
	}

	if err := keygen.EnsureUserKeys(sqlStore, suite, cfg.Users, logger); err != nil {
		return nil, fmt.Errorf("user keys: %w", err)
	}

	sqlInbox := store.NewSQLiteInbox(db)
	if err := sqlInbox.LoadPending(); err != nil {
		logger.Warn("loading pending inbox items", "err", err)
	}
	memInbox := sqlInbox.MemInbox()

	peerRegistry := inboxd.NewPeerRegistry()
	for _, p := range cfg.Federation.Peers {
		var pubBytes []byte
		if p.DomainSigningKey != "" {
			var err error
			pubBytes, err = base64.StdEncoding.DecodeString(p.DomainSigningKey)
			if err != nil {
				return nil, fmt.Errorf("decode peer %s signing key: %w", p.Domain, err)
			}
		} else {
			// Fetch the peer's domain signing key from their well-known endpoint.
			logger.Info("fetching peer domain signing key", "domain", p.Domain)
			var err error
			pubBytes, err = fetchPeerDomainSigningKey(p.Domain, p.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("fetch peer %s signing key: %w", p.Domain, err)
			}
			logger.Info("fetched peer domain signing key", "domain", p.Domain, "fingerprint", keys.Compute(pubBytes))
		}
		peerRegistry.Put(inboxd.PeerConfig{
			Domain:           p.Domain,
			Endpoint:         p.Endpoint,
			DomainSigningKey: pubBytes,
		})
		sqlStore.PutDomainKey(p.Domain, pubBytes)
		logger.Info("registered federation peer", "domain", p.Domain, "endpoint", p.Endpoint)
	}

	wsTransport := ws.NewWithConfig(ws.Config{
		AllowInsecure:  cfg.TLS.CertFile == "",
		OriginPatterns: []string{"*"},
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
			return wsTransport.Dial(ctx, endpoint)
		},
		Store:    sqlStore,
		Resolver: resolver,
		FederationEndpointFunc: func(result *discovery.Result) (string, error) {
			ep, err := inboxd.DefaultFederationEndpointFunc(result)
			if err != nil {
				return "", err
			}
			return strings.Replace(ep, "/v1/ws", "/v1/federate", 1), nil
		},
	})

	policy := NewPolicy(cfg.Policy)

	s := &Server{
		domain:         cfg.Domain,
		listenAddr:     cfg.ListenAddr,
		tlsCert:        cfg.TLS.CertFile,
		tlsKey:         cfg.TLS.KeyFile,
		externalTLS:    cfg.TLS.ExternalTLS,
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
		policy:         policy,
		logger:         logger,
	}
	return s, nil
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.ctx = ctx

	wsCfg := ws.Config{
		AllowInsecure:  s.tlsCert == "",
		OriginPatterns: []string{"*"},
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/ws", ws.NewHandler(wsCfg, func(conn transport.Conn) {
		go s.handleClient(s.ctx, conn)
	}))
	mux.Handle("/v1/federate", ws.NewHandler(wsCfg, func(conn transport.Conn) {
		go s.handleFederation(s.ctx, conn)
	}))
	mux.HandleFunc(discovery.WellKnownPath, s.handleWellKnownConfig)
	mux.HandleFunc("/.well-known/semp/keys/", s.handleWellKnownKeys)
	mux.HandleFunc("/.well-known/semp/domain-keys", s.handleWellKnownDomainKeys)

	s.httpSrv = &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
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
