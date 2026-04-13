package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"semp.dev/semp-reference-server/internal/config"
	"semp.dev/semp-reference-server/internal/keygen"
	"semp.dev/semp-reference-server/internal/server"
	"semp.dev/semp-reference-server/internal/store"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "export-keys" {
		exportKeys()
		return
	}

	configPath := flag.String("config", "semp.toml", "path to TOML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	logger := slog.New(handler)

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("failed to create server", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Run(ctx); err != nil {
		logger.Error("server exited with error", "err", err)
		os.Exit(1)
	}
	logger.Info("server stopped")
}

// ExportedKeys is the JSON format for key export/import between server and client.
type ExportedKeys struct {
	Address        string `json:"address"`
	Domain         string `json:"domain"`
	IdentityPub    string `json:"identity_public_key"`
	IdentityPriv   string `json:"identity_private_key"`
	IdentityFP     string `json:"identity_fingerprint"`
	EncryptionPub  string `json:"encryption_public_key"`
	EncryptionPriv string `json:"encryption_private_key"`
	EncryptionFP   string `json:"encryption_fingerprint"`
	Algorithm      string `json:"algorithm"`
}

func exportKeys() {
	fs := flag.NewFlagSet("export-keys", flag.ExitOnError)
	configPath := fs.String("config", "semp.toml", "path to TOML configuration file")
	address := fs.String("address", "", "user address to export (required)")
	output := fs.String("o", "", "output file (default: stdout)")
	fs.Parse(os.Args[2:])

	if *address == "" {
		fmt.Fprintln(os.Stderr, "error: -address is required")
		fmt.Fprintln(os.Stderr, "usage: semp-server export-keys -address alice@example.com [-config semp.toml] [-o keys.json]")
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	db, err := store.InitDB(cfg.Database.Path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	sqlStore := store.NewSQLiteStore(db)
	suite := crypto.SuiteBaseline
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Ensure keys exist (in case export-keys is run before the server has started)
	_, _, _, _, err = keygen.EnsureDomainKeys(sqlStore, suite, cfg.Domain, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	idPriv, idFP, err := sqlStore.LoadDomainPrivateKey(*address, "")
	_ = idPriv
	_ = idFP

	// Load identity key
	identityPriv, identityFP, err := sqlStore.LoadUserPrivateKey(*address, keys.TypeIdentity)
	if err != nil || identityPriv == nil {
		fmt.Fprintf(os.Stderr, "error: no identity key found for %s\n", *address)
		os.Exit(1)
	}
	identityPubBytes, identityPubFP, err := sqlStore.LoadUserPublicKey(*address, keys.TypeIdentity)
	if err != nil || identityPubBytes == nil {
		fmt.Fprintf(os.Stderr, "error: no identity public key found for %s\n", *address)
		os.Exit(1)
	}
	_ = identityPubFP

	// Load encryption key
	encPriv, encFP, err := sqlStore.LoadUserPrivateKey(*address, keys.TypeEncryption)
	if err != nil || encPriv == nil {
		fmt.Fprintf(os.Stderr, "error: no encryption key found for %s\n", *address)
		os.Exit(1)
	}
	encPubBytes, encPubFP, err := sqlStore.LoadUserPublicKey(*address, keys.TypeEncryption)
	if err != nil || encPubBytes == nil {
		fmt.Fprintf(os.Stderr, "error: no encryption public key found for %s\n", *address)
		os.Exit(1)
	}
	_ = encPubFP

	exported := ExportedKeys{
		Address:        *address,
		Domain:         cfg.Domain,
		IdentityPub:    base64.StdEncoding.EncodeToString(identityPubBytes),
		IdentityPriv:   base64.StdEncoding.EncodeToString(identityPriv),
		IdentityFP:     string(identityFP),
		EncryptionPub:  base64.StdEncoding.EncodeToString(encPubBytes),
		EncryptionPriv: base64.StdEncoding.EncodeToString(encPriv),
		EncryptionFP:   string(encFP),
		Algorithm:      string(suite.ID()),
	}

	data, _ := json.MarshalIndent(exported, "", "  ")

	if *output != "" {
		if err := os.WriteFile(*output, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "exported keys for %s to %s\n", *address, *output)
	} else {
		fmt.Println(string(data))
	}
}
