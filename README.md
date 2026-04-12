# SEMP Reference Server

A reference implementation of a [SEMP](https://semp.dev) (Sealed Envelope Messaging Protocol) server, built on the [semp-go](https://github.com/semp-dev/semp-go) library.

This server demonstrates real-world deployment of the SEMP protocol: client connections, cross-domain federation, discovery endpoints, SQLite-backed storage, TLS, and operator-configurable policy.

## Features

- **Client WebSocket endpoint** (`/v1/ws`) — handshake, envelope submission, envelope fetch, key requests, in-session rekeying
- **Federation WebSocket endpoint** (`/v1/federate`) — server-to-server handshake and envelope delivery with full 9-step delivery pipeline verification
- **Well-known discovery** (`/.well-known/semp/configuration`) — protocol discovery per DISCOVERY.md
- **Well-known key publication** (`/.well-known/semp/keys/{address}`) — user key lookup per KEY.md
- **SQLite storage** — persistent domain keys, user keys, device certificates, and inbox with crash recovery
- **First-run key generation** — Ed25519 signing and X25519 encryption keys generated automatically on first start
- **Config-file provisioning** — users defined in TOML, keys generated on first run and persisted
- **Configurable policy** — session TTL, domain blocklist, client permissions
- **Federation forwarding** — lazy session establishment to remote peers with automatic rekeying at 80% TTL
- **TLS support** — optional cert/key paths; plain HTTP for development
- **Graceful shutdown** — clean connection draining on SIGINT/SIGTERM

## Quick Start

```bash
# Clone and build
git clone https://github.com/seyitgkc/semp-reference-server.git
cd semp-reference-server
go build -o semp-server ./cmd/semp-server/

# Create a config file
cp config.example.toml semp.toml
# Edit semp.toml to set your domain and users

# Run
./semp-server -config semp.toml
```

On first run the server generates domain and user keys and stores them in the SQLite database. Subsequent runs load existing keys.

## Configuration

See [`config.example.toml`](config.example.toml) for all options. Minimal example:

```toml
domain = "example.com"
listen_addr = ":8443"

[database]
path = "semp.db"

[[users]]
address = "alice@example.com"

[[users]]
address = "bob@example.com"
```

### TLS

For production, provide certificate and key paths:

```toml
[tls]
cert_file = "/etc/semp/cert.pem"
key_file  = "/etc/semp/key.pem"
```

When TLS is not configured the server runs plain HTTP (development only).

### Federation

To federate with another SEMP server, add it as a peer:

```toml
[[federation.peers]]
domain             = "other.example"
endpoint           = "wss://other.example/v1/federate"
domain_signing_key = "base64-encoded-ed25519-public-key"
```

Peers without an explicit endpoint are resolved via DNS SRV/TXT and well-known URI discovery.

### Policy

```toml
[policy]
session_ttl     = 300                  # Client session lifetime in seconds
blocked_domains = ["spam.example"]     # Rejected at handshake
permissions     = ["send", "receive"]
```

## Architecture

The server is built on `semp-go` and follows the same wiring pattern as the library's demo binary, structured for production use:

```
cmd/semp-server/main.go        Entry point, config loading, signal handling
internal/config/                TOML config parsing and validation
internal/store/                 SQLite-backed keys.Store, SharedStore, and inbox
internal/keygen/                First-run domain and user key generation
internal/server/                HTTP server, WebSocket handlers, policy, lifecycle
```

All protocol logic (handshakes, envelope encryption, delivery pipeline, session management, transport bindings) lives in `semp-go`. This server provides the storage, configuration, and operational wiring around it.

### Storage

The server uses SQLite (via [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite), pure Go, no CGO) for:

- **Domain keys** — signing and encryption keypairs with private key material
- **User keys** — identity and encryption keypairs per provisioned user
- **Device certificates** — scoped delegation certificates (KEY.md section 10.3)
- **Inbox** — durable envelope queue with crash-recovery rehydration on startup

The in-memory `delivery.Inbox` required by the library is backed by SQLite for persistence across restarts.

## Roadmap

- [ ] **Reference client implementation** — a companion CLI client in this repository for end-to-end testing and demonstration of the full SEMP flow (handshake, send, receive, key management)
- [ ] Registration API for runtime user and device provisioning
- [ ] Encrypted-at-rest private key storage (KEY.md section 9)
- [ ] Structured metrics and tracing
- [ ] Proof-of-work challenge gating
- [ ] Block list management API

## Requirements

- Go 1.25 or later
- No CGO required (pure-Go SQLite driver)

## Dependencies

- [`semp.dev/semp-go`](https://github.com/semp-dev/semp-go) — SEMP protocol library
- [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml) — TOML configuration
- [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) — Pure-Go SQLite driver

## License

MIT
