# SEMP Reference Server

A reference implementation of a [SEMP](https://semp.dev) (Sealed Envelope Messaging Protocol) server, built on the [semp-go](https://github.com/semp-dev/semp-go) library.

This server demonstrates real-world deployment of the SEMP protocol: client connections, cross-domain federation, discovery endpoints, SQLite-backed storage, TLS, and operator-configurable policy.

## Features

- **Client WebSocket endpoint** (`/v1/ws`) — handshake, envelope submission, envelope fetch, key requests, in-session rekeying
- **Federation WebSocket endpoint** (`/v1/federate`) — server-to-server handshake and envelope delivery with full 9-step delivery pipeline verification
- **Registration API** (`POST /v1/register`) — clients generate keys locally and register public keys with the server
- **Well-known discovery** (`/.well-known/semp/configuration`) — protocol discovery per DISCOVERY.md
- **Well-known key publication** (`/.well-known/semp/keys/{address}`, `/.well-known/semp/domain-keys`) — user and domain key lookup
- **Automatic federation** — peer domain keys fetched lazily via well-known endpoints over HTTPS; no manual key exchange required
- **SQLite storage** — persistent domain keys, user keys, device certificates, and inbox with crash recovery
- **Configurable policy** — session TTL, domain blocklist, client permissions
- **TLS support** — direct cert/key, external TLS (reverse proxy), or plain HTTP for development
- **Graceful shutdown** — clean connection draining on SIGINT/SIGTERM

## Quick Start

```bash
# Clone and build
git clone https://github.com/semp-dev/semp-reference-server.git
cd semp-reference-server
go build -o semp-server ./cmd/semp-server/

# Create a config file
cp config.example.toml semp.toml
# Edit semp.toml — set your domain, users, and passwords

# Run
./semp-server -config semp.toml
```

On first run the server generates its domain signing and encryption keys. User keys are registered by clients via `POST /v1/register` — the server never generates or stores user private keys.

## Configuration

See [`config.example.toml`](config.example.toml) for all options. Minimal example:

```toml
domain = "example.com"
listen_addr = ":8443"

[database]
path = "semp.db"

[[users]]
address  = "alice@example.com"
password = "changeme"

[[users]]
address  = "bob@example.com"
password = "changeme"
```

### TLS

For production, provide certificate and key paths:

```toml
[tls]
cert_file = "/etc/semp/cert.pem"
key_file  = "/etc/semp/key.pem"
```

When TLS is terminated by a reverse proxy (Cloudflare, Traefik, Caddy), set `external_tls = true` so discovery responses advertise `wss://`:

```toml
[tls]
external_tls = true
```

When TLS is not configured at all the server runs plain HTTP (development only).

### Federation

Federation is automatic. Any domain with DNS SRV/TXT records and a `/.well-known/semp/domain-keys` endpoint is reachable without configuration. Domain signing keys are fetched lazily over HTTPS on the first federation handshake and cached locally.

Optionally, you can pre-configure peers:

```toml
[[federation.peers]]
domain = "other.example"
# endpoint and domain_signing_key are optional — resolved automatically
```

### Policy

```toml
[policy]
session_ttl     = 300                  # Client session lifetime in seconds
blocked_domains = ["spam.example"]     # Rejected at handshake
permissions     = ["send", "receive"]
```

## Docker Deployment

### Prerequisites

- A server with a public IP
- A domain with an A record pointing to that IP
- Docker installed

### Choosing a Hostname

The server hostname is independent of the email domain. You can use any subdomain:

| Email domain | Server hostname | Works? |
|---|---|---|
| `example.com` | `semp.example.com` | Yes |
| `example.com` | `mail.example.com` | Yes |
| `example.com` | `example.com` | Yes |

The `domain` field in `semp.toml` is always the **email domain** (e.g. `example.com`). Your reverse proxy (Traefik, Caddy, Cloudflare) handles TLS for the server hostname.

### Deploy

```bash
docker build -t semp-server .
docker run -d \
  --name semp-server \
  --restart unless-stopped \
  -v semp-data:/var/lib/semp \
  -p 8443:8443 \
  semp-server
```

If baking the config into the image, place `semp.toml` alongside the Dockerfile. Otherwise mount it:

```bash
docker run -d \
  -v ./semp.toml:/etc/semp/semp.toml:ro \
  -v semp-data:/var/lib/semp \
  -p 8443:8443 \
  semp-server
```

### DNS Records

Point your chosen hostname to the server, then add SEMP discovery records for the email domain:

```
; A record — point your hostname to the server
semp.example.com. 3600 IN A 203.0.113.10

; SRV record — tells other SEMP servers where to reach @example.com users
_semp._tcp.example.com. 3600 IN SRV 10 1 443 semp.example.com.

; TXT record — advertises SEMP support for the domain
_semp._tcp.example.com. 3600 IN TXT "v=semp1"
```

The SRV record maps the email domain to the server hostname. Federation peers use this to discover your endpoint automatically.

### Data

SQLite database is persisted in a Docker volume (`semp-data`). Back it up with:

```bash
docker cp $(docker ps -qf name=semp-server):/var/lib/semp/semp.db ./semp-backup.db
```

## Connecting with the Reference Client

The [SEMP Reference Client](https://github.com/semp-dev/semp-reference-client) provides both a CLI and a desktop GUI.

### Install

```bash
git clone https://github.com/semp-dev/semp-reference-client.git
cd semp-reference-client
go build -o semp-client ./cmd/semp-client/
```

### Create a Config

```toml
# alice.toml
identity = "alice@example.com"
server   = "wss://semp.example.com/v1/ws"

[database]
path = "alice.db"

[tls]
insecure = false
```

### Register

Each user generates keys locally and registers with the server:

```bash
./semp-client -config alice.toml register -password changeme
./semp-client -config bob.toml register -password changeme
```

This generates Ed25519 identity and X25519 encryption key pairs on the client, pushes only the public keys to the server, and caches the server's domain keys locally. **Private keys never leave the client device.**

### Send and Receive

```bash
# Alice sends a message to Bob
./semp-client -config alice.toml send \
  -to bob@example.com \
  -subject "Hello" \
  -body 'Just SEMPing real quick'

# Bob fetches and decrypts his pending messages
./semp-client -config bob.toml fetch

# Bob lists his inbox
./semp-client -config bob.toml inbox
```

### Example Output

Real output from a live deployment:

**Alice sends:**
```
$ ./semp-client -config alice.toml send -to bob@example.com -subject "Hello" -body 'Just SEMPing real quick'
level=INFO msg=connected server=wss://semp.example.com/v1/ws
level=INFO msg="session established" session_id=06ERA4E8HSKAK83ZJQN5NBNXTC ttl=5m0s
level=INFO msg="envelope sent" message_id=alice@example.com-1776054028518410000 to=[bob@example.com]
Envelope submitted: alice@example.com-1776054028518410000
  bob@example.com: delivered
```

**Server log:**
```
level=INFO msg="client connected" peer=192.168.1.10:40648
level=INFO msg="client session established" session=06ERA4E8HSKAK83ZJQN5NBNXTC identity=alice@example.com ttl=5m0s
level=INFO msg="[delivery] delivered: envelope=alice@example.com-1776054028518410000 recipient=bob@example.com sender=alice@example.com"
level=INFO msg="client disconnected" peer=192.168.1.10:40648
```

**Bob fetches:**
```
$ ./semp-client -config bob.toml fetch
level=INFO msg=connected server=wss://semp.example.com/v1/ws
level=INFO msg="session established" session_id=06ERA4P18PF4HPGEHAQX8HKNJM ttl=5m0s
level=INFO msg="fetched envelopes" count=1 drained=true

--- Message alice@example.com-1776054028518410000 ---
From:    alice@example.com
To:      bob@example.com
Subject: Hello
Body:
Just SEMPing real quick

1 message(s) fetched.
```

### Cross-Domain Federation

Real output from a federated delivery between two independent servers:

**Alice on `alpha.com` sends to Bob on `beta.com`:**
```
$ ./semp-client -config alice.toml send -to bob@beta.com -subject "Cross-domain" -body 'First federated SEMP message!'
level=INFO msg=connected server=wss://semp.alpha.com/v1/ws
level=INFO msg="session established" session_id=06ERB6WQZMTY7HBDE1GYWATTS4 ttl=5m0s
level=INFO msg="envelope sent" message_id=alice@alpha.com-1776063060023381000 to=[bob@beta.com]
Envelope submitted: alice@alpha.com-1776063060023381000
  bob@beta.com: delivered
```

**Bob on `beta.com` fetches:**
```
$ ./semp-client -config bob.toml fetch
level=INFO msg=connected server=wss://msg.beta.com/v1/ws
level=INFO msg="session established" session_id=06ERB71K2FSFG12EVJ2XCSXK08 ttl=5m0s
level=INFO msg="fetched envelopes" count=1 drained=true

--- Message alice@alpha.com-1776063060023381000 ---
From:    alice@alpha.com
To:      bob@beta.com
Subject: Cross-domain
Body:
First federated SEMP message!

1 message(s) fetched.
```

No manual key exchange, no static peer configuration. The servers discovered each other via DNS SRV records and exchanged domain signing keys automatically over HTTPS.

### Other Commands

```bash
./semp-client -config alice.toml status                              # identity, keys, server info
./semp-client -config alice.toml keys -address bob@example.com       # look up recipient keys
./semp-client -config bob.toml export <message-id> -o message.semp   # export as .semp file
./semp-client -config bob.toml import message.semp                   # import and decrypt .semp
./semp-client -config alice.toml sent                                # list sent messages
```

### Desktop GUI

```bash
go run ./cmd/semp-gui -config alice.toml
```

### Local Development (No TLS)

```toml
server = "ws://localhost:8443/v1/ws"

[tls]
insecure = true
```

## Architecture

```
cmd/semp-server/main.go        Entry point, config loading, signal handling
internal/config/                TOML config parsing and validation
internal/store/                 SQLite-backed keys.Store, SharedStore, and inbox
internal/keygen/                Domain key generation (user keys are client-generated)
internal/server/                HTTP server, WebSocket handlers, registration, policy
```

All protocol logic (handshakes, envelope encryption, delivery pipeline, session management, transport bindings) lives in [semp-go](https://github.com/semp-dev/semp-go). This server provides storage, configuration, and operational wiring.

### Key Provisioning

```
Client                                       Server
  |                                            |
  |  1. Generate identity + encryption keys    |
  |     (keys stay on device)                  |
  |                                            |
  |  2. POST /v1/register ------------------>  |
  |     { address, password, public keys }     |
  |                                            |
  |  <-- 200 OK  ----------------------------- |
  |     { domain signing key,                  |
  |       domain encryption key }              |
  |                                            |
  |  3. Cache domain keys locally              |
  |     (for handshake verification)           |
  |                                            |
  |  4. Connect via WebSocket, handshake       |
  |     (server verifies client identity       |
  |      against registered public key)        |
```

### Federation

```
Server A (example.com)                    Server B (other.example)
  |                                         |
  |  1. Envelope for bob@other.example      |
  |     arrives from local client           |
  |                                         |
  |  2. DNS SRV lookup:                     |
  |     _semp._tcp.other.example            |
  |     → semp.other.example:443            |
  |                                         |
  |  3. Fetch domain signing key:           |
  |     GET /.well-known/semp/domain-keys   |
  |     (cached after first fetch)          |
  |                                         |
  |  4. Federation handshake  ------------> |
  |  5. Forward envelope  ---------------> |
  |                              delivered  |
```

### Storage

SQLite (via [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite), pure Go, no CGO):

- **Domain keys** — server's own signing and encryption keypairs
- **User keys** — registered public keys (no private keys on server)
- **Device certificates** — scoped delegation certificates (KEY.md section 10.3)
- **Inbox** — durable envelope queue with crash-recovery rehydration on startup

## Roadmap

- [x] **Reference client** (see [semp-reference-client](https://github.com/semp-dev/semp-reference-client), CLI + desktop GUI)
- [x] Registration API for client key provisioning (`POST /v1/register`)
- [x] Automatic federation with lazy domain key discovery via DNS SRV
- [x] Post-quantum crypto suite (`pq-kyber768-x25519` hybrid, configurable)
- [x] HTTP/2 transport as mandatory baseline per spec (`/v1/h2`, `/v1/h2/federate`)
- [x] Well-known domain key publication (`/.well-known/semp/domain-keys`)
- [x] Cross-domain federation tested across live independent servers
- [ ] Encrypted-at-rest private key storage (KEY.md section 9)
- [ ] Structured metrics and tracing
- [ ] Proof-of-work challenge gating
- [ ] Block list management API
- [ ] QUIC transport binding
- [ ] Multi-device support with scoped device certificates

## Requirements

- Go 1.25 or later
- No CGO required (pure-Go SQLite driver)

## Dependencies

- [`semp.dev/semp-go`](https://github.com/semp-dev/semp-go) v0.2.2 — SEMP protocol library
- [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml) — TOML configuration
- [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) — Pure-Go SQLite driver

## License

MIT
