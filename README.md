# semp-reference-server

Reference SEMP server implementations. Demonstrates real deployment of the protocol: client connections, cross-domain federation, discovery endpoints, SQLite-backed storage, TLS, and operator-configurable policy.

## Layout

```
shared/        # language-neutral assets (config schema, SQL DDL, docs, deploy recipes)
impl/
  go/          # Go implementation (built on semp.dev/semp-go)
  ts/          # TypeScript implementation (built on @sempdev/semp)
docker/        # multi-stage Dockerfiles + docker-compose.yml
```

Each implementation reads the same TOML config shape (`shared/config/`), the same SQLite schema (`shared/schema/`), and produces byte-identical wire output. Cross-impl interop is exercised by the federation matrix in `semp-reference-client/shared/scripts/test-federation.sh`.

## Quick start

### Go

    cd impl/go
    go build -o semp-server ./cmd/semp-server
    ./semp-server -config ../../shared/config/config.example.toml

### TypeScript

    cd impl/ts
    npm install
    npm run build
    node dist/main.js -config ../../shared/config/config.example.toml

### Docker

    COMPOSE_PROFILES=go docker compose -f docker/docker-compose.yml up -d
    COMPOSE_PROFILES=ts docker compose -f docker/docker-compose.yml up -d

## Endpoints served

| Path | Speaks |
|---|---|
| `/v1/ws` | client WebSocket |
| `/v1/federate` | federation WebSocket |
| `/v1/h2`, `/v1/h2/federate` | client / federation HTTP/2 |
| `/v1/register` | user identity registration |
| `/v1/device/register` | delegated device certificate registration |
| `/v1/blocklist` | per-user block list management |
| `/.well-known/semp/configuration` | DISCOVERY.md §3 well-known config |
| `/.well-known/semp/keys/{address}` | per-user public-key fetch |
| `/.well-known/semp/domain-keys` | per-domain signing-key fetch |
| `/debug/metrics` | operator metrics |

QUIC (`tls.quic_addr`) is supported by `impl/go` only; `impl/ts` falls back to HTTP/2 + WS, which TRANSPORT.md §4 makes the mandatory baseline.

## Cross-language interop verified

The Go and TS server implementations are wire-compatible. Tested locally end-to-end (not yet in CI) with this matrix:

| Scenario | Verdict |
|---|---|
| Go server accepts Go client (same-impl) | pass |
| TS server accepts TS client (same-impl) | pass |
| Go server accepts TS client | pass |
| TS server accepts Go client | pass |
| Go server federates to TS server | pass (alice@a.local sends to bob@b.local; envelope forwarded; bob's enclosure decrypts and `sender_signature` verifies on Go reader) |
| TS server federates to Go server | pass (bob@b.local sends to alice@a.local; reverse direction passes the same shape) |

**Versions** (the four pieces that have to agree byte-for-byte): `semp-go v0.5.1`, `semp-ts v0.5.2`, `semp-reference-server` (this repo) `master`, `semp-reference-client` `master`. Each impl reads the same TOML, the same SQLite schema, and the same cross-language test vectors at `semp-spec/vectors/v1.0.0/`.

**Reproduce** the Go+TS federation pair locally:

    docker compose -f shared/deploy/docker-compose.federation.yml up -d --build

`semp-go` runs on `domain-a.local`, `semp-ts` on `domain-b.local`. Use either `semp-reference-client` impl to register users on each side and send across the pair.

## Operator deployment

`shared/deploy/` carries runtime-agnostic recipes for Dokploy, Coolify, Portainer (Traefik / Caddy reverse proxy configs), and Plesk. Each recipe points at `docker/docker-compose.yml` and selects the impl via `COMPOSE_PROFILES=go` or `COMPOSE_PROFILES=ts`.

## Related repos

- [`semp-go`](https://github.com/semp-dev/semp-go): Go protocol library.
- [`semp-ts`](https://github.com/semp-dev/semp-ts): TypeScript protocol library.
- [`semp-spec`](https://github.com/semp-dev/semp-spec): protocol specification.
- [`semp-reference-client`](https://github.com/semp-dev/semp-reference-client): reference client (also polyglot).

## License

MIT.
