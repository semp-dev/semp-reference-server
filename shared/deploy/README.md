# shared/deploy/

Operator-facing deployment recipes. Each recipe targets a specific
hosting platform (Dokploy, Coolify, Portainer, Plesk) and is
**language-implementation-agnostic** thanks to the `COMPOSE_PROFILES`
toggle.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Minimal one-server stack for an upstream reverse proxy. `COMPOSE_PROFILES=go\|ts` selects the impl. |
| `docker-compose.portainer.yml` | Caddy-fronted stack for Portainer (TLS terminates inside the stack). `SEMP_IMPL=go\|ts` env var selects the impl. |
| `docker-compose.federation.yml` | **Two-server federation pair (Go + TS) for cross-impl interop testing.** See "Interop testing" below. |
| `Caddyfile` | Caddy reverse-proxy config for the Portainer stack. |
| `semp.toml` | Production-shaped config template for one-server stacks. |
| `semp-domain-a.toml`, `semp-domain-b.toml` | Federation-pair configs for the interop stack. |
| `Dockerfile.plesk` | Plesk-specific image (Go-only) with operator helpers baked into `/usr/share/semp/`. |
| `build-plesk-image.sh` | Builds the Plesk image and exports it as a single `docker save` tarball. |
| `plesk-bundle/` | Operator helpers bundled into the Plesk image (`install.sh`, `plesk-nginx.conf`, README). |
| `coolify.md`, `dokploy.md`, `portainer.md`, `plesk.md` | Per-platform step-by-step. |

## Pick an implementation

Both `impl/go/` and `impl/ts/` are protocol-conformant: they pass the
same cross-language test vectors and produce byte-identical wire
output. Operators choose based on operational fit, not protocol fit.

| Property | `impl/go` | `impl/ts` |
|---|---|---|
| Runtime | Single static binary, no runtime deps | Node.js 22+ runtime |
| Image size | ~30 MB Alpine | ~150 MB Alpine + node_modules |
| Build deps | Go 1.26+ | Node 22+, `python3 make g++` (better-sqlite3) |
| QUIC support | Yes (TRANSPORT.md §4.3) | No (Node has no first-class QUIC server) |
| Memory footprint | ~20 MB resident | ~100 MB resident |
| Cold-start | <100 ms | ~500 ms |

Most operators pick Go for production. TS exists for shops that
already run Node tooling and want the polyglot parity.

## Interop testing

Both impls produce byte-identical wire output. The
`docker-compose.federation.yml` file makes this testable in one
command:

```bash
cd shared/deploy
docker compose -f docker-compose.federation.yml up -d --build
# domain-a.local served by Go, domain-b.local served by TS, both
# federated with each other on the same Docker network.
```

Then drive a cross-impl test: register a user on each server, send
an envelope from `alice@domain-a.local` to `bob@domain-b.local`,
and fetch it on the receiving side. Either impl of
`semp-reference-client` works for both ends (the client itself is
also language-agnostic on the wire).

A scripted runner lives at `shared/scripts/test-cross-impl.sh`.

## One-server deployments

For a single-server deployment behind your own reverse proxy:

```bash
# Pick the impl
COMPOSE_PROFILES=go docker compose -f shared/deploy/docker-compose.yml up -d
# or
COMPOSE_PROFILES=ts docker compose -f shared/deploy/docker-compose.yml up -d
```

For platform-managed deployments, follow the per-platform guide:

- **Dokploy**: see [`dokploy.md`](dokploy.md).
- **Coolify**: see [`coolify.md`](coolify.md).
- **Portainer**: see [`portainer.md`](portainer.md). Stack ships Caddy.
- **Plesk**: see [`plesk.md`](plesk.md). Single-image bundle. Go-only.

Each guide covers the impl-choice toggle and the platform-specific
nginx / Traefik / Caddy nuances.
