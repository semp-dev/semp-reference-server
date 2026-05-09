# Deploying on Dokploy

[Dokploy](https://dokploy.com) is an open-source self-hosted PaaS that runs on your own VPS. It uses Traefik for routing, automatic Let's Encrypt for TLS, and Docker Compose for orchestration. WebSocket upgrades on `/v1/ws` and `/v1/federate` work without extra configuration.

## Prerequisites

* A VPS with Dokploy installed
* DNS A/AAAA record pointing your hostname (e.g. `semp.example.com`) at the VPS
* DNS SRV/TXT records for the email domain (see the main README's "DNS Records" section)

## Pick an implementation

This guide deploys ONE impl per stack. Both Go and TS are wire-compatible; pick one. See [`README.md`](README.md) for the comparison table. The compose snippet below uses an `IMPL` build arg; switch by changing that one line.

## Steps

### 1. Create the application

In the Dokploy UI:

* Click **Create Service** > **Compose**
* Repository: `https://github.com/semp-dev/semp-reference-server`
* Branch: `master`
* Compose path: `shared/deploy/docker-compose.yml`

### 2. Set required environment variables

In the Dokploy service's **Environment** tab, add:

```
SEMP_HOST=semp.example.com
SEMP_IMPL=go
```

`SEMP_HOST` controls Traefik routing. `SEMP_IMPL` is `go` or `ts`; pick one.

### 3. Override the compose file

Replace the rendered compose with:

```yaml
services:
  semp:
    build:
      context: ../..
      dockerfile: docker/${SEMP_IMPL:-go}.Dockerfile
    restart: unless-stopped
    volumes:
      - semp-data:/var/lib/semp
      - ./semp.toml:/etc/semp/semp.toml:ro
    networks:
      - dokploy-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.semp.rule=Host(`${SEMP_HOST:?SEMP_HOST must be set in the Environment tab}`)"
      - "traefik.http.routers.semp.entrypoints=websecure"
      - "traefik.http.routers.semp.tls.certresolver=letsencrypt"
      - "traefik.http.services.semp.loadbalancer.server.port=8443"

networks:
  dokploy-network:
    external: true

volumes:
  semp-data:
```

The `${SEMP_HOST:?...}` syntax fails the deploy with a clear error if the env var is unset, instead of silently routing nowhere. The `${SEMP_IMPL:-go}` default falls back to the Go impl when unset.

### 4. Configure semp.toml

Edit `shared/deploy/semp.toml` (Dokploy will mount it into the container):

```toml
domain = "example.com"
listen_addr = ":8443"

[crypto]
suite = "pq-kyber768-x25519"

[database]
path = "/var/lib/semp/semp.db"

[[users]]
address  = "alice@example.com"
password = "changeme"

[policy]
session_ttl = 300
permissions = ["send", "receive"]
```

Leave the `[tls]` block commented out. Traefik terminates TLS at the edge and the container speaks plain HTTP inside the Docker network.

If discovery responses need to advertise `wss://` (they will, in production), add:

```toml
[tls]
external_tls = true
```

### 5. Deploy

Click **Deploy**. Traefik issues the Let's Encrypt certificate on first request. WebSocket upgrades pass through automatically.

## Verify

```sh
curl -i https://semp.example.com/.well-known/semp/configuration
```

Expect a `200` with JSON listing the WS, H2, and registration endpoints.

```sh
curl -i \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://semp.example.com/v1/ws
```

Expect `101 Switching Protocols`. The handshake will then fail (this is just a curl request, not a SEMP client), but `101` confirms the WebSocket plumbing works end to end.

## Switching impls

Change `SEMP_IMPL` in the Environment tab and redeploy. The container is rebuilt from the other Dockerfile against the same `semp-data` volume; the SQL schema is identical between impls so existing data persists.

For staging-vs-production interop testing, deploy two stacks under different hostnames (one with `SEMP_IMPL=go`, one with `SEMP_IMPL=ts`) and federate them via `[[federation.peers]]` in each `semp.toml`.

## Notes

* **QUIC/HTTP3** works only with the Go impl, and even then it is not covered here. Traefik can route UDP, but it requires a UDP entrypoint and the certificate mounted into the container, which sits outside Dokploy's UI workflow. Most operators run TCP-only.
* **Updates** redeploy from the same branch. SQLite data and domain keys persist in the `semp-data` volume.
* **Backup** the volume by running `docker run --rm -v semp-data:/data -v $(pwd):/backup alpine tar czf /backup/semp-backup.tgz /data` on the host.
