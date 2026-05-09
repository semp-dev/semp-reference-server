# Deploying on Dokploy

[Dokploy](https://dokploy.com) is an open-source self-hosted PaaS that runs on your own VPS. It uses Traefik for routing, automatic Let's Encrypt for TLS, and Docker Compose for orchestration. WebSocket upgrades on `/v1/ws` and `/v1/federate` work without extra configuration.

## Prerequisites

* A VPS with Dokploy installed
* DNS A/AAAA record pointing your hostname (e.g. `semp.example.com`) at the VPS
* DNS SRV/TXT records for the email domain (see the main README's "DNS Records" section)

## Steps

### 1. Create the application

In the Dokploy UI:

* Click **Create Service** > **Compose**
* Repository: `https://github.com/semp-dev/semp-reference-server`
* Branch: `master`
* Compose path: `deploy/docker-compose.yml`

### 2. Set the SEMP_HOST environment variable

In the Dokploy service's **Environment** tab, add:

```
SEMP_HOST=semp.example.com
```

Use your actual hostname. The compose file in the next step substitutes this value into the Traefik router rule, so a missing or wrong value here is the most common cause of a 404 from Traefik.

### 3. Override the compose file

Replace the rendered compose with:

```yaml
services:
  semp:
    build:
      context: ..
      dockerfile: Dockerfile
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

The `${SEMP_HOST:?...}` syntax fails the deploy with a clear error if the env var is unset, instead of silently routing nowhere.

### 4. Configure semp.toml

Edit `deploy/semp.toml` (Dokploy will mount it into the container):

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

## Notes

* **QUIC/HTTP3** is not covered here. Traefik can route UDP, but it requires a UDP entrypoint and the certificate mounted into the container, which sits outside Dokploy's UI workflow. Most operators run TCP-only.
* **Updates** redeploy from the same branch. SQLite data and domain keys persist in the `semp-data` volume.
* **Backup** the volume by running `docker run --rm -v semp-data:/data -v $(pwd):/backup alpine tar czf /backup/semp-backup.tgz /data` on the host.
