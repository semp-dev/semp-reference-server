# Deploying on Coolify

[Coolify](https://coolify.io) is an open-source self-hosted PaaS that uses Traefik for routing and automatic Let's Encrypt for TLS. The deployment shape is similar to Dokploy.

## Prerequisites

* A VPS with Coolify installed
* DNS A/AAAA record pointing your hostname (e.g. `semp.example.com`) at the VPS
* DNS SRV/TXT records for the email domain (see the main README's "DNS Records" section)

## Steps

### 1. Create the resource

In the Coolify UI:

* Click **+ New Resource** > **Docker Compose**
* Connect a Git source pointing at `https://github.com/semp-dev/semp-reference-server`, branch `master`
* Set **Base Directory** to `/deploy`
* Set **Docker Compose Location** to `/deploy/docker-compose.yml`

### 2. Set the SEMP_HOST environment variable

In the Coolify resource's **Environment Variables** tab, add:

```
SEMP_HOST=semp.example.com
```

Use your actual hostname. The compose file in the next step substitutes this value into the Traefik router rule, so a missing or wrong value here is the most common cause of a 404 from Traefik.

### 3. Override the compose file

Coolify lets you edit the compose inline. Replace it with:

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
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.semp.rule=Host(`${SEMP_HOST:?SEMP_HOST must be set in Environment Variables}`)"
      - "traefik.http.routers.semp.entrypoints=https"
      - "traefik.http.routers.semp.tls=true"
      - "traefik.http.routers.semp.tls.certresolver=letsencrypt"
      - "traefik.http.services.semp.loadbalancer.server.port=8443"

volumes:
  semp-data:
```

Coolify automatically attaches the service to its proxy network, so no `networks:` block is needed. The `${SEMP_HOST:?...}` syntax fails the deploy with a clear error if the env var is unset.

### 4. Configure semp.toml

Edit `deploy/semp.toml` in the repo (or use Coolify's **Mounts** tab to provide a file at `/etc/semp/semp.toml`):

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

[tls]
external_tls = true
```

Leave `cert_file` and `key_file` unset. Traefik terminates TLS, and `external_tls = true` makes the discovery endpoint advertise `wss://` instead of `ws://`.

### 5. Set the domain

In the Coolify service's **General** tab, set the FQDN to `https://semp.example.com` (matching whatever you put in `SEMP_HOST`). Coolify generates baseline Traefik labels from the FQDN, but the explicit ones in the compose above take precedence and pin the upstream port to `8443`.

### 6. Deploy

Click **Deploy**. Coolify builds the Dockerfile, starts the container, and Traefik issues the certificate on first request.

## Verify

Same as the Dokploy guide:

```sh
curl -i https://semp.example.com/.well-known/semp/configuration
```

Expect `200` with the discovery JSON, then test the WS upgrade with a `Connection: Upgrade` request expecting `101`.

## Notes

* **Persistent storage** — Coolify manages the `semp-data` volume across deploys; SQLite and domain keys survive container rebuilds.
* **Logs** are visible in the **Logs** tab of the service. The reference server emits structured logs at `info` level by default.
* **Multiple environments** — clone the resource and change the host label to run staging and production on the same VPS.
