# Deploying on Portainer

[Portainer](https://www.portainer.io) is a Docker management UI. Unlike Dokploy or Coolify it does not bundle a reverse proxy, so this stack ships Caddy alongside the SEMP server to handle TLS and Let's Encrypt automatically.

## Prerequisites

* A server with Portainer Community or Business Edition installed
* Ports `80` and `443` (TCP and UDP) free on the host (Caddy needs both for HTTPS and HTTP/3)
* DNS A/AAAA record pointing your hostname (e.g. `semp.example.com`) at the server
* DNS SRV/TXT records for the email domain (see the main README's "DNS Records" section)

## Pick an implementation

This stack deploys ONE impl. Both Go and TS are wire-compatible; pick one via the `SEMP_IMPL` environment variable. See [`README.md`](README.md) for the comparison.

## Steps

### 1. Edit semp.toml in your fork

Portainer's Stack-from-Repository feature pulls the compose file directly from a Git repo. To customise the SEMP config, fork [semp-reference-server](https://github.com/semp-dev/semp-reference-server) and edit `shared/deploy/semp.toml`:

```toml
domain = "example.com"
listen_addr = ":8443"

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

`external_tls = true` makes the discovery endpoint advertise `wss://` instead of `ws://`. The container itself speaks plain HTTP; Caddy terminates TLS upstream.

Push the change to your fork.

### 2. Create the stack in Portainer

* Go to **Stacks** > **+ Add stack**
* Name: `semp`
* Build method: **Repository**
* Repository URL: `https://github.com/<you>/semp-reference-server.git`
* Reference: `refs/heads/master`
* Compose path: `shared/deploy/docker-compose.portainer.yml`
* Enable **GitOps updates** if you want Portainer to redeploy on pushes

### 3. Set required environment variables

In the same stack form, scroll down to **Environment variables** and add:

```
SEMP_HOST=semp.example.com
SEMP_IMPL=go
```

`SEMP_HOST` is the public hostname Caddy will obtain a Let's Encrypt cert for. `SEMP_IMPL` is `go` or `ts`. Both fall through to clear errors if mistyped.

### 4. Deploy

Click **Deploy the stack**. Portainer clones the repo, builds the SEMP image from `docker/${SEMP_IMPL}.Dockerfile`, pulls `caddy:2-alpine`, and starts both containers. Caddy obtains a Let's Encrypt certificate on first request to `https://semp.example.com`.

## Verify

```sh
curl -i https://semp.example.com/.well-known/semp/configuration
```

Expect a `200` with discovery JSON.

```sh
curl -i \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://semp.example.com/v1/ws
```

Expect `101 Switching Protocols`.

## Switching impls

Edit `SEMP_IMPL` in the stack's **Environment variables** and redeploy. The container is rebuilt from the other Dockerfile against the same `semp-data` volume; the SQL schema is identical between impls.

For interop testing, run two stacks side-by-side under different hostnames and federate them via `[[federation.peers]]` in each `semp.toml`. Or use the dedicated `docker-compose.federation.yml` (see [`README.md`](README.md) "Interop testing").

## Notes

* **Logs**: both containers log to stdout/stderr; view them in **Containers** > pick the container > **Logs**. The SEMP server emits structured logs at `info` level by default.
* **Caddy state**: Let's Encrypt certificates and renewal state live in the `caddy-data` volume. Do not delete this volume between deploys, or Caddy will hit Let's Encrypt's rate limits re-issuing.
* **Without a fork**: if you don't want to fork the repo, switch the build method to **Web editor** and paste the contents of [`docker-compose.portainer.yml`](docker-compose.portainer.yml) directly. You'll then need to provide `semp.toml` and `Caddyfile` via Portainer's **Configs** feature or by adapting the compose to inline them.
* **Multiple servers on one host**: change the published ports (`80`/`443`) and add a separate domain for each Caddy instance, or share a single Caddy across stacks via an external network.
* **HTTP/3**: UDP/443 is mapped, so Caddy will offer HTTP/3 automatically. Some clients prefer it for federation reconnects.
