# Deploying on Plesk

Plesk Obsidian can run the SEMP reference server through its **Docker** extension, with Plesk's nginx in front for TLS and routing. Unlike Dokploy or Coolify, you must add nginx directives manually for WebSocket support.

## Prerequisites

* Plesk Obsidian with the **Docker** extension installed
* A domain or subdomain in Plesk (e.g. `semp.example.com`) with DNS pointing at the server
* DNS SRV/TXT records for the email domain (see the main README's "DNS Records" section)
* SSH access to the server (only for the SSH-based bundle install path)

## Recommended: prebuilt image with helpers baked in

Build a Docker image on your local machine with the operator helpers (installer, nginx directives, config template, README) baked into `/usr/share/semp/`, export it via `docker save` to a single `.tar`, upload that, and the rest is `docker load` + `docker cp` + run the installer. No second artifact, no git or Go on the Plesk host.

The image is built with `docker buildx --platform linux/amd64 --provenance=false --sbom=false`, which produces a classic single-platform `docker save` archive — the same shape Plesk's File Manager already swallows for any other Docker image upload.

### On your local machine

```sh
git clone https://github.com/semp-dev/semp-reference-server
cd semp-reference-server
./deploy/build-plesk-image.sh
```

Output: `deploy/dist/semp-server-plesk.tar` (about 9 MB).

### On the Plesk host

Upload `semp-server-plesk.tar` via Plesk File Manager or SFTP, then:

```sh
# 1. Load the image
sudo docker load -i semp-server-plesk.tar

# 2. Extract operator helpers from the image to /opt/semp/
sudo mkdir -p /opt/semp
sudo docker create --name semp-bootstrap semp-server:latest
sudo docker cp semp-bootstrap:/usr/share/semp/. /opt/semp/
sudo docker rm semp-bootstrap

# 3. First install run — scaffolds /opt/semp/config/semp.toml, exits
sudo /opt/semp/install.sh

# Edit /opt/semp/config/semp.toml: set 'domain' and add [[users]]

# 4. Second run — starts the container and prints Plesk UI steps
sudo /opt/semp/install.sh
```

The extracted `/opt/semp/README.md` covers what the install steps do and what's left for the Plesk UI (Let's Encrypt cert, paste `plesk-nginx.conf` into Additional nginx directives, uncheck the static-file shortcuts).

## Manual steps

If you'd rather build directly on the Plesk host instead of using the prebuilt image:

### 1. Build the image

SSH in and build the image on the server:

```sh
git clone https://github.com/semp-dev/semp-reference-server /opt/semp
cd /opt/semp
docker build -t semp-server:latest .

mkdir -p /opt/semp/data /opt/semp/config
cp deploy/semp.toml /opt/semp/config/semp.toml
```

Edit `/opt/semp/config/semp.toml`:

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

`external_tls = true` tells the server to advertise `wss://` in discovery responses; Plesk's nginx terminates TLS at the edge.

### 2. Run the container

In Plesk, go to **Docker** > **Run** image `semp-server:latest`:

* **Container name:** `semp-server`
* **Restart policy:** Unless stopped
* **Manual mapping** of port `8443` to host `127.0.0.1:18443` (bind to localhost so the container is not directly reachable from the public internet)
* **Volumes:**
  * `/opt/semp/data` > `/var/lib/semp`
  * `/opt/semp/config/semp.toml` > `/etc/semp/semp.toml` (read-only)

Or run it from the shell:

```sh
docker run -d \
  --name semp-server \
  --restart unless-stopped \
  -p 127.0.0.1:18443:8443 \
  -v /opt/semp/data:/var/lib/semp \
  -v /opt/semp/config/semp.toml:/etc/semp/semp.toml:ro \
  semp-server:latest
```

### 3. Issue a TLS certificate

In Plesk, open the domain (`semp.example.com`) and go to **SSL/TLS Certificates** > **Install a free basic certificate provided by Let's Encrypt**. Enable **Redirect from HTTP to HTTPS**.

### 4. Configure nginx for WebSocket support

Plesk's default nginx config does not pass `Upgrade`/`Connection` headers. Go to **Apache & nginx Settings** for the domain and paste this into **Additional nginx directives**:

```nginx
location /v1/ws {
    proxy_pass http://127.0.0.1:18443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}

location /v1/federate {
    proxy_pass http://127.0.0.1:18443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}

location / {
    proxy_pass http://127.0.0.1:18443;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### 5. Disable Plesk's static-file shortcuts

Still in **Apache & nginx Settings**:

* Uncheck **Smart static files processing**
* Uncheck **Serve static files directly by nginx**

Otherwise Plesk may try to serve `/.well-known/semp/*` from the docroot and return 404 before the proxy block runs.

### 6. Apply

Save settings. Plesk reloads nginx.

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

Expect `101 Switching Protocols`. If you get `502` or a stripped `Connection: close` response, the additional nginx directives did not apply; recheck the domain config.

## Notes

* **Plesk may overwrite custom nginx directives** if you change other domain settings. Keep a copy of the directive block.
* **Coexistence** — the SEMP server takes the entire domain because the `location /` block proxies everything to the container. Use a dedicated subdomain rather than mixing it with a Plesk-managed website.
* **HTTP/2 transport** (`/v1/h2`) works through the same `location /` proxy because the upstream connection runs over plain HTTP/1.1 framing for the persistent stream; clients that prefer the WS transport can ignore the H2 path.
* **QUIC/HTTP3** is not supported through Plesk's nginx without significant manual configuration. Stick to TCP transports.
* **Container logs** — `docker logs -f semp-server` from SSH, or **Docker** > **Logs** in the Plesk UI.
