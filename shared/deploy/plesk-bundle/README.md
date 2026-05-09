# SEMP Reference Server ; Plesk Operator Helpers

These files are extracted from the `semp-server:latest` Docker image after `docker load`. You're reading this on a Plesk host because `docker cp` pulled `/usr/share/semp/` out of the image into the directory containing this README ; typically `/opt/semp/`.

Contents:

- `install.sh` ; idempotent installer that runs the container with the right port mapping and volumes
- `plesk-nginx.conf` ; additional nginx directives for the SEMP domain
- `semp.toml.example` ; config template
- `README.md` ; this file

## What's already done

By the time you're reading this:

1. The `semp-server-plesk.tar` upload finished
2. `docker load -i semp-server-plesk.tar` was run, so `semp-server:latest` exists in the local Docker daemon
3. `docker cp` pulled these files out of the image into the current directory

## What's left

### 1. First install run (scaffolds config)

```sh
sudo ./install.sh
```

The first run copies `semp.toml.example` to `/opt/semp/config/semp.toml` and exits. Edit that file:

- `domain` ; your email domain (e.g. `example.com`)
- `[[users]]` ; one entry per user with address and password

### 2. Second install run (starts container)

```sh
sudo ./install.sh
```

This starts `semp-server` bound to `127.0.0.1:18443`, persists data in `/opt/semp/data`, and prints the next four UI steps.

### 3. Plesk UI

In the Plesk panel:

1. Add or select your domain (e.g. `semp.example.com`).
2. **Domain → SSL/TLS Certificates** → install free Let's Encrypt cert. Enable **Redirect from HTTP to HTTPS**.
3. **Domain → Apache & nginx Settings → Additional nginx directives**: paste the contents of `plesk-nginx.conf` (the file sitting next to this README).
4. Same screen, uncheck:
   - **Smart static files processing**
   - **Serve static files directly by nginx**

Apply.

## Verify

```sh
curl -i https://semp.example.com/.well-known/semp/configuration
```

Expect HTTP/2 200 with discovery JSON.

```sh
curl -i \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://semp.example.com/v1/ws
```

Expect `101 Switching Protocols`.

## Updating

On the developer machine, rebuild and re-export:

```sh
./shared/deploy/build-plesk-image.sh
```

Upload the new `semp-server-plesk.tar` to the Plesk host, then:

```sh
sudo docker load -i semp-server-plesk.tar
sudo docker create --name semp-bootstrap semp-server:latest
sudo docker cp semp-bootstrap:/usr/share/semp/. /opt/semp/
sudo docker rm semp-bootstrap
sudo /opt/semp/install.sh
```

The installer stops the old container, starts the new one against the same `/opt/semp/config/semp.toml` and `/opt/semp/data` volumes ; config and data persist.

## Logs

```sh
docker logs -f semp-server
```

Or **Plesk → Docker → Containers → semp-server → Logs**.
