# SEMP Reference Server — Plesk Deployment Bundle

This bundle contains everything needed to deploy the SEMP reference server on a Plesk host without git, Go, or build tooling on the server side. The Docker image was built on the developer's machine and exported as a single archive.

Contents:

- `semp-server.tar` — Docker image archive (`docker load`-able)
- `semp.toml.example` — config template
- `plesk-nginx.conf` — additional nginx directives for the SEMP domain
- `install.sh` — one-shot installer for SSH users
- `version.txt` — bundle version stamp

See `version.txt` for the git revision this bundle was built from.

## Quick path: SSH

```sh
sudo ./install.sh
```

On first run it scaffolds `/opt/semp/config/semp.toml` and exits so you can edit `domain` and add `[[users]]`. Re-run to load the image and start the container.

After the container is up, follow the four "Plesk UI steps" the installer prints (add domain, install Let's Encrypt cert, paste `plesk-nginx.conf` into Additional nginx directives, uncheck the static-file shortcuts).

## UI path: Plesk Docker extension

If you don't have or don't want shell access:

1. **Plesk → Docker → Images → Add Image → Upload from local file**, select `semp-server.tar`. (Older Plesk versions: SSH and run `docker load -i semp-server.tar` instead.)

2. Copy `semp.toml.example` somewhere stable on the server (e.g. `/var/lib/semp/semp.toml`) and edit:
   - `domain` — your email domain (e.g. `example.com`)
   - `[[users]]` — one entry per address with a password

3. **Plesk → Docker → Run** for `semp-server:latest`:
   - Container name: `semp-server`
   - Restart policy: **Unless stopped**
   - Manual port mapping: container `8443` → host `127.0.0.1:18443`
   - Volumes:
     - host `/var/lib/semp/data` → container `/var/lib/semp`
     - host `/var/lib/semp/semp.toml` → container `/etc/semp/semp.toml` (read-only)

4. **Domain → SSL/TLS Certificates** → install free Let's Encrypt cert. Enable **Redirect from HTTP to HTTPS**.

5. **Domain → Apache & nginx Settings → Additional nginx directives**: paste the contents of `plesk-nginx.conf`.

6. Same screen, uncheck:
   - **Smart static files processing**
   - **Serve static files directly by nginx**

7. Apply.

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

Build a new bundle locally with `./deploy/make-plesk-bundle.sh`, upload the resulting `semp-plesk-bundle.tar.gz`, extract it (overwriting the previous extraction), and re-run `sudo ./install.sh`. The installer stops the old container, loads the new image, and starts the new container against the same `/opt/semp/config/semp.toml` and `/opt/semp/data` volumes.

## Logs

```sh
docker logs -f semp-server
```

Or **Plesk → Docker → Containers → semp-server → Logs**.
