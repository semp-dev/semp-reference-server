#!/usr/bin/env bash
# SEMP reference server installer for Plesk hosts.
#
# Designed to run from inside the extracted plesk-bundle directory.
# Idempotent: first run scaffolds the config and exits; subsequent runs
# load the image and (re)start the container.
#
# Usage (on the Plesk host, as root):
#
#   sudo ./install.sh
#
# Environment overrides:
#
#   INSTALL_DIR     Where config and data live (default: /opt/semp)
#   SEMP_HOST_PORT  Localhost port for the container (default: 18443)
#   CONTAINER_NAME  Docker container name (default: semp-server)
#   IMAGE_TAG       Image tag to use (default: semp-server:latest)

set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/semp}"
SEMP_HOST_PORT="${SEMP_HOST_PORT:-18443}"
CONTAINER_NAME="${CONTAINER_NAME:-semp-server}"
IMAGE_TAG="${IMAGE_TAG:-semp-server:latest}"

err() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '>>> %s\n' "$*"; }

[[ $EUID -eq 0 ]] || err "must be run as root (try: sudo ./install.sh)"
command -v docker >/dev/null 2>&1 || err "docker is not installed"

BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
[[ -f "${BUNDLE_DIR}/semp.toml.example" ]] || err "semp.toml.example missing from bundle"
[[ -f "${BUNDLE_DIR}/plesk-nginx.conf" ]] || err "plesk-nginx.conf missing from bundle"

# Make sure the image is loaded. Either it was pre-loaded via
# 'docker load -i semp-server-plesk.tar' (the build-plesk-image.sh
# flow), or there's a semp-server.tar sitting next to this script
# (the older make-plesk-bundle.sh flow that we still tolerate).
if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
    if [[ -f "${BUNDLE_DIR}/semp-server.tar" ]]; then
        log "loading image from semp-server.tar"
        docker load -i "${BUNDLE_DIR}/semp-server.tar"
        LOADED=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^semp-server:' | head -n1)
        [[ -n "${LOADED}" ]] || err "no semp-server image found after docker load"
        docker tag "${LOADED}" "${IMAGE_TAG}"
    else
        err "image ${IMAGE_TAG} is not loaded; run 'sudo docker load -i semp-server-plesk.tar' first"
    fi
fi

mkdir -p "${INSTALL_DIR}/config" "${INSTALL_DIR}/data"

if [[ ! -f "${INSTALL_DIR}/config/semp.toml" ]]; then
    cp "${BUNDLE_DIR}/semp.toml.example" "${INSTALL_DIR}/config/semp.toml"
    cat <<EOF

==========================================================================
Config stub installed at ${INSTALL_DIR}/config/semp.toml.

Edit it now to set:
  - domain         (your email domain, e.g. example.com)
  - [[users]]      one entry per user with address and password

Then re-run this installer to start the container:
  sudo ./install.sh
==========================================================================

EOF
    exit 0
fi

# Match the data directory ownership to the container's semp user so the
# container can write to /var/lib/semp without running as root.
SEMP_UID=$(docker run --rm --entrypoint id "${IMAGE_TAG}" -u semp 2>/dev/null || echo 100)
SEMP_GID=$(docker run --rm --entrypoint id "${IMAGE_TAG}" -g semp 2>/dev/null || echo 101)
log "aligning ${INSTALL_DIR}/data ownership to container uid:gid ${SEMP_UID}:${SEMP_GID}"
chown -R "${SEMP_UID}:${SEMP_GID}" "${INSTALL_DIR}/data"
chmod 0700 "${INSTALL_DIR}/data"

if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    log "stopping and removing existing ${CONTAINER_NAME}"
    docker stop "${CONTAINER_NAME}" >/dev/null
    docker rm "${CONTAINER_NAME}" >/dev/null
fi

log "starting ${CONTAINER_NAME} bound to 127.0.0.1:${SEMP_HOST_PORT}"
docker run -d \
    --name "${CONTAINER_NAME}" \
    --restart unless-stopped \
    -p "127.0.0.1:${SEMP_HOST_PORT}:8443" \
    -v "${INSTALL_DIR}/data:/var/lib/semp" \
    -v "${INSTALL_DIR}/config/semp.toml:/etc/semp/semp.toml:ro" \
    "${IMAGE_TAG}" >/dev/null

sleep 1
docker ps --filter "name=${CONTAINER_NAME}" --format '    status: {{.Status}}'

cat <<EOF

==========================================================================
Container is running on 127.0.0.1:${SEMP_HOST_PORT}.

NEXT STEPS in the Plesk UI:

  1. Add or select your domain (e.g. semp.example.com).

  2. Domain -> SSL/TLS Certificates -> Install free Let's Encrypt
     certificate. Enable "Redirect from HTTP to HTTPS".

  3. Domain -> Apache & nginx Settings -> Additional nginx directives,
     paste the contents of:

         ${BUNDLE_DIR}/plesk-nginx.conf

  4. Same screen, uncheck:
     - "Smart static files processing"
     - "Serve static files directly by nginx"

  5. Apply.

VERIFY:

  curl -i https://semp.example.com/.well-known/semp/configuration

LOGS:

  docker logs -f ${CONTAINER_NAME}
==========================================================================

EOF
