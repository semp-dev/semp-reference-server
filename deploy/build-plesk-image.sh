#!/usr/bin/env bash
# Builds a Plesk-ready Docker image with operator helpers baked in,
# then exports it via docker save to a single tar file.
#
# Run on a developer machine that has Docker (with buildx). Output:
#
#   deploy/dist/semp-server-plesk.tar
#
# The output tar is a classic single-platform docker save archive
# (linux/amd64, no provenance/sbom attestations) — the same shape
# Plesk's File Manager already swallows for other Docker image
# uploads.
#
# Upload that tar to your Plesk server (File Manager or SFTP), then
# follow the instructions printed at the end of this script.

set -euo pipefail

err() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '>>> %s\n' "$*"; }

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
DIST_DIR="${REPO_ROOT}/deploy/dist"
TARBALL="${DIST_DIR}/semp-server-plesk.tar"
DOCKERFILE="${REPO_ROOT}/deploy/Dockerfile.plesk"

command -v docker >/dev/null 2>&1 || err "docker is required"
docker buildx version >/dev/null 2>&1 || err "docker buildx is required"
[[ -f "${DOCKERFILE}" ]] || err "${DOCKERFILE} not found"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unversioned)"
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    GIT_SHA="${GIT_SHA}-dirty"
fi
VERSION="plesk-${GIT_SHA}"

mkdir -p "${DIST_DIR}"

log "building semp-server:${VERSION} (linux/amd64, no provenance/sbom)"
docker buildx build \
    --platform linux/amd64 \
    --provenance=false \
    --sbom=false \
    --load \
    --tag "semp-server:${VERSION}" \
    --tag "semp-server:latest" \
    --file "${DOCKERFILE}" \
    "${REPO_ROOT}"

log "saving image to ${TARBALL}"
rm -f "${TARBALL}"
docker save "semp-server:latest" -o "${TARBALL}"

SIZE=$(du -h "${TARBALL}" | awk '{print $1}')
cat <<EOF

==========================================================================
Image saved: ${TARBALL}  (${SIZE})

Upload this single tar to your Plesk host (File Manager or SFTP).

Then on the Plesk host:

  # 1. Load the image into the local Docker daemon
  sudo docker load -i semp-server-plesk.tar

  # 2. Extract the operator helpers to /opt/semp
  sudo mkdir -p /opt/semp
  sudo docker create --name semp-bootstrap semp-server:latest
  sudo docker cp semp-bootstrap:/usr/share/semp/. /opt/semp/
  sudo docker rm semp-bootstrap

  # 3. First run — scaffolds /opt/semp/config/semp.toml and exits.
  #    Edit that file to set 'domain' and add [[users]] entries.
  sudo /opt/semp/install.sh

  # 4. Second run — starts the container and prints the Plesk UI steps.
  sudo /opt/semp/install.sh
==========================================================================
EOF
