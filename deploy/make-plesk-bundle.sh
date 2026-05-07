#!/usr/bin/env bash
# Builds a self-contained tarball for deploying SEMP on Plesk.
#
# Run on a developer machine that has docker and go (the build runs
# inside a container, so go is not strictly required). Output:
#
#   deploy/dist/semp-plesk-bundle.tar.gz
#
# Upload that tarball to your Plesk server (File Manager or SFTP),
# extract it, and follow the included README.md.

set -euo pipefail

err() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '>>> %s\n' "$*"; }

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
DIST_DIR="${REPO_ROOT}/deploy/dist"
BUNDLE_DIR_NAME="semp-plesk-bundle"
STAGING="${DIST_DIR}/${BUNDLE_DIR_NAME}"
TARBALL="${DIST_DIR}/${BUNDLE_DIR_NAME}.tar.gz"

command -v docker >/dev/null 2>&1 || err "docker is required"
command -v tar >/dev/null 2>&1 || err "tar is required"

GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unversioned)"
GIT_DIRTY=""
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    GIT_DIRTY="-dirty"
fi
VERSION="${GIT_SHA}${GIT_DIRTY}"
BUILD_DATE="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

log "building semp-server image (version ${VERSION})"
docker build \
    --tag "semp-server:${VERSION}" \
    --tag "semp-server:latest" \
    "${REPO_ROOT}"

log "preparing staging directory ${STAGING}"
rm -rf "${STAGING}"
mkdir -p "${STAGING}"

log "saving Docker image to semp-server.tar"
docker save "semp-server:${VERSION}" -o "${STAGING}/semp-server.tar"

log "copying bundle templates"
cp "${REPO_ROOT}/deploy/plesk-bundle/README.md"          "${STAGING}/README.md"
cp "${REPO_ROOT}/deploy/plesk-bundle/install.sh"         "${STAGING}/install.sh"
cp "${REPO_ROOT}/deploy/plesk-bundle/plesk-nginx.conf"   "${STAGING}/plesk-nginx.conf"
cp "${REPO_ROOT}/deploy/semp.toml"                       "${STAGING}/semp.toml.example"
chmod +x "${STAGING}/install.sh"

cat > "${STAGING}/version.txt" <<EOF
SEMP reference server Plesk bundle
version:    ${VERSION}
built:      ${BUILD_DATE}
image tag:  semp-server:${VERSION}
EOF

log "creating tarball ${TARBALL}"
rm -f "${TARBALL}"
tar -czf "${TARBALL}" -C "${DIST_DIR}" "${BUNDLE_DIR_NAME}"

log "cleaning up staging"
rm -rf "${STAGING}"

SIZE=$(du -h "${TARBALL}" | awk '{print $1}')
cat <<EOF

==========================================================================
Bundle built: ${TARBALL}  (${SIZE})

Upload this to your Plesk server (File Manager or SFTP), extract it,
then either:

  - SSH in and run: cd ${BUNDLE_DIR_NAME} && sudo ./install.sh

  - Or use the Plesk Docker UI to import semp-server.tar and run a
    container manually (see README.md in the bundle).
==========================================================================
EOF
