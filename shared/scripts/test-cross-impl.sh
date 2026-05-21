#!/usr/bin/env bash
# Cross-impl interop smoke for the SEMP reference stack.
#
# For each (server-impl, client-impl) pair, this script:
#
#   1. Builds the server impl into a Docker image (or local binary).
#   2. Starts it on localhost:8443 with a fresh fixture config.
#   3. Builds the client impl.
#   4. Runs `register`, `send` (to self), `fetch` against the server.
#   5. Asserts the fetched message includes the expected subject.
#
# The matrix is four pairs: (go,go) (go,ts) (ts,go) (ts,ts). The
# wire format itself is already validated by the cross-language
# vectors corpus (89/89 passing in both libraries); this script
# adds confidence at the transport-adapter and HTTP-handler layer.
#
# Usage:
#
#   bash shared/scripts/test-cross-impl.sh [SERVER_IMPL] [CLIENT_IMPL]
#
#   SERVER_IMPL  go|ts|all   default: all
#   CLIENT_IMPL  go|ts|all   default: all
#
# Requires:
#
#   docker, docker compose
#   go (for the Go client/server build)
#   node 22+ (for the TS client/server build)
#   The companion repo at ../semp-reference-client for the client side.
#
# Status: skeleton. Per-pair runners (run_pair_go_go etc.) are stubs
# that print "TODO" rather than actually exercising the round trip.
# Fill in the run_pair body before relying on this script for CI.

set -euo pipefail

SERVER_IMPL="${1:-all}"
CLIENT_IMPL="${2:-all}"

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
CLIENT_REPO="${CLIENT_REPO:-${REPO_ROOT}/../semp-reference-client}"

log() { printf '\033[1;34m>>> %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
ko()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=$((FAILED + 1)); }

FAILED=0

[[ -d "${CLIENT_REPO}" ]] || { echo "ERROR: client repo not at ${CLIENT_REPO}; set CLIENT_REPO" >&2; exit 1; }

# Build matrix selection.
case "${SERVER_IMPL}" in
    go|ts|all) ;;
    *) echo "ERROR: SERVER_IMPL must be go|ts|all" >&2; exit 1 ;;
esac
case "${CLIENT_IMPL}" in
    go|ts|all) ;;
    *) echo "ERROR: CLIENT_IMPL must be go|ts|all" >&2; exit 1 ;;
esac

run_pair() {
    local s="$1" c="$2"
    log "pair: server=${s} client=${c}"
    # TODO: implement.
    #   1. Build server-${s} image: docker build -f ${REPO_ROOT}/docker/${s}.Dockerfile -t semp-server:${s} ${REPO_ROOT}
    #   2. Build client-${c}:
    #        IMPL=go: cd ${CLIENT_REPO}/impl/go && go build -o /tmp/cross-impl-client-${c} ./cmd/semp-client
    #        IMPL=ts: cd ${CLIENT_REPO}/impl/ts && npm install && npm run build
    #   3. Write fixtures/server.toml + fixtures/alice.toml with localhost:8443
    #   4. Start the server (docker run -d -p 8443:8443 ... semp-server:${s})
    #   5. Wait for /.well-known/semp/configuration to return 200
    #   6. Run register, send (to self), fetch
    #   7. grep "Subject: cross-impl-test-${s}-${c}" in the fetch output
    #   8. Stop server, clean up
    ko "pair (${s}, ${c}) -- not yet implemented; see TODO in run_pair()"
}

for s in go ts; do
    [[ "${SERVER_IMPL}" == "all" || "${SERVER_IMPL}" == "${s}" ]] || continue
    for c in go ts; do
        [[ "${CLIENT_IMPL}" == "all" || "${CLIENT_IMPL}" == "${c}" ]] || continue
        run_pair "${s}" "${c}"
    done
done

if [[ "${FAILED}" -gt 0 ]]; then
    echo
    echo "${FAILED} pair(s) failed."
    exit 1
fi

echo
ok "all pairs passed"
