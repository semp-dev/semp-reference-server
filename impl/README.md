# impl/

Language implementations of the reference server. Each impl reads the
same config schema (`shared/config/`), the same SQLite schema
(`shared/schema/`), and produces byte-identical wire output.

## Parity matrix

| Feature | `impl/go` | `impl/ts` |
|---|---|---|
| Transport: WebSocket (`/v1/ws`, `/v1/federate`) | yes | yes |
| Transport: HTTP/2 (`/v1/h2`, `/v1/h2/federate`) | yes | yes |
| Transport: QUIC (`tls.quic_addr`) | yes | no (Node has no first-class QUIC server) |
| Crypto suite: x25519-chacha20-poly1305 | yes | yes |
| Crypto suite: pq-kyber768-x25519 | yes | yes |
| SQLite store (modernc / better-sqlite3) | yes | yes |
| `database.master_key` encryption at rest | yes | yes |
| Federation forwarder + cached sessions | yes | yes |
| Auto-rekey at 80% TTL | yes | yes |
| `/debug/metrics` | yes | yes |

QUIC is the only conformance-acceptable difference: TRANSPORT.md §4
makes HTTP/2 mandatory and QUIC optional, so a TS-only deployment is
spec-conformant.
