# impl/

Language implementations of the reference server. Each impl reads the
same config schema (`shared/config/`), the same SQLite schema
(`shared/schema/`), and produces byte-identical wire output.

## Parity matrix

| Feature | `impl/go` | `impl/ts` |
|---|---|---|
| Transport: WebSocket (`/v1/ws`, `/v1/federate`) | ✅ | ✅ |
| Transport: HTTP/2 (`/v1/h2`, `/v1/h2/federate`) | ✅ | ✅ |
| Transport: QUIC (`tls.quic_addr`) | ✅ | ❌ (Node has no first-class QUIC server) |
| Crypto suite: x25519-chacha20-poly1305 | ✅ | ✅ |
| Crypto suite: pq-kyber768-x25519 | ✅ | ✅ |
| SQLite store (modernc / better-sqlite3) | ✅ | ✅ |
| `database.master_key` encryption at rest | ✅ | ✅ |
| Federation forwarder + cached sessions | ✅ | ✅ |
| Auto-rekey at 80% TTL | ✅ | ✅ |
| `/debug/metrics` | ✅ | ✅ |

QUIC is the only conformance-acceptable difference: TRANSPORT.md §4
makes HTTP/2 mandatory and QUIC optional, so a TS-only deployment is
spec-conformant.
