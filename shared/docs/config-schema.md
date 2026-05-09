# Server config schema

TOML reference for both `impl/go` and `impl/ts`.

| Field | Type | Default | Description |
|---|---|---|---|
| `domain` | string | (required) | This server's home domain. |
| `listen_addr` | string | `:8443` | Bind address for the HTTP/WS listener. |
| `tls.cert_file` | string | (empty: serve plain HTTP) | TLS cert path. |
| `tls.key_file` | string | (empty: serve plain HTTP) | TLS key path. |
| `tls.quic_addr` | string | (empty) | UDP bind address for QUIC. Go-only; TS impl skips. |
| `tls.external_tls` | bool | `false` | TLS terminated upstream (proxy). Operator sets this when TLS is at the proxy and `cert_file`/`key_file` are unset. |
| `crypto.suite` | string | `pq-kyber768-x25519` | Either `pq-kyber768-x25519` or `x25519-chacha20-poly1305`. |
| `database.path` | string | `semp.db` | SQLite database file path. |
| `database.master_key` | string | (empty: keys at rest in plaintext) | Hex-encoded 32-byte Argon2id-derived master key. When set, private key material in `domain_keys` and `user_keys` is encrypted at rest. |
| `users[].address` | string | (required per entry) | User SEMP address. |
| `users[].password` | string | (required per entry) | Bcrypt-hashed registration password. |
| `federation.session_ttl` | int (seconds) | `3600` | Federation session TTL. |
| `federation.retention` | string | `30d` | Federation envelope retention. |
| `federation.peers[].domain` | string | (required per entry) | Peer domain. |
| `federation.peers[].endpoint` | string | (empty: discovery-driven) | Pin endpoint to skip discovery. |
| `federation.peers[].domain_signing_key` | string | (empty: discovery-fetched) | Base64-encoded peer signing key (skips well-known fetch). |
| `policy.session_ttl` | int (seconds) | `300` | Client session TTL. |
| `policy.permissions` | array of strings | `["send", "receive"]` | Permissions granted in handshake `accepted`. |
| `policy.blocked_domains` | array of strings | empty | Domains rejected at handshake. |
| `policy.pow.enabled` | bool | `true` | Issue PoW challenges. |
| `policy.pow.difficulty` | int | `16` | Leading-zero bits required. |
| `policy.pow.ttl` | int (seconds) | `300` | Challenge TTL. |
| `logging.level` | string | `info` | One of `debug`, `info`, `warn`, `error`. |
| `logging.format` | string | `text` | Either `text` or `json`. |

## Validation rules

- `domain` MUST be non-empty.
- `users` MUST have at least one entry.
- `tls.cert_file` and `tls.key_file` MUST be set together OR both empty
  AND `external_tls = true`.
- `crypto.suite` MUST be one of the two listed values.
- `database.master_key`, when set, MUST be 64 hex characters (32 bytes).
- Each `federation.peers[].domain` MUST be unique.

Both impl parsers MUST surface validation errors with byte-identical
messages so error output matches across implementations.
