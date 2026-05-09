# SQLite store contract

Pinned settings every impl applies on `InitDB`-equivalent:

| Pragma | Value | Reason |
|---|---|---|
| `journal_mode` | `WAL` | Concurrent reads while a write is in progress. |
| `foreign_keys` | `ON` | Enforce key-record / device-cert references. |
| `busy_timeout` | `5000` (ms) | Wait up to 5s for a competing writer. |

## Concurrency expectations

The server-side database is **single-process**. WAL allows concurrent
reads, but only one writer at a time. If two server processes attempt
to write the same DB simultaneously, the second one waits up to
`busy_timeout` ms then returns a `database is locked` error.

Operators running multiple `semp-server` instances against the same
SQLite file will hit this. Use a separate DB per instance, or a
client-server SQL backend (Postgres) behind your own implementation.

## Driver semantics

- `impl/go` uses `modernc.org/sqlite` (pure-Go, async via `database/sql`).
- `impl/ts` uses `better-sqlite3` (native bindings, fully synchronous).

Both honor WAL and `busy_timeout` identically. Synchronous-vs-async is
internal to each impl and does not affect on-disk behavior or wire output.

## Master-key encryption envelope

When the TOML config sets `database.master_key`, private key material
in `domain_keys` and `user_keys` is encrypted at rest. Both impls MUST
use the **byte-identical** envelope so a database written by one impl
is readable by the other.

| Parameter | Value |
|---|---|
| KDF | Argon2id |
| Argon2id `memory` | `131072` (128 MiB) |
| Argon2id `iterations` | `4` |
| Argon2id `parallel` | `4` |
| Argon2id `keyLen` | `32` bytes |
| Argon2id `saltLen` | `16` bytes |
| AEAD | AES-256-GCM |
| AAD | the row's `key_id` value as UTF-8 bytes |

Each row stores: `key_salt` (the random Argon2id salt), `key_nonce`
(the AEAD nonce), and `private_key` (the AEAD ciphertext + auth tag).

A cross-impl test SHOULD write a DB from the Go impl, swap the binary
to the TS impl with the same `master_key`, and successfully read the
private keys back. Drift in any Argon2id parameter or AAD format
breaks this contract.
