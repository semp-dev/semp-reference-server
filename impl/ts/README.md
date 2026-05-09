# impl/ts

TypeScript implementation of the SEMP reference server. Built on
`@sempdev/semp@^0.5.0`.

## Build

    npm install
    npm run build

## Run

    node bin/semp-server.js --config ../../shared/config/config.example.toml

## Test

    npm test

## Module layout

- `bin/semp-server.js`: CLI entry; loads the built `dist/main.js`.
- `src/main.ts`: parses argv, loads TOML, builds + starts the server,
  installs SIGINT/SIGTERM handlers.
- `src/config/`: TOML loader; mirrors `impl/go/internal/config/config.go`
  validation and defaults.
- `src/server/`: HTTP listener wiring + lifecycle. Per-transport
  adapters at `transport_ws.ts` (uses the `ws` package) and
  `transport_h2.ts` (POST turn-based, threaded by `Semp-Session-Id`).
- `src/runtime/`: per-connection post-handshake message loop. Built on
  `@sempdev/semp/session.runDispatcher` plus per-type handlers
  (envelope, fetch, keys, rekey).
- `src/store/`: SQLite-backed `keys.KeyStore` impl plus inbox, block
  list, and master-key encryption envelope (parity with Go's
  `internal/store/encrypt.go`).
- `src/keygen/`: domain key bootstrap.
- `src/util/`: DNS SRV + well-known signing-key auto-fetch helpers.

## Caveats vs impl/go

- QUIC: not supported. Documented in `shared/docs/transport-handlers.md`.
- The semp-ts handshake driver only negotiates the baseline suite
  (`x25519-chacha20-poly1305`); envelope sealing still honors the
  configured `crypto.suite`.
- Cross-domain SEMP_KEYS lookups return `not_found`: semp-ts v0.5.0's
  `Forwarder` does not expose a `FetchKeys` shim yet.
