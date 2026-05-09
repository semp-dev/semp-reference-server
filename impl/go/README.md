# impl/go

Go implementation of the SEMP reference server. Built on `semp.dev/semp-go`.

## Build

    go build -o semp-server ./cmd/semp-server

## Run

    ./semp-server -config ../../shared/config/config.example.toml

## Test

    go test ./...

## Module layout

- `cmd/semp-server/`: entry point. Loads TOML config, sets up logging,
  starts the server, handles SIGINT/SIGTERM.
- `internal/config/`: TOML config loader.
- `internal/server/`: HTTP listener wiring + lifecycle. Per-transport
  adapters at `transport_ws.go`, `transport_h2.go` (NEW in v0.5.0;
  the library no longer ships server-side `NewHandler` factories).
- `internal/runtime/`: per-connection post-handshake message loop;
  built on `session.Dispatch` plus per-type handlers
  (envelope, fetch, keys, rekey). NEW in v0.5.0; replaces the
  deleted `delivery/inboxd` library package.
- `internal/store/`: SQLite-backed `keys.Store` impl plus inbox,
  block list, and master-key encryption envelope.
- `internal/keygen/`: domain key bootstrap.
