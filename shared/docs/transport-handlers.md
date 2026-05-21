# Transport handlers

Both implementations serve the same HTTP / WebSocket endpoints. The
table below documents what each endpoint speaks; per-impl wire-format
adapters bridge `net/http` (Go) or `node:http`+`ws` (TS) to a
`transport.Conn`-shaped object that the protocol primitives consume.

## Endpoints

| Path | Method | Speaks |
|---|---|---|
| `/v1/ws` | GET (Upgrade) | WebSocket; subprotocol `semp.v1`; client traffic. |
| `/v1/federate` | GET (Upgrade) | WebSocket; subprotocol `semp.v1`; federation traffic. |
| `/v1/h2` | POST (turn-based) | JSON over HTTP/2; client traffic. Threads `Semp-Session-Id` header. |
| `/v1/h2/federate` | POST (turn-based) | JSON over HTTP/2; federation traffic. |
| `/v1/register` | POST | Plain JSON: register a user's identity + encryption keys. |
| `/v1/device/register` | POST | Plain JSON: register a delegated device certificate. |
| `/v1/blocklist[/...]` | GET / POST / DELETE | User block list management. |
| `/.well-known/semp/configuration` | GET | DISCOVERY.md §3 well-known configuration document. |
| `/.well-known/semp/keys/{address}` | GET | Per-user public-key fetch. |
| `/.well-known/semp/domain-keys` | GET | Per-domain signing-key fetch. |
| `/debug/metrics` | GET | Operator metrics (text/expvar). |

## QUIC

`impl/go` optionally serves QUIC at `tls.quic_addr` if set. `impl/ts`
does not support QUIC (Node has no first-class QUIC server). HTTP/2
is the spec's mandatory baseline (TRANSPORT.md §4) so this is not a
conformance gap.

## Per-impl adapter responsibility

semp-go v0.5.0 deleted the `transport/{ws,h2}.NewHandler` factories;
each consumer writes its own `net/http`->`transport.Conn` adapter. The
Go impl's adapter lives at `impl/go/internal/server/transport_*.go`;
the TS impl's at `impl/ts/src/server/transport_*.ts`.

Both adapters MUST:
- Validate the WS subprotocol is exactly `semp.v1`.
- Cap inbound message size at the `[crypto].max_envelope_size` value
  (default 25 MiB) BEFORE handing bytes to the protocol layer.
- For HTTP/2: maintain a per-`Semp-Session-Id` session map; each POST
  is one Send -> 200-response cycle. New sessions mint a ULID and spawn
  the post-handshake goroutine / async function.
