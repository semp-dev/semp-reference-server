// Package runtime is the post-handshake server-side message loop used
// by the cmd/semp-server reference binary. It absorbs the runtime that
// previously lived in semp.dev/semp-go's delivery/inboxd package, which
// was deleted in semp-go v0.5.0 when the library was split between
// protocol primitives and operator runtimes.
//
// Two top-level entry points serve one accepted connection each:
//
//   - ServeClient runs against a connected client. The peer is a local
//     user agent submitting envelopes on behalf of its owning user. The
//     server signs each envelope (envelope.Sign), runs the local
//     delivery pipeline, and forwards any cross-domain recipients via
//     the delivery.Forwarder.
//
//   - ServeFederation runs against a connected peer server. The peer
//     forwards envelopes that were signed and session-MAC bound by the
//     remote sender's home server. This server verifies both proofs
//     (signature against the remote sender domain's published key,
//     session_mac against THIS federation session's K_env_mac), runs
//     the local delivery pipeline, and stores envelopes for local
//     recipients.
//
// Both entry points compose session.Dispatch with a per-message
// handler set: OnEnvelope, OnFetch, OnKeys, OnRekey. The dispatcher
// reads each frame off the wire, peeks at its type, and routes to the
// matching handler. Handlers return on completion or with a transport
// error; the dispatcher loops until the peer closes or ctx is
// cancelled.
//
// The package is intentionally protocol-pure. It accepts a
// transport.Conn for the wire, a *delivery.Forwarder for cross-domain
// forwarding, a keys.Store for peer key lookups, a *delivery.Inbox for
// local delivery, and a *slog.Logger for operational logs.
package runtime
