package runtime

import (
	"context"
	"log/slog"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
	"semp.dev/semp-go/transport"
)

// FederationDeps groups the dependencies a federation-side dispatch
// loop needs. A federation peer forwards envelopes whose seal.signature
// was produced by the original sender domain (not by us); we verify
// against keys looked up in Store and never re-sign.
type FederationDeps struct {
	Suite     crypto.Suite
	Store     keys.Store
	Inbox     *delivery.Inbox
	BlockList delivery.BlockListLookup

	LocalDomain string

	DomainSignFP   keys.Fingerprint
	DomainSignPriv []byte
	DomainEncFP    keys.Fingerprint
	DomainEncPriv  []byte
	DomainEncPub   []byte

	// Identity is the authenticated peer identity established by the
	// preceding federation handshake (the peer server's domain).
	Identity string

	// Session is the live *session.Session backing this federation
	// connection.
	Session *session.Session

	Logger *slog.Logger
}

// ServeFederation runs the post-handshake message loop against an
// inbound federation peer. The peer is expected to forward envelopes
// whose seal.signature carries the original sender domain's
// provenance proof. This loop verifies both proofs (signature against
// the original sender domain's key from Store, session_mac against
// THIS federation session's K_env_mac), unwraps the brief, applies
// the user-level block list, and stores envelopes for local
// recipients.
//
// Federation does not multi-hop: recipients outside LocalDomain are
// reported as recipient_not_found in the per-recipient response.
func ServeFederation(ctx context.Context, conn transport.Conn, deps FederationDeps) error {
	handlers := session.DispatchHandlers{
		OnEnvelope: func(ctx context.Context, raw []byte) error {
			return handleFederationSubmissionFrame(ctx, conn, raw, deps)
		},
		OnKeys: func(ctx context.Context, raw []byte) error {
			return handleFederationKeys(ctx, conn, raw, deps)
		},
		OnRekey: func(ctx context.Context, raw []byte) error {
			return handleRekey(ctx, conn, raw, deps.Suite, deps.Session, deps.Identity, deps.Logger)
		},
		OnHandlerError: func(err error, msgType string) {
			if deps.Logger != nil {
				deps.Logger.Warn("federation dispatch handler error",
					"peer", deps.Identity,
					"type", msgType,
					"err", err,
				)
			}
		},
	}
	return session.Dispatch(ctx, conn, handlers)
}
