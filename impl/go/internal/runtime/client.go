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

// ClientDeps groups the dependencies a client-side dispatch loop needs.
// One ClientDeps is built per accepted connection, reusing the
// process-wide store/inbox/forwarder/blocklist while binding the
// per-connection identity, device key, and session.
type ClientDeps struct {
	// Suite is the negotiated cryptographic suite for this session.
	Suite crypto.Suite

	// Store is the keys.Store for peer key lookups (used by the
	// federation receipt verification path on the client-mode loop and
	// by the SEMP_KEYS local-lookup path when the client requests its
	// own domain keys).
	Store keys.Store

	// Inbox is the shared in-memory queue used at delivery pipeline
	// step 9. Multiple connections (one ServeClient per peer) write
	// into the same Inbox and the per-recipient SEMP_FETCH handler
	// drains it on demand.
	Inbox *delivery.Inbox

	// Forwarder, if non-nil, is consulted in client mode when an
	// envelope is addressed to a recipient outside LocalDomain. A nil
	// Forwarder means cross-domain recipients get recipient_not_found.
	Forwarder *delivery.Forwarder

	// BlockList is the per-recipient block list lookup applied at
	// step 8 of the delivery pipeline (DELIVERY.md section 2). Optional:
	// a nil lookup means "no blocks configured" and all envelopes
	// pass the user-policy step.
	BlockList delivery.BlockListLookup

	// LocalDomain is the server's own domain. Recipients on this
	// domain are delivered locally; everyone else is routed via
	// Forwarder.
	LocalDomain string

	// DomainSignFP and DomainSignPriv are the server's long-term
	// signing key, used to sign envelopes during client submission.
	DomainSignFP   keys.Fingerprint
	DomainSignPriv []byte

	// DomainEncFP, DomainEncPriv, and DomainEncPub are the server's
	// domain encryption keypair, used to unwrap K_brief from inbound
	// envelopes so the server can read brief.to and brief.from.
	DomainEncFP   keys.Fingerprint
	DomainEncPriv []byte
	DomainEncPub  []byte

	// Identity is the authenticated client identity established by
	// the preceding handshake (the user's address).
	Identity string

	// DeviceKeyID is the fingerprint of the long-term device key the
	// client used to sign the handshake's identity proof. Used for
	// scope enforcement on every submitted envelope per CLIENT.md
	// section 2.4.
	DeviceKeyID keys.Fingerprint

	// Session is the live *session.Session backing this connection.
	// Used for in-session rekey handling and for reading K_env_mac
	// from the session's current state, so rekey events transparently
	// rotate the key under which envelopes are signed.
	Session *session.Session

	// Logger receives operational notes. May be nil to disable logging.
	Logger *slog.Logger
}

// ServeClient runs the post-handshake message loop against conn. The
// connection has already completed the SEMP handshake and yielded
// deps.Session. ServeClient returns nil for clean shutdown, io.EOF if
// the peer closed without an error, or the underlying error otherwise.
func ServeClient(ctx context.Context, conn transport.Conn, deps ClientDeps) error {
	handlers := session.DispatchHandlers{
		OnEnvelope: func(ctx context.Context, raw []byte) error {
			return handleClientSubmissionFrame(ctx, conn, raw, deps)
		},
		OnFetch: func(ctx context.Context, raw []byte) error {
			return handleFetch(ctx, conn, raw, deps.Inbox, deps.Identity, deps.Logger)
		},
		OnKeys: func(ctx context.Context, raw []byte) error {
			return handleClientKeys(ctx, conn, raw, deps)
		},
		OnRekey: func(ctx context.Context, raw []byte) error {
			return handleRekey(ctx, conn, raw, deps.Suite, deps.Session, deps.Identity, deps.Logger)
		},
		OnHandlerError: func(err error, msgType string) {
			if deps.Logger != nil {
				deps.Logger.Warn("client dispatch handler error",
					"identity", deps.Identity,
					"type", msgType,
					"err", err,
				)
			}
		},
	}
	return session.Dispatch(ctx, conn, handlers)
}
