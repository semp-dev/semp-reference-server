package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/session"
	"semp.dev/semp-go/transport"
)

// handleRekey processes a SEMP_REKEY init from the peer and runs the
// responder side of the rekey exchange (SESSION.md section 3). The
// session's key material is rotated in-place on success; subsequent
// envelope handling uses the new K_env_mac via session.EnvMAC().
func handleRekey(ctx context.Context, conn transport.Conn, raw []byte, suite crypto.Suite, sess *session.Session, identity string, logger *slog.Logger) error {
	if sess == nil {
		// We have no live session state to rekey against. Drop the
		// message; the peer will retry or fall back to re-handshake.
		return errors.New("rekey not supported: no live session")
	}
	handler := &session.RekeyHandler{
		Suite:   suite,
		Session: sess,
	}
	if err := handler.Handle(ctx, conn, raw); err != nil {
		return fmt.Errorf("rekey handle: %w", err)
	}
	if logger != nil {
		logger.Info("rekey ok",
			"identity", identity,
			"session", sess.ID,
			"rekey_count", sess.RekeyCount,
		)
	}
	return nil
}
