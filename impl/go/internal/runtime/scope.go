package runtime

import (
	"context"
	"fmt"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/keys"
)

// enforceSendScope applies the CLIENT.md section 2.4 scope check to
// the given recipient list using the device certificate attached to
// deps.DeviceKeyID in the local store.
//
// Returns:
//   - rejections: one SubmissionResult per recipient that was blocked
//     by the scope. Empty when no cert exists, when the cert's
//     scope.send.mode is "all", or when all recipients passed the
//     scope check.
//   - allBlocked: true when EVERY recipient was blocked. The caller
//     uses this to short-circuit delivery for submissions where
//     nothing would make it through.
//   - err: a fatal error that blocks the entire submission (e.g. a
//     certificate whose chain does not verify). A broken cert kills
//     the submission entirely, per CLIENT.md section 2.3.
func enforceSendScope(ctx context.Context, deps ClientDeps, envelopeID string, recipients []brief.Address) (rejections []delivery.SubmissionResult, allBlocked bool, err error) {
	if deps.DeviceKeyID == "" || deps.Store == nil {
		return nil, false, nil
	}
	cert, err := deps.Store.LookupDeviceCertificate(ctx, deps.DeviceKeyID)
	if err != nil {
		return nil, false, fmt.Errorf("lookup device certificate: %w", err)
	}
	if cert == nil {
		// No certificate means this is a primary (full-access)
		// device: scope checks do not apply.
		return nil, false, nil
	}
	// Verify the chain: the issuing device key must be a registered
	// identity key for the cert's UserID, and the signature must
	// check out. A broken chain is fatal.
	if err := cert.VerifyChain(ctx, deps.Suite, deps.Store); err != nil {
		return nil, false, fmt.Errorf("verify device certificate chain: %w", err)
	}
	// Cross-check: the certificate MUST identify the same user as
	// the session identity. A mismatch means the store returned
	// someone else's cert: a configuration bug; fail closed.
	if cert.Account != deps.Identity {
		return nil, false, fmt.Errorf("device certificate account %s does not match session identity %s",
			cert.Account, deps.Identity)
	}

	scope := cert.Scope.Send
	blocked := make([]delivery.SubmissionResult, 0)
	allowedCount := 0
	for _, addr := range recipients {
		if scope.AllowsRecipient(addr) {
			allowedCount++
			continue
		}
		address := string(addr)
		reasonText := fmt.Sprintf("recipient %s is outside the device's scope.send", address)
		if scope.Mode == keys.MatcherModeNone {
			reasonText = "device certificate scope.send.mode is 'none'"
		}
		blocked = append(blocked, delivery.SubmissionResult{
			Recipient:  address,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonScopeExceeded,
			Reason:     reasonText,
		})
		if deps.Logger != nil {
			deps.Logger.Warn("scope_exceeded",
				"identity", deps.Identity,
				"envelope", envelopeID,
				"recipient", address,
				"mode", string(scope.Mode),
			)
		}
	}
	allBlocked = allowedCount == 0 && len(recipients) > 0
	return blocked, allBlocked, nil
}
