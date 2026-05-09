package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/envelope"
)

// issueDeliveryReceipt produces a signed SEMP_DELIVERY_RECEIPT for
// env per DELIVERY.md section 1.1.1.5. Called by the recipient side
// on every delivered acknowledgment so the sender server can satisfy
// its section 1.1.1.6 verification obligation.
func issueDeliveryReceipt(deps FederationDeps, env *envelope.Envelope) (*delivery.DeliveryReceipt, error) {
	if deps.DomainSignFP == "" || len(deps.DomainSignPriv) == 0 {
		return nil, errors.New("recipient server has no domain signing key configured")
	}
	canonicalBytes, err := env.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("canonical envelope bytes: %w", err)
	}
	receipt := &delivery.DeliveryReceipt{
		EnvelopeHash: delivery.EnvelopeHash{
			Algorithm: delivery.EnvelopeHashAlgorithmSHA256,
			Value:     delivery.ComputeEnvelopeHash(canonicalBytes),
		},
		RecipientDomain: deps.LocalDomain,
		AcceptedAt:      time.Now().UTC().Truncate(time.Second),
	}
	if err := delivery.SignDeliveryReceipt(deps.Suite.Signer(), deps.DomainSignPriv, string(deps.DomainSignFP), receipt); err != nil {
		return nil, fmt.Errorf("sign receipt: %w", err)
	}
	return receipt, nil
}

// verifyDeliveredReceipt enforces the DELIVERY.md section 1.1.1.6
// sender-side obligation: a `delivered` acknowledgment from a peer
// server MUST carry a verifiable signed receipt over the canonical
// envelope bytes; otherwise the result MUST be treated as a transport
// failure and retried.
//
// Returns the peerResult unchanged when verification succeeds, or a
// demoted version with Status=StatusRejected and
// ReasonCode=ReasonServerUnavailable when the receipt is missing,
// malformed, or unverifiable.
func verifyDeliveredReceipt(ctx context.Context, deps ClientDeps, peerDomain string, env *envelope.Envelope, peerResult delivery.SubmissionResult) delivery.SubmissionResult {
	if peerResult.Status != semp.StatusDelivered {
		return peerResult
	}
	demote := func(reason string) delivery.SubmissionResult {
		if deps.Logger != nil {
			deps.Logger.Warn("receipt verification failed; demoting to server_unavailable",
				"identity", deps.Identity,
				"recipient", peerResult.Recipient,
				"reason", reason,
			)
		}
		return delivery.SubmissionResult{
			Recipient:  peerResult.Recipient,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonServerUnavailable,
			Reason:     reason,
		}
	}
	if peerResult.Receipt == nil {
		return demote("delivered acknowledgment missing required receipt (DELIVERY.md section 1.1.1.6)")
	}
	if peerResult.Receipt.RecipientDomain != peerDomain {
		return demote(fmt.Sprintf("receipt recipient_domain %q does not match peer %q",
			peerResult.Receipt.RecipientDomain, peerDomain))
	}
	canonicalBytes, err := env.CanonicalBytes()
	if err != nil {
		return demote(fmt.Sprintf("canonical envelope bytes: %v", err))
	}
	if err := delivery.VerifyEnvelopeBinding(peerResult.Receipt, canonicalBytes); err != nil {
		return demote(err.Error())
	}
	if deps.Store == nil {
		return demote("no keys.Store configured; cannot resolve recipient domain key")
	}
	rec, err := deps.Store.LookupDomainKey(ctx, peerDomain)
	if err != nil {
		return demote(fmt.Sprintf("lookup peer domain key: %v", err))
	}
	if rec == nil {
		return demote("no peer domain key on file")
	}
	if string(rec.KeyID) != peerResult.Receipt.Signature.KeyID {
		// Receipt was signed by a key other than the one we currently
		// have published for this domain. Could be a recent rotation
		// or an attacker. Either way, treat as recoverable: a retry
		// after refreshing the peer's key set MAY succeed.
		return demote(fmt.Sprintf("receipt signature.key_id %q does not match cached peer domain key %q",
			peerResult.Receipt.Signature.KeyID, rec.KeyID))
	}
	pubBytes, err := decodeBase64(rec.PublicKey)
	if err != nil {
		return demote(fmt.Sprintf("decode peer domain public key: %v", err))
	}
	if err := delivery.VerifyDeliveryReceipt(deps.Suite.Signer(), pubBytes, peerResult.Receipt); err != nil {
		return demote(err.Error())
	}
	return peerResult
}
