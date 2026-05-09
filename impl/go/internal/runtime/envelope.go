package runtime

import (
	"context"
	"encoding/json"
	"fmt"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/transport"
)

// handleClientSubmissionFrame processes one envelope upload from a
// connected client. The server signs the envelope, runs the delivery
// pipeline (DELIVERY.md section 2 steps 5-9, with the foreign-signature
// and session_mac checks skipped because we just produced both), and
// then post-processes any non-local recipients into forwarder calls.
func handleClientSubmissionFrame(ctx context.Context, conn transport.Conn, raw []byte, deps ClientDeps) error {
	env, err := envelope.Decode(raw)
	if err != nil {
		resp := delivery.NewSubmissionResponse("malformed", []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, conn, resp)
		return fmt.Errorf("decode envelope: %w", err)
	}
	return handleClientSubmission(ctx, conn, env, deps)
}

// handleClientSubmission is the client-mode submission path. The
// envelope arrives unsigned from the client; the server signs it,
// runs the delivery pipeline, and post-processes any non-local
// recipients into forwarder calls.
func handleClientSubmission(ctx context.Context, conn transport.Conn, env *envelope.Envelope, deps ClientDeps) error {
	// The client transmits the envelope WITHOUT seal.signature or
	// seal.session_mac populated. The home server fills both in per
	// CLIENT.md section 1.3 / ENVELOPE.md section 7.1 step 8.
	if err := envelope.Sign(env, deps.Suite, deps.DomainSignPriv, deps.Session.EnvMAC()); err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, conn, resp)
		return fmt.Errorf("sign envelope: %w", err)
	}

	// We need the brief here too to drive scope enforcement before we
	// hand the envelope to the pipeline. The pipeline will unwrap the
	// brief a second time during step 6/7. The double-unwrap is the
	// price of running the scope check (a sender-side concern) at
	// submission time before the envelope reaches the receiver
	// pipeline (a receiver-side concern).
	bf, err := envelope.OpenBrief(env, deps.Suite, deps.DomainEncFP, deps.DomainEncPriv, deps.DomainEncPub)
	if err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     fmt.Sprintf("server cannot unwrap brief: %v", err),
		}})
		_ = sendJSON(ctx, conn, resp)
		return fmt.Errorf("open brief: %w", err)
	}

	allRecipients := append([]brief.Address{}, bf.To...)
	allRecipients = append(allRecipients, bf.CC...)

	// Scope enforcement: if the authenticated device has a
	// certificate, check every recipient against scope.send per
	// CLIENT.md section 2.4. This is a sender-side control and runs
	// BEFORE the receive pipeline so a delegated device cannot use
	// the pipeline's policy hooks to leak information about
	// recipients outside its scope.
	scopeResults, scopeAllRejected, err := enforceSendScope(ctx, deps, env.Postmark.ID, allRecipients)
	if err != nil {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonPolicyForbidden,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, conn, resp)
		return fmt.Errorf("enforce scope: %w", err)
	}
	if scopeAllRejected {
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, scopeResults)
		return sendJSON(ctx, conn, resp)
	}

	// Run the delivery pipeline. Client-mode skips the signature and
	// session_mac verification steps because we just produced both.
	pipe := &delivery.Pipeline{
		Suite:         deps.Suite,
		EnvMAC:        deps.Session.EnvMAC,
		DomainEncFP:   deps.DomainEncFP,
		DomainEncPriv: deps.DomainEncPriv,
		DomainEncPub:  deps.DomainEncPub,
		BlockList:     deps.BlockList,
		IsLocal:       isLocalAddressFor(deps.LocalDomain),
		Inbox:         deps.Inbox,
		Logger:        slogPrintf(deps.Logger),

		SkipSignatureCheck:  true,
		SkipSessionMACCheck: true,
	}
	pipeResult, err := pipe.Process(ctx, env)
	if err != nil {
		return fmt.Errorf("client pipeline: %w", err)
	}
	if pipeResult.Rejected() {
		rej := pipeResult.Rejection
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: rej.Code,
			Reason:     rej.Reason,
		}})
		return sendJSON(ctx, conn, resp)
	}

	// Merge scope-rejection rows back in: scopeResults overrides
	// whatever the pipeline produced for the same recipient because
	// scope checks are sender-side and authoritative.
	blocked := make(map[string]delivery.SubmissionResult, len(scopeResults))
	for _, r := range scopeResults {
		if r.Status == semp.StatusRejected {
			blocked[r.Recipient] = r
		}
	}

	// Walk the pipeline results and replace any non-local
	// recipient_not_found rows with the actual forwarder outcome.
	wire, err := envelope.Encode(env)
	if err != nil {
		return fmt.Errorf("re-encode envelope: %w", err)
	}
	results := make([]delivery.SubmissionResult, 0, len(pipeResult.Results))
	for _, row := range pipeResult.Results {
		if r, ok := blocked[row.Recipient]; ok {
			results = append(results, r)
			continue
		}
		if row.Status != semp.StatusRecipientNotFound {
			if row.Status == semp.StatusDelivered && deps.Logger != nil {
				deps.Logger.Info("envelope delivered locally",
					"identity", deps.Identity,
					"envelope", env.Postmark.ID,
					"recipient", row.Recipient,
				)
			}
			results = append(results, row)
			continue
		}
		// Non-local recipient: try the forwarder.
		address := row.Recipient
		if deps.Forwarder == nil {
			results = append(results, delivery.SubmissionResult{
				Recipient: address,
				Status:    semp.StatusRecipientNotFound,
				Reason:    "cross-domain forwarding is not enabled on this server",
			})
			continue
		}
		peerDomain := domainOf(address)
		// Clone the envelope per peer so each forward gets its own
		// session_mac re-bind without stomping on the other recipients.
		forwardEnv, err := envelope.Decode(wire)
		if err != nil {
			results = append(results, delivery.SubmissionResult{
				Recipient:  address,
				Status:     semp.StatusRejected,
				ReasonCode: semp.ReasonSealInvalid,
				Reason:     "forwarding failed",
			})
			continue
		}
		peerResp, err := deps.Forwarder.Forward(ctx, peerDomain, forwardEnv)
		if err != nil {
			results = append(results, delivery.SubmissionResult{
				Recipient:  address,
				Status:     semp.StatusRejected,
				ReasonCode: semp.ReasonServerUnavailable,
				Reason:     "forwarding to remote domain failed: " + err.Error(),
			})
			if deps.Logger != nil {
				deps.Logger.Warn("forward failed",
					"identity", deps.Identity,
					"envelope", env.Postmark.ID,
					"recipient", address,
					"err", err,
				)
			}
			continue
		}
		// The peer's response carries per-recipient results of its
		// own. For every delivered outcome, DELIVERY.md section 1.1.1.6
		// requires the sender server to verify the signed receipt
		// against the recipient domain's published signing key
		// before treating the result as terminal.
		for _, peerResult := range peerResp.Results {
			verified := verifyDeliveredReceipt(ctx, deps, peerDomain, forwardEnv, peerResult)
			results = append(results, verified)
			if deps.Logger != nil {
				deps.Logger.Info("envelope forwarded",
					"identity", deps.Identity,
					"envelope", env.Postmark.ID,
					"recipient", verified.Recipient,
					"status", string(verified.Status),
				)
			}
		}
	}

	resp := delivery.NewSubmissionResponse(env.Postmark.ID, results)
	return sendJSON(ctx, conn, resp)
}

// handleFederationSubmissionFrame processes one envelope arriving on a
// federation session. The envelope is ALREADY signed by the original
// sender domain and ALREADY session-MAC bound under this federation
// session's K_env_mac (the peer rebound it before forwarding).
func handleFederationSubmissionFrame(ctx context.Context, conn transport.Conn, raw []byte, deps FederationDeps) error {
	env, err := envelope.Decode(raw)
	if err != nil {
		resp := delivery.NewSubmissionResponse("malformed", []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: semp.ReasonSealInvalid,
			Reason:     err.Error(),
		}})
		_ = sendJSON(ctx, conn, resp)
		return fmt.Errorf("decode envelope: %w", err)
	}
	return handleFederationSubmission(ctx, conn, env, deps)
}

// handleFederationSubmission is the federation receiver path. The
// pipeline runs every step of DELIVERY.md section 2: it verifies both
// proofs (signature against the original sender domain's published
// key, session_mac against OUR K_env_mac), unwraps the brief, applies
// the user-level block list, and stores envelopes for local
// recipients. We MUST NOT re-sign: the domain signature is the
// provenance proof and any change would break it.
//
// Federation mode does not multi-hop. Recipients addressed to other
// domains are reported as recipient_not_found.
func handleFederationSubmission(ctx context.Context, conn transport.Conn, env *envelope.Envelope, deps FederationDeps) error {
	pipe := &delivery.Pipeline{
		Suite:         deps.Suite,
		EnvMAC:        deps.Session.EnvMAC,
		DomainKeys:    &storeDomainKeyLookup{store: deps.Store},
		DomainEncFP:   deps.DomainEncFP,
		DomainEncPriv: deps.DomainEncPriv,
		DomainEncPub:  deps.DomainEncPub,
		BlockList:     deps.BlockList,
		IsLocal:       isLocalAddressFor(deps.LocalDomain),
		Inbox:         deps.Inbox,
		Logger:        slogPrintf(deps.Logger),
	}
	pipeResult, err := pipe.Process(ctx, env)
	if err != nil {
		return fmt.Errorf("federation pipeline: %w", err)
	}
	if pipeResult.Rejected() {
		rej := pipeResult.Rejection
		resp := delivery.NewSubmissionResponse(env.Postmark.ID, []delivery.SubmissionResult{{
			Recipient:  deps.Identity,
			Status:     semp.StatusRejected,
			ReasonCode: rej.Code,
			Reason:     rej.Reason,
		}})
		_ = sendJSON(ctx, conn, resp)
		return fmt.Errorf("federation pipeline rejected envelope: %s", rej.Code)
	}
	// Override the pipeline's generic "recipient is not local" reason
	// text with the federation-specific "endpoint does not multi-hop"
	// for clarity in cross-domain logs. For every delivered outcome,
	// issue a SEMP_DELIVERY_RECEIPT inline per DELIVERY.md section
	// 1.1.1.5.
	for i := range pipeResult.Results {
		switch pipeResult.Results[i].Status {
		case semp.StatusRecipientNotFound:
			pipeResult.Results[i].Reason = "federation endpoint does not multi-hop"
		case semp.StatusDelivered:
			if deps.Logger != nil {
				deps.Logger.Info("federated delivery",
					"peer", deps.Identity,
					"envelope", env.Postmark.ID,
					"recipient", pipeResult.Results[i].Recipient,
				)
			}
			receipt, err := issueDeliveryReceipt(deps, env)
			if err != nil {
				if deps.Logger != nil {
					deps.Logger.Warn("issue receipt failed; demoting to silent",
						"peer", deps.Identity,
						"envelope", env.Postmark.ID,
						"err", err,
					)
				}
				pipeResult.Results[i] = delivery.SubmissionResult{
					Recipient: pipeResult.Results[i].Recipient,
					Status:    semp.StatusSilent,
					Reason:    "receipt issuance failed",
				}
			} else {
				pipeResult.Results[i].Receipt = receipt
			}
		}
	}
	resp := delivery.NewSubmissionResponse(env.Postmark.ID, pipeResult.Results)
	return sendJSON(ctx, conn, resp)
}

// sendJSON marshals v with encoding/json and writes the bytes to
// stream. Submission and fetch messages are not signed and do not
// need to round-trip through canonical form.
func sendJSON(ctx context.Context, stream transport.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return stream.Send(ctx, b)
}
