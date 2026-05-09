package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/transport"
)

// domainEncKeyLookup is the optional interface a Store may implement
// to expose the domain encryption key alongside the signing key. The
// reference server's *store.SQLiteStore satisfies it.
type domainEncKeyLookup interface {
	LookupDomainEncryptionKey(domain string) *keys.Record
}

// handleClientKeys fulfills a SEMP_KEYS request from a connected
// client. Local addresses are served directly from the server's own
// store; addresses on a peer domain known to the Forwarder are
// fetched cross-domain via the federation session. Unknown domains
// return status="not_found".
//
// Reference: CLIENT.md section 5.4, section 5.4.6.
func handleClientKeys(ctx context.Context, conn transport.Conn, raw []byte, deps ClientDeps) error {
	var req keys.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parse SEMP_KEYS request: %w", err)
	}
	if req.Type != keys.RequestType || req.Step != keys.RequestStepRequest {
		return fmt.Errorf("unexpected SEMP_KEYS type/step: %s/%s", req.Type, req.Step)
	}

	results := make([]keys.ResponseResult, 0, len(req.Addresses))
	for _, addr := range req.Addresses {
		d := domainOf(addr)
		if d == deps.LocalDomain {
			local := lookupLocalKeys(ctx, deps.Store, addr, req.IncludeDomainKeys)
			if local.Status == keys.StatusFound {
				if err := signLocalResult(deps, &local); err != nil {
					local.Status = keys.StatusError
					local.ErrorReason = err.Error()
				}
			}
			results = append(results, local)
			continue
		}
		// Remote domain. Try the Forwarder.
		if deps.Forwarder == nil {
			results = append(results, keys.ResponseResult{
				Address: addr,
				Status:  keys.StatusNotFound,
				Domain:  d,
			})
			continue
		}
		peerReq := keys.NewRequest(newRequestID(), []string{addr})
		peerResp, err := deps.Forwarder.FetchKeys(ctx, d, peerReq)
		if err != nil {
			results = append(results, keys.ResponseResult{
				Address:     addr,
				Status:      keys.StatusError,
				Domain:      d,
				ErrorReason: err.Error(),
			})
			continue
		}
		found := false
		for _, r := range peerResp.Results {
			if r.Address == addr {
				results = append(results, r)
				found = true
				break
			}
		}
		if !found {
			results = append(results, keys.ResponseResult{
				Address: addr,
				Status:  keys.StatusNotFound,
				Domain:  d,
			})
		}
	}
	resp := keys.NewResponse(req.ID, results)
	return sendJSON(ctx, conn, resp)
}

// handleFederationKeys fulfills a SEMP_KEYS request received over a
// federation session. We only resolve addresses on our own local
// domain because federation does not multi-hop.
func handleFederationKeys(ctx context.Context, conn transport.Conn, raw []byte, deps FederationDeps) error {
	var req keys.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parse SEMP_KEYS request: %w", err)
	}
	if req.Type != keys.RequestType || req.Step != keys.RequestStepRequest {
		return fmt.Errorf("unexpected SEMP_KEYS type/step: %s/%s", req.Type, req.Step)
	}

	results := make([]keys.ResponseResult, 0, len(req.Addresses))
	clientLikeDeps := ClientDeps{
		Suite:          deps.Suite,
		Store:          deps.Store,
		LocalDomain:    deps.LocalDomain,
		DomainSignFP:   deps.DomainSignFP,
		DomainSignPriv: deps.DomainSignPriv,
	}
	for _, addr := range req.Addresses {
		d := domainOf(addr)
		if d == deps.LocalDomain {
			local := lookupLocalKeys(ctx, deps.Store, addr, req.IncludeDomainKeys)
			if local.Status == keys.StatusFound {
				if err := signLocalResult(clientLikeDeps, &local); err != nil {
					local.Status = keys.StatusError
					local.ErrorReason = err.Error()
				}
			}
			results = append(results, local)
			continue
		}
		// Federation does not multi-hop.
		results = append(results, keys.ResponseResult{
			Address: addr,
			Status:  keys.StatusNotFound,
			Domain:  d,
		})
	}
	resp := keys.NewResponse(req.ID, results)
	return sendJSON(ctx, conn, resp)
}

// lookupLocalKeys serves one address from the server's own keys.Store.
// Returns status="not_found" if the address has no published keys.
func lookupLocalKeys(ctx context.Context, store keys.Store, address string, includeDomain bool) keys.ResponseResult {
	domain := domainOf(address)
	result := keys.ResponseResult{
		Address: address,
		Domain:  domain,
		Status:  keys.StatusNotFound,
	}
	if store == nil {
		return result
	}
	userKeys, err := store.LookupUserKeys(ctx, address)
	if err != nil {
		result.Status = keys.StatusError
		result.ErrorReason = err.Error()
		return result
	}
	if len(userKeys) == 0 {
		return result
	}
	result.UserKeys = userKeys
	result.Status = keys.StatusFound
	if includeDomain {
		if domRec, err := store.LookupDomainKey(ctx, domain); err == nil && domRec != nil {
			result.DomainKey = domRec
		}
		if domEncLookup, ok := store.(domainEncKeyLookup); ok {
			if encRec := domEncLookup.LookupDomainEncryptionKey(domain); encRec != nil {
				result.DomainEncKey = encRec
			}
		}
	}
	return result
}

// signLocalResult applies the domain signatures required by
// CLIENT.md section 3.3 / KEY.md section 5.1 to a ResponseResult
// before returning it to a client. Two signatures are attached:
//
//  1. A per-record domain signature on every user Record in
//     result.UserKeys, via keys.SignRecord.
//  2. A response-level OriginSignature on the whole result via
//     keys.SignResponseResult.
//
// Records are deep-copied before signing so we never mutate the
// store's shared copies.
func signLocalResult(deps ClientDeps, result *keys.ResponseResult) error {
	if deps.DomainSignPriv == nil {
		return errors.New("runtime: no domain signing key")
	}
	signer := deps.Suite.Signer()
	cloned := make([]*keys.Record, 0, len(result.UserKeys))
	for _, rec := range result.UserKeys {
		if rec == nil {
			continue
		}
		cp := *rec
		cp.Signatures = nil
		if err := keys.SignRecord(signer, deps.DomainSignPriv, deps.LocalDomain, deps.DomainSignFP, &cp); err != nil {
			return fmt.Errorf("sign user record %s: %w", rec.KeyID, err)
		}
		cloned = append(cloned, &cp)
	}
	result.UserKeys = cloned
	if err := keys.SignResponseResult(signer, deps.DomainSignPriv, deps.DomainSignFP, result); err != nil {
		return fmt.Errorf("sign response result: %w", err)
	}
	return nil
}

// newRequestID returns a short pseudo-ULID for a SEMP_KEYS request.
// Per-session uniqueness is sufficient for correlation; we use a
// timestamp + the address count to keep the function dependency-free.
func newRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
