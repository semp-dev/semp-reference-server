package runtime

import (
	"context"

	"semp.dev/semp-go/keys"
)

// storeDomainKeyLookup adapts a keys.Store to delivery.DomainKeyLookup.
// The pipeline expects raw public-key bytes; the store records carry
// base64-encoded strings, so this thin shim handles the decode and
// returns ENOKEY-equivalent (nil, nil) when the domain has no record
// on file.
type storeDomainKeyLookup struct {
	store keys.Store
}

func (s *storeDomainKeyLookup) LookupDomainPublicKey(ctx context.Context, domain string) ([]byte, error) {
	if s == nil || s.store == nil {
		return nil, nil
	}
	rec, err := s.store.LookupDomainKey(ctx, domain)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	return decodeBase64(rec.PublicKey)
}
