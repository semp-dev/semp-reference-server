package runtime

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"semp.dev/semp-go/delivery"
)

var (
	base64Std    = base64.StdEncoding
	base64RawStd = base64.RawStdEncoding
)

// isLocalAddressFor returns a delivery.LocalAddressFunc closing over
// the supplied local domain. Used to wire pipeline.IsLocal in both
// client and federation modes.
func isLocalAddressFor(localDomain string) delivery.LocalAddressFunc {
	return func(address string) bool {
		at := strings.LastIndexByte(address, '@')
		if at < 0 {
			return false
		}
		return strings.EqualFold(address[at+1:], localDomain)
	}
}

// domainOf returns the domain part of a user address (the substring
// after the last '@'), or the empty string if the address has no '@'.
func domainOf(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	return address[at+1:]
}

// decodeBase64 is a tiny wrapper around encoding/base64 that accepts
// either the standard or the raw (unpadded) encoding, so callers that
// receive keys published by different implementations do not need to
// guess about padding.
func decodeBase64(s string) ([]byte, error) {
	if b, err := base64Std.DecodeString(s); err == nil {
		return b, nil
	}
	return base64RawStd.DecodeString(s)
}

// slogPrintfAdapter wraps an *slog.Logger so it satisfies the
// delivery.PipelineLogger / Printf-shaped logger interface that the
// surviving pipeline still expects.
type slogPrintfAdapter struct {
	l *slog.Logger
}

func (a slogPrintfAdapter) Printf(format string, args ...any) {
	if a.l == nil {
		return
	}
	a.l.Info(fmt.Sprintf(format, args...))
}

// slogPrintf returns a Printf-shaped logger over l, or nil when l is
// nil. The pipeline's Logger field is itself optional so a nil return
// disables pipeline logging without further checks.
func slogPrintf(l *slog.Logger) delivery.PipelineLogger {
	if l == nil {
		return nil
	}
	return slogPrintfAdapter{l: l}
}
