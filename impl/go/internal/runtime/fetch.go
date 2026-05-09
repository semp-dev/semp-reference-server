package runtime

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/transport"
)

// handleFetch returns every waiting envelope for the authenticated
// identity. SEMP_FETCH is a demo-only extension (HANDSHAKE.md section
// 4.6 leaves the wakeup mechanism out of scope).
func handleFetch(ctx context.Context, conn transport.Conn, raw []byte, inbox *delivery.Inbox, identity string, logger *slog.Logger) error {
	var req delivery.FetchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parse fetch request: %w", err)
	}
	if req.Type != delivery.FetchType || req.Step != delivery.FetchStepRequest {
		return fmt.Errorf("unexpected fetch type/step: %s/%s", req.Type, req.Step)
	}
	queued := inbox.Drain(identity)
	out := make([]string, 0, len(queued))
	for _, payload := range queued {
		out = append(out, base64.StdEncoding.EncodeToString(payload))
	}
	if logger != nil {
		logger.Info("fetch returned envelopes",
			"identity", identity,
			"count", len(out),
		)
	}
	return sendJSON(ctx, conn, delivery.NewFetchResponse(out))
}
