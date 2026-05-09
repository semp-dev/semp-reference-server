// Server-side WebSocket adapter for SEMP. Replicates the
// transport/ws.NewHandler body that lived in semp.dev/semp-go's
// transport/ws package up through v0.4.2 and was deleted in v0.5.0
// when the library separated from the reference server runtime.
//
// The handler upgrades inbound HTTP requests to a SEMP WebSocket
// connection, validates the `semp.v1` subprotocol per TRANSPORT.md
// section 4.1.1, and delivers the resulting transport.Conn to the
// supplied accept callback.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/coder/websocket"

	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/ws"
)

// wsServerConfig groups the server-side WebSocket adapter knobs.
// v0.5.0's ws.Config dropped server-side fields (OriginPatterns) when
// the library separated client and server roles, so we carry them here.
type wsServerConfig struct {
	// MaxEnvelopeSize is the maximum SEMP message size in bytes that
	// the upgraded conn will accept on read. Zero means
	// ws.DefaultMaxEnvelopeSize.
	MaxEnvelopeSize int64

	// OriginPatterns is forwarded to websocket.AcceptOptions.OriginPatterns.
	// Used by the listener to authorize cross-origin upgrade requests.
	OriginPatterns []string
}

// newWSHandler returns an http.Handler that upgrades inbound HTTP
// requests to SEMP WebSocket connections. Each accepted connection is
// delivered to the supplied accept function in its own goroutine.
//
// This is the entry point used to mount SEMP on the existing
// *http.Server in this binary.
func newWSHandler(cfg wsServerConfig, accept func(transport.Conn)) http.Handler {
	limit := cfg.MaxEnvelopeSize
	if limit <= 0 {
		limit = ws.DefaultMaxEnvelopeSize
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wc, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:   []string{ws.Subprotocol},
			OriginPatterns: cfg.OriginPatterns,
		})
		if err != nil {
			// Accept already wrote an HTTP error response.
			return
		}
		if wc.Subprotocol() != ws.Subprotocol {
			_ = wc.Close(websocket.StatusPolicyViolation, "subprotocol not confirmed")
			return
		}
		wc.SetReadLimit(limit)
		c := &wsConn{
			ws:   wc,
			peer: r.RemoteAddr,
		}
		accept(c)
	})
}

// wsConn is the server-side transport.Conn over a WebSocket. It
// mirrors the client-side ws.Conn from semp-go but is owned by this
// package so the runtime does not depend on a deleted server-side
// package.
type wsConn struct {
	ws   *websocket.Conn
	peer string

	closeOnce sync.Once
}

// Send transmits one SEMP message as a single WebSocket text frame
// (TRANSPORT.md section 4.1.2).
func (c *wsConn) Send(ctx context.Context, msg []byte) error {
	if c == nil || c.ws == nil {
		return errors.New("ws: nil connection")
	}
	if err := c.ws.Write(ctx, websocket.MessageText, msg); err != nil {
		return fmt.Errorf("ws: send: %w", err)
	}
	return nil
}

// Recv blocks until the next complete SEMP message is available, then
// returns its bytes. Binary frames are rejected per TRANSPORT.md
// section 4.1.2.
func (c *wsConn) Recv(ctx context.Context) ([]byte, error) {
	if c == nil || c.ws == nil {
		return nil, errors.New("ws: nil connection")
	}
	mt, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("ws: recv: %w", err)
	}
	if mt != websocket.MessageText {
		return nil, fmt.Errorf("ws: unexpected message type %v (SEMP requires text frames)", mt)
	}
	return data, nil
}

// Close sends a clean close frame and tears down the underlying
// connection.
func (c *wsConn) Close() error {
	if c == nil || c.ws == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		err = c.ws.Close(websocket.StatusNormalClosure, "")
	})
	return err
}

// Peer returns a human-readable identifier for the remote endpoint.
func (c *wsConn) Peer() string {
	if c == nil {
		return ""
	}
	return c.peer
}
