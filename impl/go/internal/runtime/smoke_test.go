package runtime

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"semp.dev/semp-go/transport"
)

// pipeConn is a one-direction in-memory transport.Conn used to exercise
// the dispatch loop without a real network. Each pipeConn reads from
// inCh and writes to outCh; pairing two pipeConns with swapped
// channels yields a bidirectional connection.
type pipeConn struct {
	peer string
	inCh chan []byte
	outCh chan []byte

	closeOnce sync.Once
	closed    chan struct{}
}

func newPipePair(peerA, peerB string) (*pipeConn, *pipeConn) {
	atob := make(chan []byte, 4)
	btoa := make(chan []byte, 4)
	a := &pipeConn{peer: peerA, inCh: btoa, outCh: atob, closed: make(chan struct{})}
	b := &pipeConn{peer: peerB, inCh: atob, outCh: btoa, closed: make(chan struct{})}
	// When one side closes, signal the other so its Recv unblocks.
	aClosed := a.closed
	bClosed := b.closed
	go func() {
		select {
		case <-aClosed:
			b.closeOnce.Do(func() { close(bClosed) })
		case <-bClosed:
			a.closeOnce.Do(func() { close(aClosed) })
		}
	}()
	return a, b
}

func (p *pipeConn) Send(ctx context.Context, msg []byte) error {
	select {
	case <-p.closed:
		return errors.New("pipe closed")
	case <-ctx.Done():
		return ctx.Err()
	case p.outCh <- msg:
		return nil
	}
}

func (p *pipeConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-p.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-p.inCh:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	}
}

func (p *pipeConn) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

func (p *pipeConn) Peer() string { return p.peer }

var _ transport.Conn = (*pipeConn)(nil)

// TestServeClientReturnsOnClose verifies that the client dispatch loop
// returns io.EOF when the connection closes cleanly. This is the
// minimum smoke test that wires session.Dispatch through the runtime
// package without requiring a full handshake to be set up.
func TestServeClientReturnsOnClose(t *testing.T) {
	t.Parallel()

	server, client := newPipePair("server", "client")
	defer server.Close()
	defer client.Close()

	deps := ClientDeps{
		LocalDomain: "test.example",
		Identity:    "alice@test.example",
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeClient(context.Background(), server, deps)
	}()

	// Close the client side: ServeClient should return io.EOF.
	_ = client.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeClient did not return after pipe close")
	}
}

// TestServeFederationReturnsOnClose mirrors TestServeClientReturnsOnClose
// for the federation entry point.
func TestServeFederationReturnsOnClose(t *testing.T) {
	t.Parallel()

	server, peer := newPipePair("server", "peer")
	defer server.Close()
	defer peer.Close()

	deps := FederationDeps{
		LocalDomain: "test.example",
		Identity:    "peer.example",
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ServeFederation(context.Background(), server, deps)
	}()

	_ = peer.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected io.EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeFederation did not return after pipe close")
	}
}
