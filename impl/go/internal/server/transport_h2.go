// Server-side HTTP/2 persistent-session adapter for SEMP. Replicates
// the transport/h2.NewPersistentHandler body that lived in
// semp.dev/semp-go's transport/h2 package up through v0.4.2 and was
// deleted in v0.5.0 when the library separated from the reference
// server runtime.
//
// Inbound POSTs without a Semp-Session-Id header mint a fresh session
// id and spawn the accept callback against the per-session
// transport.Conn adapter; subsequent POSTs route to the existing
// session by id. Strict turn-based: the accept callback alternates
// Recv -> Send -> Recv -> Send.

package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/h2"
)

// defaultH2IdleTimeout is the duration after which a server-side
// persistent session is closed if no POST arrives. The value matches
// the deleted h2.DefaultIdleTimeout constant.
const defaultH2IdleTimeout = 60 * time.Second

// newH2Handler returns an http.Handler that maintains per-session
// virtual transport.Conns keyed on the Semp-Session-Id header. It
// closes the gap between HTTP/2's per-request model and the symmetric
// transport.Conn model used by handshake and the runtime dispatch
// loop.
//
// Lifecycle per session:
//
//  1. A POST with no Semp-Session-Id creates a new session: a virtual
//     conn is allocated, registered under a freshly generated session
//     id, and handed to the accept callback in a new goroutine.
//  2. The same POST's body is pushed onto the virtual conn's turn
//     queue as the first Recv, and the HTTP handler blocks waiting
//     for the accept callback to Send its reply.
//  3. Subsequent POSTs with a matching Semp-Session-Id repeat step 2,
//     routing the body to the existing virtual conn.
//  4. When the accept callback returns, or when the idle timer fires,
//     or when Close is called, the virtual conn is closed and removed
//     from the session registry.
func newH2Handler(cfg h2.Config, accept func(transport.Conn)) http.Handler {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = h2.DefaultMaxBodyBytes
	}
	idleTimeout := defaultH2IdleTimeout
	reg := newH2SessionRegistry()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > maxBody {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBody {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		sid := r.Header.Get(h2.HeaderSessionID)
		var vc *h2VirtualConn
		if sid == "" {
			newSID, err := newH2SessionID()
			if err != nil {
				http.Error(w, "session id: "+err.Error(), http.StatusInternalServerError)
				return
			}
			sid = newSID
			vc = newH2VirtualConn(sid, r.RemoteAddr, idleTimeout)
			localSID := sid
			vc.onClose = func() { reg.remove(localSID) }
			reg.put(sid, vc)
			// Run the accept callback in its own goroutine. For direct
			// consumers the callback loops Recv/Send for the lifetime
			// of the session.
			go accept(vc)
		} else {
			vc = reg.get(sid)
			if vc == nil {
				http.Error(w, "unknown session", http.StatusNotFound)
				return
			}
		}
		vc.touch()

		t := &h2Turn{req: body, replyCh: make(chan h2TurnReply, 1)}
		select {
		case vc.turns <- t:
		case <-vc.closed:
			http.Error(w, "session closed", http.StatusGone)
			return
		case <-r.Context().Done():
			return
		}

		select {
		case rep := <-t.replyCh:
			if rep.err != nil {
				http.Error(w, rep.err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", h2.ContentType)
			w.Header().Set(h2.HeaderSessionID, sid)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(rep.body)
		case <-vc.closed:
			http.Error(w, "session closed", http.StatusGone)
			return
		case <-r.Context().Done():
			return
		}
	})
}

// h2Turn is one client-POST-driven exchange: the HTTP handler pushes
// the request body and waits on replyCh for the accept callback to
// populate a response.
type h2Turn struct {
	req     []byte
	replyCh chan h2TurnReply
}

// h2TurnReply is what the accept goroutine hands back to the HTTP
// handler. Exactly one of body or err is populated.
type h2TurnReply struct {
	body []byte
	err  error
}

// h2VirtualConn is the server-side transport.Conn that sits behind a
// sequence of HTTP/2 POSTs sharing one Semp-Session-Id. From the
// accept callback's perspective it looks like a plain bidirectional
// message stream; under the hood each Recv pops a turn submitted by
// a POST handler and each Send hands the reply back to that handler.
type h2VirtualConn struct {
	sessionID string
	peer      string

	turns chan *h2Turn

	pendingMu sync.Mutex
	pending   *h2Turn

	closeOnce sync.Once
	closed    chan struct{}

	idleTimeout time.Duration
	idleTimer   *time.Timer
	idleMu      sync.Mutex

	onClose func()
}

func newH2VirtualConn(sessionID, peer string, idleTimeout time.Duration) *h2VirtualConn {
	vc := &h2VirtualConn{
		sessionID:   sessionID,
		peer:        peer,
		turns:       make(chan *h2Turn, 1),
		closed:      make(chan struct{}),
		idleTimeout: idleTimeout,
	}
	if idleTimeout > 0 {
		vc.idleTimer = time.AfterFunc(idleTimeout, func() { _ = vc.Close() })
	}
	return vc
}

func (vc *h2VirtualConn) touch() {
	if vc == nil || vc.idleTimer == nil {
		return
	}
	vc.idleMu.Lock()
	defer vc.idleMu.Unlock()
	vc.idleTimer.Reset(vc.idleTimeout)
}

// Send hands msg to the HTTP handler currently waiting on a pending
// turn. Returns an error if there is no pending turn (Send was called
// before Recv) or if the conn is closed.
func (vc *h2VirtualConn) Send(ctx context.Context, msg []byte) error {
	if vc == nil {
		return errors.New("h2: nil virtual conn")
	}
	select {
	case <-vc.closed:
		return errors.New("h2: virtual conn closed")
	default:
	}
	vc.pendingMu.Lock()
	t := vc.pending
	vc.pending = nil
	vc.pendingMu.Unlock()
	if t == nil {
		return errors.New("h2: Send called without a pending POST")
	}
	select {
	case t.replyCh <- h2TurnReply{body: msg}:
		return nil
	case <-vc.closed:
		return errors.New("h2: virtual conn closed")
	case <-ctx.Done():
		select {
		case t.replyCh <- h2TurnReply{err: ctx.Err()}:
		default:
		}
		return ctx.Err()
	}
}

// Recv blocks until a new POST arrives for this session, then returns
// its request body. If the previous turn's reply was never sent, it
// is abandoned with an error so its HTTP handler returns 500 rather
// than hanging.
func (vc *h2VirtualConn) Recv(ctx context.Context) ([]byte, error) {
	if vc == nil {
		return nil, errors.New("h2: nil virtual conn")
	}
	vc.pendingMu.Lock()
	if prev := vc.pending; prev != nil {
		select {
		case prev.replyCh <- h2TurnReply{err: errors.New("h2: accept callback abandoned previous turn")}:
		default:
		}
		vc.pending = nil
	}
	vc.pendingMu.Unlock()

	select {
	case t, ok := <-vc.turns:
		if !ok {
			return nil, io.EOF
		}
		vc.pendingMu.Lock()
		vc.pending = t
		vc.pendingMu.Unlock()
		return t.req, nil
	case <-vc.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close tears down the virtual conn. Any goroutine blocked in Recv
// sees io.EOF on its next return. Any HTTP handler currently waiting
// on a pending turn's reply gets a "closed" error via the reply
// channel. The onClose hook runs at most once after the close fires.
func (vc *h2VirtualConn) Close() error {
	if vc == nil {
		return nil
	}
	vc.closeOnce.Do(func() {
		close(vc.closed)
		if vc.idleTimer != nil {
			vc.idleTimer.Stop()
		}
		vc.pendingMu.Lock()
		if prev := vc.pending; prev != nil {
			select {
			case prev.replyCh <- h2TurnReply{err: errors.New("h2: virtual conn closed")}:
			default:
			}
			vc.pending = nil
		}
		vc.pendingMu.Unlock()
		if vc.onClose != nil {
			vc.onClose()
		}
	})
	return nil
}

// Peer returns the HTTP client's RemoteAddr.
func (vc *h2VirtualConn) Peer() string {
	if vc == nil {
		return ""
	}
	return vc.peer
}

// h2SessionRegistry is a tiny concurrent map from session id to
// h2VirtualConn. Used by newH2Handler to route subsequent POSTs to
// the same virtual conn as the initial POST that created the
// session.
type h2SessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*h2VirtualConn
}

func newH2SessionRegistry() *h2SessionRegistry {
	return &h2SessionRegistry{sessions: map[string]*h2VirtualConn{}}
}

func (r *h2SessionRegistry) put(sid string, vc *h2VirtualConn) {
	r.mu.Lock()
	r.sessions[sid] = vc
	r.mu.Unlock()
}

func (r *h2SessionRegistry) get(sid string) *h2VirtualConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[sid]
}

func (r *h2SessionRegistry) remove(sid string) {
	r.mu.Lock()
	delete(r.sessions, sid)
	r.mu.Unlock()
}

// crockfordAlphabet is the Crockford base32 alphabet used by ULIDs.
// We don't need bit-for-bit ULID compliance; just a collision-free
// 26-character identifier.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordEncoding = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

// newH2SessionID returns a ULID-shaped 26-character session
// identifier with a 48-bit millisecond timestamp prefix and 80 bits
// of randomness.
func newH2SessionID() (string, error) {
	var raw [16]byte
	now := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(raw[:8], now<<16)
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("h2: session id randomness: %w", err)
	}
	enc := crockfordEncoding.EncodeToString(raw[:])
	if len(enc) > 26 {
		enc = enc[:26]
	}
	return enc, nil
}
