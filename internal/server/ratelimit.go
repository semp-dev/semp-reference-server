package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ipRateLimiter implements a fixed-window rate limiter keyed by client IP.
// Used to protect endpoints like /v1/register from abuse (finding 1.5).
type ipRateLimiter struct {
	mu       sync.Mutex
	requests map[string]*window
	limit    int
	window   time.Duration
}

type window struct {
	count  int
	start  time.Time
}

func newIPRateLimiter(limit int, windowDuration time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		requests: make(map[string]*window),
		limit:    limit,
		window:   windowDuration,
	}
}

// allow reports whether the given IP is within the rate limit.
func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	w, ok := rl.requests[ip]
	if !ok || now.Sub(w.start) >= rl.window {
		rl.requests[ip] = &window{count: 1, start: now}
		return true
	}
	w.count++
	return w.count <= rl.limit
}

// cleanup removes stale entries. Should be called periodically.
func (rl *ipRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, w := range rl.requests {
		if now.Sub(w.start) >= rl.window {
			delete(rl.requests, ip)
		}
	}
}

// clientIP extracts the client IP from the request, stripping the port.
func clientIP(r *http.Request) string {
	// Prefer X-Forwarded-For if behind a reverse proxy.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (leftmost) IP.
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
