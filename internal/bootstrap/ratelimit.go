package bootstrap

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/config"
	"golang.org/x/time/rate"
)

// rateLimiter implements per-IP token bucket rate limiting with configurable
// exemptions for health and metadata endpoints.
type rateLimiter struct {
	config          config.RateLimitConfig
	limiters        map[string]*rate.Limiter
	mu              sync.RWMutex
	cleanupInterval time.Duration
	lastAccess      map[string]time.Time
}

// newRateLimiter creates a global rate limiter with the provided configuration.
// cleanupInterval defaults to 5 minutes; override only in tests before calling.
func newRateLimiter(cfg config.RateLimitConfig) *rateLimiter {
	return newRateLimiterWithInterval(cfg, 5*time.Minute)
}

// newRateLimiterWithInterval creates a rate limiter with a custom cleanup interval.
func newRateLimiterWithInterval(cfg config.RateLimitConfig, cleanupInterval time.Duration) *rateLimiter {
	rl := &rateLimiter{
		config:          cfg,
		limiters:        make(map[string]*rate.Limiter),
		cleanupInterval: cleanupInterval,
		lastAccess:      make(map[string]time.Time),
	}
	// Start background cleanup of stale limiters
	go rl.cleanupLoop()
	return rl
}

// middleware returns an HTTP middleware that applies rate limiting.
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check path exemptions
		if rl.isExemptPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP for rate limiting key
		clientIP := rl.clientIP(r)
		limiter := rl.getLimiter(clientIP)

		if !limiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isExemptPath checks if the request path matches any exempt prefix.
func (rl *rateLimiter) isExemptPath(path string) bool {
	for _, exempt := range rl.config.ExemptPaths {
		if strings.HasPrefix(path, exempt) {
			return true
		}
	}
	return false
}

// clientIP extracts the client IP from the request, respecting X-Forwarded-For
// when behind trusted proxies.
func (rl *rateLimiter) clientIP(r *http.Request) string {
	ip := remoteIPForRateLimit(r)
	// Strip port if present
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		return host
	}
	return ip
}

// getLimiter returns or creates a rate limiter for the given client IP.
func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Update last access time
	rl.lastAccess[ip] = time.Now()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(rl.config.RequestsPerSecond), rl.config.BurstSize)
		rl.limiters[ip] = limiter
	}
	return limiter
}

// cleanupLoop periodically removes stale limiters to prevent memory growth.
func (rl *rateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanupStaleLimiters()
	}
}

// cleanupStaleLimiters removes limiters that haven't been accessed recently.
func (rl *rateLimiter) cleanupStaleLimiters() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, lastAccess := range rl.lastAccess {
		if lastAccess.Before(cutoff) {
			delete(rl.limiters, ip)
			delete(rl.lastAccess, ip)
		}
	}
}

// rateLimitMiddleware creates a rate limiting middleware from configuration.
func rateLimitMiddleware(cfg config.RateLimitConfig) func(http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}
	rl := newRateLimiter(cfg)
	return rl.middleware
}
