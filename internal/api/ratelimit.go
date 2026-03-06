package api

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	rate       int           // requests per window
	window     time.Duration // time window
	buckets    map[string]*bucket
	mu         sync.RWMutex
	cleanupInt time.Duration
	stopCh     chan struct{}
	doneCh     chan struct{}
	closeOnce  sync.Once
}

type bucket struct {
	tokens    int
	lastReset time.Time
}

// RateLimitConfig configures the rate limiter
type RateLimitConfig struct {
	RequestsPerWindow int
	Window            time.Duration
	Enabled           bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	if cfg.RequestsPerWindow == 0 {
		cfg.RequestsPerWindow = 1000
	}
	if cfg.Window == 0 {
		cfg.Window = time.Hour
	}

	rl := &RateLimiter{
		rate:       cfg.RequestsPerWindow,
		window:     cfg.Window,
		buckets:    make(map[string]*bucket),
		cleanupInt: cfg.Window * 2,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request is allowed for the given key
func (rl *RateLimiter) Allow(key string) (bool, int, time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]

	if !ok {
		// New bucket
		b = &bucket{
			tokens:    rl.rate - 1,
			lastReset: now,
		}
		rl.buckets[key] = b
		return true, b.tokens, now.Add(rl.window)
	}

	// Check if window has passed
	if now.Sub(b.lastReset) >= rl.window {
		b.tokens = rl.rate - 1
		b.lastReset = now
		return true, b.tokens, now.Add(rl.window)
	}

	// Check if tokens available
	if b.tokens <= 0 {
		return false, 0, b.lastReset.Add(rl.window)
	}

	b.tokens--
	return true, b.tokens, b.lastReset.Add(rl.window)
}

// cleanup removes old buckets periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInt)
	defer func() {
		ticker.Stop()
		close(rl.doneCh)
	}()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, b := range rl.buckets {
				if now.Sub(b.lastReset) > rl.window*2 {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Close stops background cleanup goroutines.
func (rl *RateLimiter) Close() {
	if rl == nil {
		return
	}

	rl.closeOnce.Do(func() {
		close(rl.stopCh)
		<-rl.doneCh
	})
}

// RateLimitMiddleware creates middleware that rate limits requests
func RateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler {
	return RateLimitMiddlewareWithLimiter(cfg, nil)
}

// RateLimitMiddlewareWithLimiter creates middleware using a caller-managed limiter instance.
func RateLimitMiddlewareWithLimiter(cfg RateLimitConfig, rl *RateLimiter) func(http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	if rl == nil {
		rl = NewRateLimiter(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for public endpoints.
			if isPublicEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Use API key or IP as rate limit key
			key := getClientKey(r)

			allowed, remaining, reset := rl.Allow(key)

			// Always set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.RequestsPerWindow))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))

			if !allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(time.Until(reset).Seconds()), 10))
				writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Rate limit exceeded. Try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientKey extracts the rate limit key from the request
func getClientKey(r *http.Request) string {
	// Canonicalize API key extraction across Authorization and X-API-Key
	// so the same key always maps to the same rate limit bucket.
	if key, err := extractAPIKeyStrict(r); err == nil && key != "" {
		return "apikey:" + key
	}

	// Fall back to IP address
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return "ip:" + ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return "ip:" + ip
	}
	return "ip:" + r.RemoteAddr
}

// Pagination helpers

// PaginationParams holds pagination parameters
type PaginationParams struct {
	Limit  int
	Offset int
	Cursor string
}

// PaginationResponse holds pagination metadata
type PaginationResponse struct {
	Total      int64  `json:"total,omitempty"`
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// ParsePagination extracts pagination params from request
func ParsePagination(r *http.Request, defaultLimit, maxLimit int) PaginationParams {
	p := PaginationParams{
		Limit:  defaultLimit,
		Offset: 0,
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			p.Limit = l
		}
	}

	if p.Limit > maxLimit {
		p.Limit = maxLimit
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			p.Offset = o
		}
	}

	p.Cursor = r.URL.Query().Get("cursor")

	return p
}

// BuildPaginationResponse builds pagination metadata
func BuildPaginationResponse(total int64, params PaginationParams, resultCount int) PaginationResponse {
	return PaginationResponse{
		Total:   total,
		Limit:   params.Limit,
		Offset:  params.Offset,
		HasMore: int64(params.Offset+resultCount) < total,
	}
}
