package deviceauth

import (
	"sync"
	"time"
)

// TokenBucket is a process-local token-bucket rate limiter keyed by string.
// It is not a substitute for an edge rate limiter (the design assumes AWS
// WAF is in front), but it shaves off retry storms before they reach the
// store.
type TokenBucket struct {
	mu               sync.Mutex
	ratePerSecond    float64
	burst            float64
	now              func() time.Time
	buckets          map[string]*tokenBucketEntry
	lastSweep        time.Time
	maxIdle          time.Duration
}

type tokenBucketEntry struct {
	tokens    float64
	updatedAt time.Time
}

// NewTokenBucket constructs a token bucket with the given steady-state rate
// and burst capacity. A rate <= 0 disables the limiter.
func NewTokenBucket(ratePerSecond float64, burst int) *TokenBucket {
	bucket := &TokenBucket{
		ratePerSecond: ratePerSecond,
		burst:         float64(burst),
		now:           time.Now,
		buckets:       make(map[string]*tokenBucketEntry),
		maxIdle:       10 * time.Minute,
	}
	if bucket.burst <= 0 {
		bucket.burst = 1
	}
	return bucket
}

// Allow returns true if the caller may proceed for the given key.
func (b *TokenBucket) Allow(key string) bool {
	if b == nil || b.ratePerSecond <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweepLocked(now)
	entry, ok := b.buckets[key]
	if !ok {
		entry = &tokenBucketEntry{tokens: b.burst, updatedAt: now}
		b.buckets[key] = entry
	}
	elapsed := now.Sub(entry.updatedAt).Seconds()
	if elapsed > 0 {
		entry.tokens += elapsed * b.ratePerSecond
		if entry.tokens > b.burst {
			entry.tokens = b.burst
		}
		entry.updatedAt = now
	}
	if entry.tokens < 1 {
		return false
	}
	entry.tokens--
	return true
}

func (b *TokenBucket) sweepLocked(now time.Time) {
	if now.Sub(b.lastSweep) < time.Minute {
		return
	}
	b.lastSweep = now
	for key, entry := range b.buckets {
		if now.Sub(entry.updatedAt) > b.maxIdle {
			delete(b.buckets, key)
		}
	}
}
