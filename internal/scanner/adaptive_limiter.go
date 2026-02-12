package scanner

import (
	"context"
	"sync"
)

type AdaptiveLimiter struct {
	mu     sync.Mutex
	limit  int
	min    int
	max    int
	tokens chan struct{}
}

func NewAdaptiveLimiter(min, max, initial int) *AdaptiveLimiter {
	if max <= 0 {
		max = 1
	}
	if min <= 0 {
		min = 1
	}
	if min > max {
		min = max
	}
	if initial < min {
		initial = min
	}
	if initial > max {
		initial = max
	}

	limiter := &AdaptiveLimiter{
		limit:  initial,
		min:    min,
		max:    max,
		tokens: make(chan struct{}, max),
	}
	for i := 0; i < initial; i++ {
		limiter.tokens <- struct{}{}
	}
	return limiter
}

func (l *AdaptiveLimiter) Acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.tokens:
		return nil
	}
}

func (l *AdaptiveLimiter) Release() {
	limit := l.Limit()
	if len(l.tokens) >= limit {
		return
	}
	select {
	case l.tokens <- struct{}{}:
	default:
	}
}

func (l *AdaptiveLimiter) Adjust(newLimit int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if newLimit < l.min {
		newLimit = l.min
	}
	if newLimit > l.max {
		newLimit = l.max
	}
	l.limit = newLimit

	for len(l.tokens) > l.limit {
		<-l.tokens
	}
	for len(l.tokens) < l.limit {
		select {
		case l.tokens <- struct{}{}:
		default:
			return l.limit
		}
	}

	return l.limit
}

func (l *AdaptiveLimiter) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}
