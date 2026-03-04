package scanner

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

type RetryOptions struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Jitter    float64
}

func DefaultRetryOptions() RetryOptions {
	return RetryOptions{
		Attempts:  3,
		BaseDelay: 2 * time.Second,
		MaxDelay:  30 * time.Second,
		Jitter:    0.2,
	}
}

func WithRetry(ctx context.Context, opts RetryOptions, op func() error) (int, error) {
	_, attempts, err := WithRetryValue(ctx, opts, func() (struct{}, error) {
		return struct{}{}, op()
	})
	return attempts, err
}

func WithRetryValue[T any](ctx context.Context, opts RetryOptions, op func() (T, error)) (T, int, error) {
	options := normalizeRetryOptions(opts)
	var lastValue T
	var lastErr error
	backoff := options.BaseDelay

	for attempt := 1; attempt <= options.Attempts; attempt++ {
		if ctx.Err() != nil {
			return lastValue, attempt - 1, ctx.Err()
		}

		value, err := op()
		lastValue = value
		lastErr = err
		if err == nil {
			return value, attempt, nil
		}
		if ctx.Err() != nil {
			return lastValue, attempt, ctx.Err()
		}
		if attempt == options.Attempts || !isRetryableScanError(err) {
			return lastValue, attempt, err
		}

		wait := applyJitter(backoff, options.Jitter)
		if wait > options.MaxDelay {
			wait = options.MaxDelay
		}
		if !sleepWithContext(ctx, wait) {
			return lastValue, attempt, ctx.Err()
		}
		backoff *= 2
		if backoff > options.MaxDelay {
			backoff = options.MaxDelay
		}
	}

	return lastValue, options.Attempts, lastErr
}

func normalizeRetryOptions(opts RetryOptions) RetryOptions {
	defaults := DefaultRetryOptions()
	if opts.Attempts <= 0 {
		opts.Attempts = defaults.Attempts
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = defaults.BaseDelay
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = defaults.MaxDelay
	}
	if opts.Jitter <= 0 {
		opts.Jitter = defaults.Jitter
	}
	return opts
}

func applyJitter(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return base
	}
	val := cryptoRandomFloat64()
	factor := 1 + ((val*2 - 1) * jitter)
	if factor < 0 {
		factor = 0
	}
	return time.Duration(float64(base) * factor)
}

func cryptoRandomFloat64() float64 {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0.5
	}
	v := binary.BigEndian.Uint64(b[:]) >> 11
	return float64(v) / (1 << 53)
}

func isRetryableScanError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	for _, token := range []string{
		"timeout",
		"timed out",
		"tempor",
		"connection reset",
		"connection refused",
		"connection closed",
		"broken pipe",
		"eof",
		"server busy",
		"service unavailable",
		"statement timed out",
		"warehouse is suspended",
		"net/http: tls handshake timeout",
	} {
		if strings.Contains(msg, token) {
			return true
		}
	}

	return false
}
