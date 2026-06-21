package sourcecdk

import (
	"context"
	"errors"
	"time"
)

// Retryable HTTP status codes are defined as literals so the Source CDK keeps no
// net/http dependency, which the bootstrap HTTP-boundary guardrail reserves for
// internal/sourcehttp.
const (
	statusTooManyRequests  = 429
	statusServerErrorFloor = 500
)

// HTTPStatusError carries an HTTP status code alongside a provider message so
// sources can classify unauthorized and retryable responses without re-parsing
// the raw response body.
type HTTPStatusError struct {
	Code    int
	Message string
}

// Error returns the provider-supplied (or status-derived) message.
func (e *HTTPStatusError) Error() string {
	return e.Message
}

// StatusCode returns the HTTP status code carried by the error.
func (e *HTTPStatusError) StatusCode() int {
	return e.Code
}

// IsHTTPStatus reports whether err is (or wraps) an *HTTPStatusError carrying the
// given status code.
func IsHTTPStatus(err error, code int) bool {
	var statusErr *HTTPStatusError
	return errors.As(err, &statusErr) && statusErr.Code == code
}

// IsRetryableHTTPStatus reports whether err carries a 429 Too Many Requests or any
// 5xx status code, the responses a source should retry with backoff.
func IsRetryableHTTPStatus(err error) bool {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.Code == statusTooManyRequests || statusErr.Code >= statusServerErrorFloor
}

// SleepContext blocks for delay or until ctx is cancelled, returning ctx.Err() if
// the wait is interrupted. A non-positive delay returns immediately.
func SleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
