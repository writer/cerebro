package providers

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func retryAfterDelay(headers http.Header) (time.Duration, bool) {
	if raw := strings.TrimSpace(headers.Get("Retry-After")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil {
			return clampRetryDelay(time.Duration(seconds) * time.Second), true
		}
		if retryAt, err := http.ParseTime(raw); err == nil {
			return clampRetryDelay(time.Until(retryAt)), true
		}
	}
	return rateLimitResetDelay(headers)
}

func rateLimitResetDelay(headers http.Header) (time.Duration, bool) {
	resetSeconds, err := strconv.ParseInt(headers.Get("X-Rate-Limit-Reset"), 10, 64)
	if err != nil {
		return 0, false
	}
	return clampRetryDelay(time.Until(time.Unix(resetSeconds, 0))), true
}

func clampRetryDelay(delay time.Duration) time.Duration {
	if delay < 0 {
		return 0
	}
	return delay
}
