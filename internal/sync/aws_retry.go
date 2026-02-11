package sync

import (
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	awsPageRetryMax      = 4
	awsRetryBaseDelay    = 2 * time.Second
	awsSlowPageThreshold = 5 * time.Second
)

func awsRetryDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}

	delay := awsRetryBaseDelay * time.Duration(1<<attempt)
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}

	jitter := time.Duration(rand.Int63n(int64(delay / 2)))
	return delay/2 + jitter
}

func isAWSRateLimitError(err error) bool {
	if err == nil {
		return false
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		if strings.Contains(code, "throttl") ||
			strings.Contains(code, "toomanyrequests") ||
			code == "requestlimitexceeded" ||
			code == "limitexceededexception" ||
			code == "slowdown" {
			return true
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() == 429
	}

	return false
}

func logAWSPageDuration(logger *slog.Logger, service, operation string, page int, duration time.Duration, items int) {
	slow := duration >= awsSlowPageThreshold
	logger.Info("aws page fetched", "service", service, "operation", operation, "page", page, "items", items, "duration", duration, "slow", slow)
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
