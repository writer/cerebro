package sync

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"golang.org/x/time/rate"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type retryClass int

const (
	retryNone retryClass = iota
	retryThrottle
	retryTransient
	retryAuth
)

func (c retryClass) String() string {
	switch c {
	case retryThrottle:
		return "throttle"
	case retryTransient:
		return "transient"
	case retryAuth:
		return "auth"
	default:
		return "none"
	}
}

func (c retryClass) shouldRetry() bool {
	return c == retryThrottle || c == retryTransient
}

type retryOptions struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Jitter    float64
}

const (
	defaultAWSRateLimit   rate.Limit = 10
	defaultAWSRateBurst              = 5
	defaultGCPRateLimit   rate.Limit = 5
	defaultGCPRateBurst              = 3
	defaultAzureRateLimit rate.Limit = 5
	defaultAzureRateBurst            = 3
)

func defaultAWSRetryOptions() retryOptions {
	return retryOptions{
		Attempts:  4,
		BaseDelay: 2 * time.Second,
		MaxDelay:  30 * time.Second,
		Jitter:    0.2,
	}
}

func defaultGCPRetryOptions() retryOptions {
	return retryOptions{
		Attempts:  3,
		BaseDelay: 1 * time.Second,
		MaxDelay:  20 * time.Second,
		Jitter:    0.2,
	}
}

func defaultAzureRetryOptions() retryOptions {
	return retryOptions{
		Attempts:  3,
		BaseDelay: 1 * time.Second,
		MaxDelay:  20 * time.Second,
		Jitter:    0.2,
	}
}

type retryDelayFunc func(class retryClass, attempt int, opts retryOptions) time.Duration

func retryFetch(
	ctx context.Context,
	limiter *rate.Limiter,
	opts retryOptions,
	logger *slog.Logger,
	message string,
	logFields []any,
	classify func(error) retryClass,
	delayFn retryDelayFunc,
	op func() ([]map[string]interface{}, error),
) ([]map[string]interface{}, error) {
	if opts.Attempts <= 0 {
		opts.Attempts = 1
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = 1 * time.Second
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = 30 * time.Second
	}
	if delayFn == nil {
		delayFn = defaultRetryDelay
	}

	var lastErr error
	var lastRows []map[string]interface{}
	for attempt := 1; attempt <= opts.Attempts; attempt++ {
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return lastRows, err
			}
		}

		rows, err := op()
		if err == nil {
			return rows, nil
		}
		lastErr = err
		if len(rows) > 0 {
			lastRows = rows
		}

		class := classify(err)
		if !class.shouldRetry() || attempt == opts.Attempts {
			return rows, err
		}

		delay := delayFn(class, attempt, opts)
		if logger != nil {
			fields := append([]any{}, logFields...)
			fields = append(fields, "attempt", attempt, "delay", delay, "reason", class.String(), "error", err)
			logger.Warn(message, fields...)
		}
		if err := sleepWithContext(ctx, delay); err != nil {
			return lastRows, err
		}
	}

	return lastRows, lastErr
}

func defaultRetryDelay(class retryClass, attempt int, opts retryOptions) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := opts.BaseDelay * time.Duration(1<<uint(attempt-1))
	if delay > opts.MaxDelay {
		delay = opts.MaxDelay
	}
	return applyRetryJitter(delay, opts.Jitter)
}

func awsRetryDelayForClass(class retryClass, attempt int, opts retryOptions) time.Duration {
	if class == retryThrottle {
		return awsRetryDelay(attempt - 1)
	}
	return defaultRetryDelay(class, attempt, opts)
}

func applyRetryJitter(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return base
	}
	factor := 1 + ((cryptoRandomFloat64()*2 - 1) * jitter)
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

func classifyAWSError(err error) retryClass {
	if err == nil || isContextError(err) {
		return retryNone
	}
	if isAWSRateLimitError(err) {
		return retryThrottle
	}
	if isAWSAuthError(err) {
		return retryAuth
	}
	if isRetryableNetworkError(err) || isAWSServiceUnavailable(err) {
		return retryTransient
	}
	return retryNone
}

func isAWSAuthError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		switch code {
		case "accessdenied",
			"accessdeniedexception",
			"unauthorizedoperation",
			"unrecognizedclientexception",
			"invalidclienttokenid",
			"expiredtoken",
			"authfailure",
			"invalidsignatureexception",
			"signaturedoesnotmatch":
			return true
		}
	}
	return false
}

func isAWSServiceUnavailable(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		switch code {
		case "internalfailure",
			"serviceunavailable",
			"requesttimeout",
			"requesttimeoutexception":
			return true
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode() >= 500
	}
	return false
}

func classifyGCPError(err error) retryClass {
	if err == nil || isContextError(err) {
		return retryNone
	}

	if statusErr, ok := status.FromError(err); ok {
		switch statusErr.Code() {
		case codes.ResourceExhausted:
			return retryThrottle
		case codes.PermissionDenied, codes.Unauthenticated:
			return retryAuth
		case codes.DeadlineExceeded, codes.Unavailable:
			return retryTransient
		}
	}

	var gErr *googleapi.Error
	if errors.As(err, &gErr) {
		switch gErr.Code {
		case 401, 403:
			return retryAuth
		case 429:
			return retryThrottle
		default:
			if gErr.Code >= 500 {
				return retryTransient
			}
		}
		for _, item := range gErr.Errors {
			reason := strings.ToLower(item.Reason)
			if strings.Contains(reason, "ratelimit") || strings.Contains(reason, "quota") {
				return retryThrottle
			}
		}
	}

	if isRetryableNetworkError(err) {
		return retryTransient
	}
	return retryNone
}

func classifyAzureError(err error) retryClass {
	if err == nil || isContextError(err) {
		return retryNone
	}

	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		code := strings.ToLower(respErr.ErrorCode)
		if respErr.StatusCode == 401 || respErr.StatusCode == 403 {
			return retryAuth
		}
		if respErr.StatusCode == 429 || strings.Contains(code, "throttl") || strings.Contains(code, "toomany") {
			return retryThrottle
		}
		if respErr.StatusCode >= 500 {
			return retryTransient
		}
	}

	if isRetryableNetworkError(err) {
		return retryTransient
	}
	return retryNone
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isRetryableNetworkError(err error) bool {
	if err == nil || isContextError(err) {
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
		"net/http: tls handshake timeout",
	} {
		if strings.Contains(msg, token) {
			return true
		}
	}

	return false
}
