package sourceruntime

import (
	"context"
	"errors"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime/eventadmission"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

// SyncFailureClass is the stable retry category for a failed source runtime
// sync. Values follow the error contract in
// docs/engineering/rust-source-runtime-adr.md plus projection_unavailable for
// failures of Cerebro's own append or projection stores.
type SyncFailureClass string

const (
	SyncFailureUnauthorized          SyncFailureClass = "unauthorized"
	SyncFailurePermissionDenied      SyncFailureClass = "permission_denied"
	SyncFailureInvalidConfig         SyncFailureClass = "invalid_config"
	SyncFailureRateLimited           SyncFailureClass = "rate_limited"
	SyncFailureProviderUnavailable   SyncFailureClass = "provider_unavailable"
	SyncFailureDecodeFailed          SyncFailureClass = "decode_failed"
	SyncFailureCursorInvalid         SyncFailureClass = "cursor_invalid"
	SyncFailureBudgetExhausted       SyncFailureClass = "budget_exhausted"
	SyncFailureCancelled             SyncFailureClass = "cancelled"
	SyncFailureProjectionUnavailable SyncFailureClass = "projection_unavailable"
	SyncFailureInternal              SyncFailureClass = "internal"
)

const (
	httpStatusUnauthorized    = 401
	httpStatusForbidden       = 403
	httpStatusTooManyRequests = 429
	httpStatusServerError     = 500

	maxSyncRetryAfter = 15 * time.Minute
)

// SyncFailure is the classified form of a failed sync.
type SyncFailure struct {
	Class      SyncFailureClass
	RetryAfter time.Duration
}

// syncRetryAfterCarrier is implemented by errors that carry a provider
// declared retry delay.
type syncRetryAfterCarrier interface {
	error
	RetryAfter() time.Duration
}

// ClassifySyncFailure maps a sync error to its retry class using only typed
// error identity. Unknown errors are internal.
func ClassifySyncFailure(err error) SyncFailure {
	if err == nil {
		return SyncFailure{}
	}
	failure := SyncFailure{Class: classifySyncFailureClass(err)}
	var carrier syncRetryAfterCarrier
	if errors.As(err, &carrier) {
		failure.RetryAfter = boundSyncRetryAfter(carrier.RetryAfter())
	}
	return failure
}

func boundSyncRetryAfter(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	if value > maxSyncRetryAfter {
		return maxSyncRetryAfter
	}
	return value
}

func classifySyncFailureClass(err error) SyncFailureClass {
	// Lease loss and cancellation are checked first: a provider error joined
	// with a lost lease is still the caller's decision, not a provider fault.
	if anyErrorIs(err,
		context.Canceled,
		ports.ErrSourceRuntimeLeaseLost,
		ErrSyncInProgress,
		sourceworker.ErrWorkerLeaseLost,
		sourceworker.ErrWorkerStaleAuthority,
	) {
		return SyncFailureCancelled
	}
	if class, ok := classifySyncSentinel(err); ok {
		return class
	}
	// HTTP status precedes SourceError kind because sources commonly wrap a
	// 401/403/429 status in the generic provider kind.
	if class, ok := classifyHTTPStatus(err); ok {
		return class
	}
	if class, ok := classifySourceErrorKind(err); ok {
		return class
	}
	return SyncFailureInternal
}

func classifySyncSentinel(err error) (SyncFailureClass, bool) {
	switch {
	case anyErrorIs(err,
		sourceworker.ErrProviderAuthentication,
		sourceworker.ErrCredentialUnavailable,
		ErrCredentialLeaseRevoked,
	):
		return SyncFailureUnauthorized, true
	case errors.Is(err, sourceworker.ErrProviderPermission):
		return SyncFailurePermissionDenied, true
	case anyErrorIs(err,
		sourcecdk.ErrInvalidConfig,
		sourceworker.ErrSourceConfiguration,
		sourceworker.ErrCredentialReferenceMissing,
		sourceworker.ErrWorkerUnsupported,
		ErrInvalidRequest,
	):
		return SyncFailureInvalidConfig, true
	case errors.Is(err, sourceworker.ErrProviderRateLimited):
		return SyncFailureRateLimited, true
	case errors.Is(err, sourceworker.ErrWorkerCursorInvalid):
		// Checked before decode_failed because it also wraps ErrWorkerContract.
		return SyncFailureCursorInvalid, true
	case anyErrorIs(err,
		sourceworker.ErrProviderResponseTooLarge,
		sourceworker.ErrWorkerResultTooLarge,
		sourcecdk.ErrNDJSONDecompressedTooLarge,
	):
		return SyncFailureBudgetExhausted, true
	case anyErrorIs(err,
		sourceworker.ErrProviderMalformedResponse,
		sourceworker.ErrWorkerContract,
		sourcecdk.ErrInvalidEventEnvelope,
		eventadmission.ErrBatchRejected,
	):
		return SyncFailureDecodeFailed, true
	case anyErrorIs(err,
		sourceworker.ErrProviderTimeout,
		sourceworker.ErrProviderEgress,
		sourceworker.ErrProviderUnexpectedStatus,
		context.DeadlineExceeded,
	):
		return SyncFailureProviderUnavailable, true
	case anyErrorIs(err,
		sourceworker.ErrWorkerAppend,
		sourceworker.ErrWorkerProjection,
		ports.ErrGraphRuntimeUnavailable,
		ports.ErrAppendLogDeadLetterBacklogHardLimit,
	):
		return SyncFailureProjectionUnavailable, true
	}
	var exhausted *ports.AppendLogPublishExhaustedError
	if errors.As(err, &exhausted) {
		return SyncFailureProjectionUnavailable, true
	}
	if anyErrorIs(err,
		sourceworker.ErrWorkerInternal,
		sourceworker.ErrInvalidExecution,
		ErrRuntimeUnavailable,
		eventadmission.ErrKernelUnavailable,
		ErrCredentialLeaseInvalidScope,
		ErrCredentialLeaseExpired,
		ErrCredentialLeaseScopeMismatch,
		ErrCredentialLeaseConsumed,
	) {
		return SyncFailureInternal, true
	}
	return "", false
}

func classifySourceErrorKind(err error) (SyncFailureClass, bool) {
	var sourceErr *sourcecdk.SourceError
	if !errors.As(err, &sourceErr) || sourceErr == nil {
		return "", false
	}
	switch sourceErr.Kind {
	case sourcecdk.ErrorKindInvalidConfig:
		return SyncFailureInvalidConfig, true
	case sourcecdk.ErrorKindAuth:
		return SyncFailureUnauthorized, true
	case sourcecdk.ErrorKindPermission:
		return SyncFailurePermissionDenied, true
	case sourcecdk.ErrorKindRateLimited:
		return SyncFailureRateLimited, true
	case sourcecdk.ErrorKindProvider, sourcecdk.ErrorKindTransient:
		return SyncFailureProviderUnavailable, true
	case sourcecdk.ErrorKindDecode, sourcecdk.ErrorKindInvalidEvent:
		return SyncFailureDecodeFailed, true
	default:
		return "", false
	}
}

func classifyHTTPStatus(err error) (SyncFailureClass, bool) {
	var statusErr *sourcecdk.HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr == nil {
		return "", false
	}
	switch {
	case statusErr.Code == httpStatusUnauthorized:
		return SyncFailureUnauthorized, true
	case statusErr.Code == httpStatusForbidden:
		return SyncFailurePermissionDenied, true
	case statusErr.Code == httpStatusTooManyRequests:
		return SyncFailureRateLimited, true
	case statusErr.Code >= httpStatusServerError:
		return SyncFailureProviderUnavailable, true
	default:
		return "", false
	}
}

func anyErrorIs(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
