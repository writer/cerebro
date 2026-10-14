package sourceruntime

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceruntime/eventadmission"
	"github.com/writer/cerebro/internal/sourceruntime/sourceworker"
)

func TestClassifySyncFailureMapsEverySentinel(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want SyncFailureClass
	}{
		"context canceled":             {context.Canceled, SyncFailureCancelled},
		"lease lost":                   {ports.ErrSourceRuntimeLeaseLost, SyncFailureCancelled},
		"sync in progress":             {ErrSyncInProgress, SyncFailureCancelled},
		"worker lease lost":            {sourceworker.ErrWorkerLeaseLost, SyncFailureCancelled},
		"worker stale authority":       {sourceworker.ErrWorkerStaleAuthority, SyncFailureCancelled},
		"provider authentication":      {sourceworker.ErrProviderAuthentication, SyncFailureUnauthorized},
		"credential unavailable":       {sourceworker.ErrCredentialUnavailable, SyncFailureUnauthorized},
		"credential lease revoked":     {ErrCredentialLeaseRevoked, SyncFailureUnauthorized},
		"provider permission":          {sourceworker.ErrProviderPermission, SyncFailurePermissionDenied},
		"cdk invalid config":           {sourcecdk.ErrInvalidConfig, SyncFailureInvalidConfig},
		"worker source configuration":  {sourceworker.ErrSourceConfiguration, SyncFailureInvalidConfig},
		"credential reference missing": {sourceworker.ErrCredentialReferenceMissing, SyncFailureInvalidConfig},
		"worker unsupported":           {sourceworker.ErrWorkerUnsupported, SyncFailureInvalidConfig},
		"invalid request":              {ErrInvalidRequest, SyncFailureInvalidConfig},
		"provider rate limited":        {sourceworker.ErrProviderRateLimited, SyncFailureRateLimited},
		"worker cursor invalid":        {sourceworker.ErrWorkerCursorInvalid, SyncFailureCursorInvalid},
		"provider response too large":  {sourceworker.ErrProviderResponseTooLarge, SyncFailureBudgetExhausted},
		"worker result too large":      {sourceworker.ErrWorkerResultTooLarge, SyncFailureBudgetExhausted},
		"ndjson too large":             {sourcecdk.ErrNDJSONDecompressedTooLarge, SyncFailureBudgetExhausted},
		"provider malformed response":  {sourceworker.ErrProviderMalformedResponse, SyncFailureDecodeFailed},
		"worker contract":              {sourceworker.ErrWorkerContract, SyncFailureDecodeFailed},
		"invalid event envelope":       {sourcecdk.ErrInvalidEventEnvelope, SyncFailureDecodeFailed},
		"admission batch rejected":     {eventadmission.ErrBatchRejected, SyncFailureDecodeFailed},
		"admission rejected error":     {&eventadmission.RejectedError{}, SyncFailureDecodeFailed},
		"provider timeout":             {sourceworker.ErrProviderTimeout, SyncFailureProviderUnavailable},
		"provider egress":              {sourceworker.ErrProviderEgress, SyncFailureProviderUnavailable},
		"provider unexpected status":   {sourceworker.ErrProviderUnexpectedStatus, SyncFailureProviderUnavailable},
		"deadline exceeded":            {context.DeadlineExceeded, SyncFailureProviderUnavailable},
		"worker append":                {sourceworker.ErrWorkerAppend, SyncFailureProjectionUnavailable},
		"worker projection":            {sourceworker.ErrWorkerProjection, SyncFailureProjectionUnavailable},
		"graph runtime unavailable":    {ports.ErrGraphRuntimeUnavailable, SyncFailureProjectionUnavailable},
		"dead letter hard limit":       {ports.ErrAppendLogDeadLetterBacklogHardLimit, SyncFailureProjectionUnavailable},
		"append publish exhausted":     {&ports.AppendLogPublishExhaustedError{Subject: "events", Err: errors.New("nats down")}, SyncFailureProjectionUnavailable},
		"worker internal":              {sourceworker.ErrWorkerInternal, SyncFailureInternal},
		"invalid execution":            {sourceworker.ErrInvalidExecution, SyncFailureInternal},
		"runtime unavailable":          {ErrRuntimeUnavailable, SyncFailureInternal},
		"admission kernel unavailable": {eventadmission.ErrKernelUnavailable, SyncFailureInternal},
		"credential lease scope":       {ErrCredentialLeaseInvalidScope, SyncFailureInternal},
		"credential lease expired":     {ErrCredentialLeaseExpired, SyncFailureInternal},
		"credential lease mismatch":    {ErrCredentialLeaseScopeMismatch, SyncFailureInternal},
		"credential lease consumed":    {ErrCredentialLeaseConsumed, SyncFailureInternal},
		"source kind invalid config":   {sourcecdk.WrapSourceError(sourcecdk.ErrorKindInvalidConfig, "s", "f", errors.New("x")), SyncFailureInvalidConfig},
		"source kind auth":             {sourcecdk.WrapSourceError(sourcecdk.ErrorKindAuth, "s", "f", errors.New("x")), SyncFailureUnauthorized},
		"source kind permission":       {sourcecdk.WrapSourceError(sourcecdk.ErrorKindPermission, "s", "f", errors.New("x")), SyncFailurePermissionDenied},
		"source kind rate limited":     {sourcecdk.WrapSourceError(sourcecdk.ErrorKindRateLimited, "s", "f", errors.New("x")), SyncFailureRateLimited},
		"source kind provider":         {sourcecdk.WrapSourceError(sourcecdk.ErrorKindProvider, "s", "f", errors.New("x")), SyncFailureProviderUnavailable},
		"source kind transient":        {sourcecdk.WrapSourceError(sourcecdk.ErrorKindTransient, "s", "f", errors.New("x")), SyncFailureProviderUnavailable},
		"source kind decode":           {sourcecdk.WrapSourceError(sourcecdk.ErrorKindDecode, "s", "f", errors.New("x")), SyncFailureDecodeFailed},
		"source kind invalid event":    {sourcecdk.WrapSourceError(sourcecdk.ErrorKindInvalidEvent, "s", "f", errors.New("x")), SyncFailureDecodeFailed},
		"http 401":                     {&sourcecdk.HTTPStatusError{Code: 401}, SyncFailureUnauthorized},
		"http 403":                     {&sourcecdk.HTTPStatusError{Code: 403}, SyncFailurePermissionDenied},
		"http 429":                     {&sourcecdk.HTTPStatusError{Code: 429}, SyncFailureRateLimited},
		"http 503":                     {&sourcecdk.HTTPStatusError{Code: 503}, SyncFailureProviderUnavailable},
		"http 404":                     {&sourcecdk.HTTPStatusError{Code: 404}, SyncFailureInternal},
		"unknown":                      {errors.New("unclassified"), SyncFailureInternal},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifySyncFailure(tc.err).Class; got != tc.want {
				t.Fatalf("ClassifySyncFailure(%v) = %q, want %q", tc.err, got, tc.want)
			}
			wrapped := fmt.Errorf("sync runtime: %w", tc.err)
			if got := ClassifySyncFailure(wrapped).Class; got != tc.want {
				t.Fatalf("ClassifySyncFailure(wrapped %v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestClassifySyncFailurePrecedence(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want SyncFailureClass
	}{
		"lease loss beats provider failure": {errors.Join(ports.ErrSourceRuntimeLeaseLost, sourceworker.ErrProviderAuthentication), SyncFailureCancelled},
		"http status beats generic provider kind": {
			sourcecdk.WrapSourceError(sourcecdk.ErrorKindProvider, "s", "f", &sourcecdk.HTTPStatusError{Code: 401}),
			SyncFailureUnauthorized,
		},
		"worker sentinel beats source kind": {
			sourcecdk.WrapSourceError(sourcecdk.ErrorKindDecode, "s", "f", sourceworker.ErrWorkerCursorInvalid),
			SyncFailureCursorInvalid,
		},
		"cursor invalid still matches contract": {sourceworker.ErrWorkerCursorInvalid, SyncFailureCursorInvalid},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifySyncFailure(tc.err).Class; got != tc.want {
				t.Fatalf("ClassifySyncFailure(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
	if !errors.Is(sourceworker.ErrWorkerCursorInvalid, sourceworker.ErrWorkerContract) {
		t.Fatal("ErrWorkerCursorInvalid must wrap ErrWorkerContract")
	}
}

func TestClassifySyncFailureNilIsEmpty(t *testing.T) {
	t.Parallel()
	if got := ClassifySyncFailure(nil); got != (SyncFailure{}) {
		t.Fatalf("ClassifySyncFailure(nil) = %#v, want zero", got)
	}
}

type retryAfterTestError struct {
	delay time.Duration
}

func (e retryAfterTestError) Error() string             { return "rate limited" }
func (e retryAfterTestError) RetryAfter() time.Duration { return e.delay }
func (e retryAfterTestError) Unwrap() error             { return sourceworker.ErrProviderRateLimited }

func TestClassifySyncFailureExtractsBoundedRetryAfter(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		delay time.Duration
		want  time.Duration
	}{
		"in range": {7 * time.Minute, 7 * time.Minute},
		"capped":   {2 * time.Hour, 15 * time.Minute},
		"negative": {-time.Second, 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			failure := ClassifySyncFailure(fmt.Errorf("sync: %w", retryAfterTestError{delay: tc.delay}))
			if failure.Class != SyncFailureRateLimited || failure.RetryAfter != tc.want {
				t.Fatalf("ClassifySyncFailure() = %#v, want rate_limited retry_after=%s", failure, tc.want)
			}
		})
	}
	if got := ClassifySyncFailure(sourceworker.ErrProviderRateLimited).RetryAfter; got != 0 {
		t.Fatalf("retry_after without carrier = %s, want 0", got)
	}
}
