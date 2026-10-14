package sourceruntime

import (
	"math"
	"math/rand/v2"
	"time"
)

const (
	// SyncOperatorActionHold is how long a runtime waits after a failure that
	// only an operator can fix (credentials, scopes, config, contracts). It
	// does not grow: the next attempt is a periodic probe for the fix.
	SyncOperatorActionHold = 6 * time.Hour
	// SyncRateLimitFloor is the minimum wait after a provider rate limit.
	SyncRateLimitFloor = 5 * time.Minute
	// SyncRateLimitJitterFraction spreads rate-limited retries so runtimes
	// sharing one provider budget do not return in lockstep.
	SyncRateLimitJitterFraction = 0.2
	SyncBackoffBase             = 2 * time.Minute
	SyncBackoffCap              = time.Hour
	// SyncCircuitOpenThreshold is the consecutive-failure count at which
	// exponential classes stop jittering and hold at SyncBackoffCap.
	SyncCircuitOpenThreshold uint32 = 8
)

// SyncRetryPolicy computes when a failed source runtime sync may run again.
// It is deterministic given Jitter.
type SyncRetryPolicy struct {
	// Jitter returns a value in [0, 1). Nil uses math/rand/v2.
	Jitter func() float64
}

// SyncRetryDecision is the outcome of applying the policy to one failure.
type SyncRetryDecision struct {
	NextAttemptAt time.Time
	CircuitOpen   bool
}

// NextSyncAttempt returns the earliest time the next scheduled sync may run.
// A result equal to now means no backoff.
func (p SyncRetryPolicy) NextSyncAttempt(class SyncFailureClass, consecutiveFailures uint32, retryAfter time.Duration, now time.Time) time.Time {
	return p.Decide(class, consecutiveFailures, retryAfter, now).NextAttemptAt
}

// Decide applies the policy and reports whether the circuit is open.
func (p SyncRetryPolicy) Decide(class SyncFailureClass, consecutiveFailures uint32, retryAfter time.Duration, now time.Time) SyncRetryDecision {
	if consecutiveFailures == 0 {
		consecutiveFailures = 1
	}
	switch {
	case SyncFailureNeedsOperator(class):
		return SyncRetryDecision{NextAttemptAt: now.Add(SyncOperatorActionHold)}
	case class == SyncFailureRateLimited:
		wait := max(boundSyncRetryAfter(retryAfter), SyncRateLimitFloor)
		wait += time.Duration(float64(wait) * SyncRateLimitJitterFraction * p.jitter())
		return SyncRetryDecision{NextAttemptAt: now.Add(wait)}
	case SyncFailureBacksOffExponentially(class):
		if consecutiveFailures >= SyncCircuitOpenThreshold {
			return SyncRetryDecision{NextAttemptAt: now.Add(SyncBackoffCap), CircuitOpen: true}
		}
		ceiling := syncExponentialCeiling(consecutiveFailures)
		return SyncRetryDecision{NextAttemptAt: now.Add(time.Duration(float64(ceiling) * p.jitter()))}
	default:
		return SyncRetryDecision{NextAttemptAt: now}
	}
}

// SyncCircuitOpenAfter returns the consecutive-failure threshold at which the
// stored schedule should report an open circuit for class, or zero when the
// class never opens the circuit.
func SyncCircuitOpenAfter(class SyncFailureClass) uint32 {
	if SyncFailureBacksOffExponentially(class) {
		return SyncCircuitOpenThreshold
	}
	return 0
}

// SyncFailureNeedsOperator reports classes that will not clear without an
// operator change.
func SyncFailureNeedsOperator(class SyncFailureClass) bool {
	switch class {
	case SyncFailureUnauthorized, SyncFailurePermissionDenied, SyncFailureInvalidConfig, SyncFailureDecodeFailed, SyncFailureCursorInvalid:
		return true
	default:
		return false
	}
}

// SyncFailureBacksOffExponentially reports classes retried with capped
// exponential backoff.
func SyncFailureBacksOffExponentially(class SyncFailureClass) bool {
	switch class {
	case SyncFailureProviderUnavailable, SyncFailureProjectionUnavailable, SyncFailureInternal:
		return true
	default:
		return false
	}
}

func syncExponentialCeiling(consecutiveFailures uint32) time.Duration {
	ceiling := SyncBackoffBase
	for i := uint32(1); i < consecutiveFailures; i++ {
		ceiling *= 2
		if ceiling >= SyncBackoffCap {
			return SyncBackoffCap
		}
	}
	return ceiling
}

func (p SyncRetryPolicy) jitter() float64 {
	var value float64
	if p.Jitter != nil {
		value = p.Jitter()
	} else {
		value = rand.Float64() //nolint:gosec // retry jitter is not security-sensitive.
	}
	if value < 0 || math.IsNaN(value) {
		return 0
	}
	if value >= 1 {
		return 1
	}
	return value
}
