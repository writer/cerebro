package sourceruntime

import (
	"testing"
	"time"
)

func fixedSyncJitter(value float64) SyncRetryPolicy {
	return SyncRetryPolicy{Jitter: func() float64 { return value }}
}

func TestSyncRetryPolicyHoldsOperatorClassesWithoutGrowth(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, class := range []SyncFailureClass{
		SyncFailureUnauthorized,
		SyncFailurePermissionDenied,
		SyncFailureInvalidConfig,
		SyncFailureDecodeFailed,
		SyncFailureCursorInvalid,
	} {
		for _, failures := range []uint32{1, 3, 50} {
			decision := fixedSyncJitter(0.9).Decide(class, failures, time.Hour, now)
			if want := now.Add(6 * time.Hour); !decision.NextAttemptAt.Equal(want) || decision.CircuitOpen {
				t.Fatalf("%s failures=%d decision = %#v, want %s without circuit", class, failures, decision, want)
			}
			if SyncCircuitOpenAfter(class) != 0 {
				t.Fatalf("%s circuit threshold = %d, want 0", class, SyncCircuitOpenAfter(class))
			}
		}
	}
}

func TestSyncRetryPolicyRateLimited(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := map[string]struct {
		retryAfter time.Duration
		jitter     float64
		want       time.Duration
	}{
		"floor without retry-after":   {0, 0, 5 * time.Minute},
		"floor with max jitter":       {0, 1, 6 * time.Minute},
		"provider delay above floor":  {10 * time.Minute, 0, 10 * time.Minute},
		"provider delay with jitter":  {10 * time.Minute, 0.5, 11 * time.Minute},
		"provider delay capped":       {time.Hour, 0, 15 * time.Minute},
		"short provider delay floors": {time.Minute, 0, 5 * time.Minute},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := fixedSyncJitter(tc.jitter).NextSyncAttempt(SyncFailureRateLimited, 4, tc.retryAfter, now)
			if want := now.Add(tc.want); !got.Equal(want) {
				t.Fatalf("NextSyncAttempt() = %s, want %s", got, want)
			}
		})
	}
	if SyncCircuitOpenAfter(SyncFailureRateLimited) != 0 {
		t.Fatal("rate_limited must not open the circuit")
	}
}

func TestSyncRetryPolicyExponentialGrowthCapAndCircuit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ceilings := map[uint32]time.Duration{
		0: 2 * time.Minute,
		1: 2 * time.Minute,
		2: 4 * time.Minute,
		3: 8 * time.Minute,
		4: 16 * time.Minute,
		5: 32 * time.Minute,
		6: time.Hour,
		7: time.Hour,
	}
	for _, class := range []SyncFailureClass{SyncFailureProviderUnavailable, SyncFailureProjectionUnavailable, SyncFailureInternal} {
		if SyncCircuitOpenAfter(class) != 8 {
			t.Fatalf("%s circuit threshold = %d, want 8", class, SyncCircuitOpenAfter(class))
		}
		for failures, ceiling := range ceilings {
			upper := fixedSyncJitter(1).Decide(class, failures, 0, now)
			if !upper.NextAttemptAt.Equal(now.Add(ceiling)) || upper.CircuitOpen {
				t.Fatalf("%s failures=%d upper = %#v, want %s", class, failures, upper, ceiling)
			}
			half := fixedSyncJitter(0.5).NextSyncAttempt(class, failures, 0, now)
			if !half.Equal(now.Add(ceiling / 2)) {
				t.Fatalf("%s failures=%d half jitter = %s, want %s", class, failures, half, now.Add(ceiling/2))
			}
			if lower := fixedSyncJitter(0).NextSyncAttempt(class, failures, 0, now); !lower.Equal(now) {
				t.Fatalf("%s failures=%d zero jitter = %s, want now", class, failures, lower)
			}
		}
		for _, failures := range []uint32{8, 9, 1000} {
			decision := fixedSyncJitter(0).Decide(class, failures, 0, now)
			if !decision.NextAttemptAt.Equal(now.Add(time.Hour)) || !decision.CircuitOpen {
				t.Fatalf("%s failures=%d decision = %#v, want circuit open at cap", class, failures, decision)
			}
		}
	}
}

func TestSyncRetryPolicyDoesNotBackOffIncompleteOrCancelled(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, class := range []SyncFailureClass{SyncFailureBudgetExhausted, SyncFailureCancelled} {
		decision := fixedSyncJitter(0.7).Decide(class, 20, time.Hour, now)
		if !decision.NextAttemptAt.Equal(now) || decision.CircuitOpen {
			t.Fatalf("%s decision = %#v, want immediate retry", class, decision)
		}
	}
}

func TestSyncRetryPolicyClampsJitterSource(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if got := fixedSyncJitter(-3).NextSyncAttempt(SyncFailureInternal, 3, 0, now); !got.Equal(now) {
		t.Fatalf("negative jitter = %s, want now", got)
	}
	if got := fixedSyncJitter(7).NextSyncAttempt(SyncFailureInternal, 3, 0, now); !got.Equal(now.Add(8 * time.Minute)) {
		t.Fatalf("oversized jitter = %s, want ceiling", got)
	}
	for range 100 {
		got := SyncRetryPolicy{}.NextSyncAttempt(SyncFailureInternal, 3, 0, now)
		if got.Before(now) || got.After(now.Add(8*time.Minute)) {
			t.Fatalf("default jitter = %s, want within [now, now+8m]", got)
		}
	}
}
