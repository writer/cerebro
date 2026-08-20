package sourceruntime

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sourceRuntimeLeaseScopeForTest() CredentialLeaseScope {
	return CredentialLeaseScope{
		TenantID:            "tenant-a",
		RuntimeID:           "runtime-a",
		SourceID:            "source-a",
		FamilyID:            "identity_user",
		Operation:           "ReadPage",
		RequestIntentDigest: strings.Repeat("a", 64),
		LogicalPageID:       "page-0001",
		SourceGeneration:    7,
		AuthorityEpoch:      3,
	}
}

func sourceRuntimeCredentialLeaseForTest(scope CredentialLeaseScope, now time.Time) CredentialLeaseReference {
	return CredentialLeaseReference{
		ReferenceID: "lease-ref-1",
		Scope:       scope,
		IssuedAt:    now.Add(-time.Minute),
		ExpiresAt:   now.Add(time.Minute),
	}
}

func TestCredentialLeaseScopeRejectsCrossOperationReuseAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	scope := sourceRuntimeLeaseScopeForTest()
	lease := sourceRuntimeCredentialLeaseForTest(scope, now)
	if err := ValidateCredentialLeaseFor(lease, scope, now); err != nil {
		t.Fatalf("ValidateCredentialLeaseFor() error = %v", err)
	}

	otherPage := scope
	otherPage.LogicalPageID = "page-0002"
	if err := ValidateCredentialLeaseFor(lease, otherPage, now); !errors.Is(err, ErrCredentialLeaseScopeMismatch) {
		t.Fatalf("cross-page ValidateCredentialLeaseFor() error = %v, want scope mismatch", err)
	}

	otherOperation := scope
	otherOperation.Operation = "Discover"
	if err := ValidateCredentialLeaseFor(lease, otherOperation, now); !errors.Is(err, ErrCredentialLeaseScopeMismatch) {
		t.Fatalf("cross-operation ValidateCredentialLeaseFor() error = %v, want scope mismatch", err)
	}

	replaced := scope
	replaced.SourceGeneration++
	if err := ValidateCredentialLeaseFor(lease, replaced, now); !errors.Is(err, ErrCredentialLeaseScopeMismatch) {
		t.Fatalf("replacement ValidateCredentialLeaseFor() error = %v, want scope mismatch", err)
	}

	rolledBack := scope
	rolledBack.AuthorityEpoch++
	if err := ValidateCredentialLeaseFor(lease, rolledBack, now); !errors.Is(err, ErrCredentialLeaseScopeMismatch) {
		t.Fatalf("rollback ValidateCredentialLeaseFor() error = %v, want scope mismatch", err)
	}

	if err := ValidateCredentialLeaseFor(lease, scope, lease.ExpiresAt); !errors.Is(err, ErrCredentialLeaseExpired) {
		t.Fatalf("expired ValidateCredentialLeaseFor() error = %v, want expired", err)
	}
}

func TestCredentialLeaseConsumeRevokesDeterministicallyWithoutSecretDisclosure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	scope := sourceRuntimeLeaseScopeForTest()
	lease := sourceRuntimeCredentialLeaseForTest(scope, now)
	if err := ConsumeCredentialLease(&lease, scope, now); err != nil {
		t.Fatalf("ConsumeCredentialLease() error = %v", err)
	}
	if err := ConsumeCredentialLease(&lease, scope, now); !errors.Is(err, ErrCredentialLeaseRevoked) {
		t.Fatalf("second ConsumeCredentialLease() error = %v, want revoked", err)
	}
	err := ValidateCredentialLeaseScope(CredentialLeaseScope{
		TenantID:            "tenant-a",
		RuntimeID:           "runtime-a",
		SourceID:            "source-a",
		FamilyID:            "identity_user",
		Operation:           "ReadPage",
		RequestIntentDigest: "secret-sentinel",
		LogicalPageID:       "page-0001",
		SourceGeneration:    1,
		AuthorityEpoch:      1,
	})
	if !errors.Is(err, ErrCredentialLeaseInvalidScope) {
		t.Fatalf("ValidateCredentialLeaseScope() error = %v, want invalid scope", err)
	}
}

func TestRuntimeEgressFixtureModeRemainsOfflineAndLiveIsAllowlisted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	scope := sourceRuntimeLeaseScopeForTest()
	lease := sourceRuntimeCredentialLeaseForTest(scope, now)

	offline := DecideEgress(EgressPolicy{
		Mode:                EgressModeFixture,
		TenantID:            scope.TenantID,
		FamilyID:            scope.FamilyID,
		RequestIntentDigest: scope.RequestIntentDigest,
	}, "https://provider.example.test/users", scope, lease, now)
	if offline.Allowed || offline.Reason != "offline_mode" {
		t.Fatalf("fixture egress = %#v, want offline denial", offline)
	}

	live := EgressPolicy{
		Mode:                EgressModeLive,
		TenantID:            scope.TenantID,
		FamilyID:            scope.FamilyID,
		RequestIntentDigest: scope.RequestIntentDigest,
		AllowedOrigins:      map[string]struct{}{"https://provider.example.test": {}},
	}
	allowed := DecideEgress(live, "https://provider.example.test/users", scope, lease, now)
	if !allowed.Allowed || allowed.Origin != "https://provider.example.test" {
		t.Fatalf("live allowed egress = %#v, want provider origin", allowed)
	}
	denied := DecideEgress(live, "https://evil.example.test/redirect", scope, lease, now)
	if denied.Allowed || denied.Reason != "host_not_allowed" {
		t.Fatalf("open redirect egress = %#v, want host_not_allowed", denied)
	}
}

func TestProviderFailureRetryClassificationDoesNotAdvanceProgress(t *testing.T) {
	for _, kind := range []ProviderFailureKind{
		ProviderFailureTimeout,
		ProviderFailureDNS,
		ProviderFailureTLS,
		ProviderFailureHTTP5xx,
		ProviderFailureRetryAfter,
		ProviderFailureCancellation,
		ProviderFailureTruncatedResponse,
		ProviderFailureInvalidCompression,
		ProviderFailureResponseSizeLimit,
		ProviderFailurePartialPageResponse,
	} {
		classification := ClassifyProviderFailure(kind, time.Hour)
		if classification.AdvancesProgress {
			t.Fatalf("%s advanced progress", kind)
		}
		if classification.RetryAfter != 15*time.Minute {
			t.Fatalf("%s retry_after = %s, want 15m", kind, classification.RetryAfter)
		}
		if strings.Contains(classification.DiagnosticCode, "secret-sentinel") {
			t.Fatalf("%s leaked provider body in diagnostic code", kind)
		}
	}
}
