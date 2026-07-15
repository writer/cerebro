package sourcecertification

import (
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEvaluateConcreteCertificationStates(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		input       Input
		want        Tier
		invalidated bool
		expired     bool
	}{
		{name: "catalog only", input: Input{SourceID: "aws", Now: now}, want: TierCataloged},
		{name: "spec verified", input: certifiedInput("github", now, false), want: TierSpecVerified},
		{name: "contract tested", input: certifiedInput("okta", now, true), want: TierContractTested},
		{name: "production observed", input: func() Input {
			input := certifiedInput("jira", now, true)
			input.Runtime = RuntimeObservation{Configured: true, Healthy: true, Fresh: true, LastObservedAt: now.Add(-time.Hour)}
			return input
		}(), want: TierProductionObserved},
		{name: "outcome validated", input: func() Input {
			input := certifiedInput("trivy", now, true)
			input.Runtime = RuntimeObservation{Configured: true, Healthy: true, Fresh: true, LastObservedAt: now.Add(-time.Hour)}
			input.Outcome = OutcomeObservation{Accepted: true, Receipt: "outcomes/accepted/1", LastObservedAt: now}
			return input
		}(), want: TierOutcomeValidated},
		{name: "expired", input: func() Input {
			input := certifiedInput("github", now, false)
			input.Certification.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
			return input
		}(), want: TierCataloged, expired: true},
		{name: "invalidated", input: func() Input {
			input := certifiedInput("github", now, false)
			input.ProviderAPI.HasDisproof = true
			return input
		}(), want: TierCataloged, invalidated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Evaluate(test.input)
			if got.EffectiveTier != test.want || got.Invalidated != test.invalidated || got.Expired != test.expired {
				t.Fatalf("Evaluate() = %+v, want tier=%s invalidated=%t expired=%t", got, test.want, test.invalidated, test.expired)
			}
		})
	}
}

func TestEvaluateDoesNotTreatRuntimeVolumeAsOutcomeProof(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	input := certifiedInput("github", now, true)
	input.Runtime = RuntimeObservation{Configured: true, Healthy: true, Fresh: true, LastObservedAt: now}
	result := Evaluate(input)
	if result.EffectiveTier != TierProductionObserved {
		t.Fatalf("EffectiveTier = %q, want production_observed", result.EffectiveTier)
	}
	if result.EffectiveTier == TierOutcomeValidated {
		t.Fatal("runtime observation counted as accepted outcome")
	}
}

func TestEvaluateRequiresDurableOutcomeReceipt(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	input := certifiedInput("github", now, true)
	input.Runtime = RuntimeObservation{Configured: true, Healthy: true, Fresh: true, LastObservedAt: now.Add(-time.Hour)}
	input.Outcome = OutcomeObservation{Accepted: true, LastObservedAt: now}
	if result := Evaluate(input); result.EffectiveTier != TierProductionObserved {
		t.Fatalf("EffectiveTier = %q, want production_observed without durable outcome receipt", result.EffectiveTier)
	}
}

func TestRuntimeObservationsRequireFreshHealthyRuntime(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	observations := RuntimeObservations([]*cerebrov1.SourceRuntime{
		{
			SourceId:     "github",
			Config:       map[string]string{"__cerebro_runtime_status": "healthy"},
			LastSyncedAt: timestamppb.New(now.Add(-DefaultRuntimeFreshness - time.Hour)),
		},
		{
			SourceId:     "github",
			Config:       map[string]string{"__cerebro_runtime_status": "failed"},
			LastSyncedAt: timestamppb.New(now.Add(-time.Minute)),
		},
	}, now)

	observation := observations["github"]
	if !observation.Healthy {
		t.Fatal("Healthy = false, want true when a healthy runtime exists")
	}
	if observation.Fresh {
		t.Fatal("Fresh = true, want false when the only fresh runtime is unhealthy")
	}
	wantObservedAt := now.Add(-DefaultRuntimeFreshness - time.Hour)
	if !observation.LastObservedAt.Equal(wantObservedAt) {
		t.Fatalf("LastObservedAt = %s, want latest healthy observation %s", observation.LastObservedAt, wantObservedAt)
	}
	input := certifiedInput("github", now, true)
	input.Runtime = observation
	if result := Evaluate(input); result.EffectiveTier != TierContractTested {
		t.Fatalf("EffectiveTier = %q, want contract_tested without a fresh healthy runtime", result.EffectiveTier)
	}
}

func TestAvailabilityGatePreservesDiscoveryAndConfiguredRuntime(t *testing.T) {
	result := Result{EffectiveTier: TierCataloged}
	policy := AvailabilityPolicy{MinimumTier: TierContractTested}
	below := ApplyAvailability(result, false, policy)
	if below.State != AvailabilityBelowMinimum || !below.Discoverable || below.MeetsMinimum {
		t.Fatalf("below-minimum availability = %+v", below)
	}
	configured := ApplyAvailability(result, true, policy)
	if configured.State != AvailabilityConfiguredBelowMinimum || !configured.Discoverable {
		t.Fatalf("configured availability = %+v", configured)
	}
	preview := ApplyAvailability(result, false, AvailabilityPolicy{MinimumTier: TierContractTested, IncludePreview: true})
	if preview.State != AvailabilityPreview || !preview.PreviewAllowed || !preview.Discoverable {
		t.Fatalf("preview availability = %+v", preview)
	}
}

func TestParseTierIsClosed(t *testing.T) {
	for _, value := range []string{"cataloged", "spec_verified", "contract_tested", "production_observed", "outcome_validated"} {
		if _, err := ParseTier(value); err != nil {
			t.Fatalf("ParseTier(%q) error = %v", value, err)
		}
	}
	if _, err := ParseTier("trusted"); err == nil {
		t.Fatal("ParseTier(trusted) error = nil, want closed-tier validation error")
	}
}

func certifiedInput(sourceID string, now time.Time, sandbox bool) Input {
	evidence := []sourcecdk.CatalogCertificationEvidence{{Kind: sourcecdk.CertificationEvidenceProviderSpec, Reference: "https://provider.example/spec", Digest: "sha256:" + strings.Repeat("0", 64)}}
	if sandbox {
		evidence = append(evidence, sourcecdk.CatalogCertificationEvidence{Kind: sourcecdk.CertificationEvidenceSandboxContract, Receipt: "contract/receipt", Digest: "sha256:" + strings.Repeat("0", 64)})
	}
	return Input{
		SourceID:      sourceID,
		Certification: &sourcecdk.CatalogCertification{Owner: "source-runtime", ReviewedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(90 * 24 * time.Hour).Format(time.RFC3339), Evidence: evidence},
		ProviderAPI:   connectorcatalog.RuntimeProviderAPIDepth{RuntimeProviderAPIProofDepth: connectorcatalog.RuntimeProviderAPIProofDepth{HasProof: true}},
		Now:           now,
	}
}
