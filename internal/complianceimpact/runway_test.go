package complianceimpact

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
)

func TestCalculateSourceRunway(t *testing.T) {
	asOf := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	base := sourceRunwayInput(asOf)
	t.Run("healthy", func(t *testing.T) {
		result, err := CalculateSourceRunway(base)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != RunwayHealthy || result.Digest == "" {
			t.Fatalf("result = %#v", result)
		}
	})
	t.Run("warning before credential expiry", func(t *testing.T) {
		input := base
		input.CredentialExpiresAt = asOf.Add(90 * time.Minute)
		result, err := CalculateSourceRunway(input)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != RunwayWarning || !hasRunwayReason(result.Reasons, RunwaySourceAuthExpiring) {
			t.Fatalf("result = %#v", result)
		}
	})
	t.Run("incomplete coverage is blind", func(t *testing.T) {
		input := base
		input.CoverageComplete = false
		result, err := CalculateSourceRunway(input)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != RunwayBlind || !hasRunwayReason(result.Reasons, RunwayCoverageIncomplete) {
			t.Fatalf("result = %#v", result)
		}
	})
	t.Run("missing checkpoint is unknown", func(t *testing.T) {
		input := base
		input.LastSuccessfulAt = time.Time{}
		result, err := CalculateSourceRunway(input)
		if err != nil {
			t.Fatal(err)
		}
		if result.State != RunwayUnknown || !hasRunwayReason(result.Reasons, RunwayCheckpointMissing) {
			t.Fatalf("result = %#v", result)
		}
	})
	t.Run("future checkpoint is rejected", func(t *testing.T) {
		input := base
		input.LastSuccessfulAt = asOf.Add(time.Minute)
		if _, err := CalculateSourceRunway(input); err == nil {
			t.Fatal("expected future checkpoint to be rejected")
		}
	})
}

func sourceRunwayInput(asOf time.Time) SourceRunwayInput {
	objective := mustImpactRevision("compliance", complianceintegration.FactObjective, "objective", "objective-rev", 1, "sha256:"+strings.Repeat("a", 64), asOf)
	proof := mustImpactRevision("source", complianceintegration.FactProjection, "source-proof", "proof-rev", 1, "sha256:"+strings.Repeat("b", 64), asOf)
	return SourceRunwayInput{TenantID: "tenant", Objective: objective, SourceProof: proof, AsOf: asOf, LastSuccessfulAt: asOf.Add(-time.Hour), ExpectedCadence: time.Hour, MaximumStaleness: 8 * time.Hour, SourceHealthy: true, CoverageComplete: true}
}

func hasRunwayReason(values []RunwayReason, wanted RunwayReason) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
