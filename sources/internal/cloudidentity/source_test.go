package cloudidentitysource

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func TestOversizedEvidencePreservesIncompletePrincipal(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	principal := ci.Principal{ID: "arn:aws:iam::111111111111:role/example", Provider: ci.AWS, Kind: "aws_iam_role", Account: "111111111111"}
	cohort := ci.Evidence{Schema: ci.SchemaVersion, Principal: principal, Scope: "example", ConsumerInventoryComplete: true, CollectedAt: now, Declared: ci.PolicyState{Complete: true}, Observed: ci.PolicyState{Complete: true}, Consumers: []ci.Workload{{ID: "workload", Configuration: map[string]string{"oversized": strings.Repeat("x", maxEvidenceBytes)}}}}
	events, err := CollectionEvents("example", ci.Collection{Scope: "example", Evidence: []ci.Evidence{cohort}, CollectedAt: now, InventoryComplete: true})
	if err != nil {
		t.Fatal(err)
	}
	var evidence ci.Evidence
	if err := json.Unmarshal(events[0].Payload, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Principal != principal || evidence.ConsumerInventoryComplete || evidence.Observed.Complete || evidence.Declared.Complete || len(events[0].Payload) > maxEvidenceBytes {
		t.Fatalf("oversized evidence did not remain bounded and incomplete: %#v", evidence)
	}
	if len(evidence.Gaps) != 1 || evidence.Gaps[0].Code != "principal_evidence_budget_exceeded" {
		t.Fatalf("missing attributable budget gap: %#v", evidence.Gaps)
	}
	if assessment := ci.Assess(evidence, now, 48*time.Hour); assessment.Status == ci.Clear || assessment.Status == ci.Supported {
		t.Fatalf("oversized evidence produced a security conclusion: %#v", assessment)
	}
	var coverage CollectionCoverage
	if err := json.Unmarshal(events[1].Payload, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.GapCount != 1 || coverage.Gaps[0].Scope != principal.ID {
		t.Fatalf("budget failure missing from coverage: %#v", coverage)
	}
}

func TestCoverageIncludesScopedProviderAndInvestigationFailures(t *testing.T) {
	providerGap := ci.Gap{Code: "provider_denied", Scope: "principal", Message: "IAM observation denied"}
	sourceGap := ci.Gap{Code: "source_incomplete", Scope: "consumer", Message: "Dynamic cloud call cannot be bounded"}
	collection := ci.Collection{Scope: "example", CollectedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), InventoryComplete: true, Evidence: []ci.Evidence{{Schema: ci.SchemaVersion, Scope: "example", Principal: ci.Principal{ID: "principal", Provider: ci.GCP}, Observed: ci.PolicyState{Gaps: []ci.Gap{providerGap}}, Gaps: []ci.Gap{providerGap}, Investigations: []ci.Investigation{{Validation: ci.Validation{Gaps: []ci.Gap{sourceGap}}}}}}}
	events, err := CollectionEvents("example", collection)
	if err != nil {
		t.Fatal(err)
	}
	var coverage CollectionCoverage
	if err := json.Unmarshal(events[len(events)-1].Payload, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.GapCount != 2 {
		t.Fatalf("coverage lost or duplicated scoped failures: %#v", coverage)
	}
	found := map[string]string{}
	for _, gap := range coverage.Gaps {
		found[gap.Code] = gap.Scope
	}
	if found[providerGap.Code] != "principal" || found[sourceGap.Code] != "consumer" {
		t.Fatalf("coverage lost failure ownership: %#v", found)
	}
}
