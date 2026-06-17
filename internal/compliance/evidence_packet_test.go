package compliance

import (
	"testing"
	"time"
)

func TestBuildControlEvidencePacketIncludesAuditorEvidenceDetails(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	packet := BuildControlEvidencePacket(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Findings: []ControlFindingSignal{{
			ID:              "finding-1",
			RuleID:          "identity-mfa-required",
			Title:           "Privileged user without MFA",
			Status:          "open",
			Severity:        "high",
			FirstObservedAt: now.Add(-24 * time.Hour),
			LastObservedAt:  now.Add(-1 * time.Hour),
		}},
		Evidence: []ControlEvidenceSignal{{
			ID:           "evidence-1",
			RuleID:       "identity-mfa-required",
			EvidenceType: "identity_configuration",
			Status:       "passing",
			Source:       "identity-provider",
			ObservedAt:   now.Add(-2 * time.Hour),
		}},
	})

	if packet.Version != ControlEvidencePacketVersion {
		t.Fatalf("Version = %q, want %q", packet.Version, ControlEvidencePacketVersion)
	}
	if !packet.GeneratedAt.Equal(now) {
		t.Fatalf("GeneratedAt = %s, want %s", packet.GeneratedAt, now)
	}
	if packet.SelectionID != "custom-iam" || packet.Summary.Total != 1 || packet.Summary.ByStatus[ControlPostureFailing] != 1 {
		t.Fatalf("packet summary = %#v, want one failing custom-iam control", packet.Summary)
	}
	if len(packet.Controls) != 1 {
		t.Fatalf("len(Controls) = %d, want 1", len(packet.Controls))
	}
	control := packet.Controls[0]
	if control.Status != ControlPostureFailing {
		t.Fatalf("Status = %q, want failing", control.Status)
	}
	if len(control.Findings) != 1 || control.Findings[0].Title != "Privileged user without MFA" || control.Findings[0].Severity != "high" {
		t.Fatalf("Findings = %#v, want detailed finding", control.Findings)
	}
	if len(control.Evidence.Items) != 1 || control.Evidence.Items[0].Source != "identity-provider" {
		t.Fatalf("Evidence.Items = %#v, want identity-provider evidence item", control.Evidence.Items)
	}
	if control.Evidence.Items[0].Quality != ControlEvidenceQualityStrong {
		t.Fatalf("Evidence item quality = %q, want strong", control.Evidence.Items[0].Quality)
	}
	if len(control.Evidence.Expectations) != 1 {
		t.Fatalf("Evidence.Expectations = %#v, want one expectation", control.Evidence.Expectations)
	}
	expectation := control.Evidence.Expectations[0]
	if expectation.ID != "privileged-mfa-state" || expectation.Status != ControlEvidenceExpectationSatisfied || expectation.Quality != ControlEvidenceQualityStrong {
		t.Fatalf("expectation = %#v, want satisfied strong privileged-mfa-state", expectation)
	}
	if len(expectation.EvidenceIDs) != 1 || expectation.EvidenceIDs[0] != "evidence-1" {
		t.Fatalf("Expectation EvidenceIDs = %#v, want evidence-1", expectation.EvidenceIDs)
	}
	if control.Readiness.Score != 40 || control.Readiness.Rating != ControlEvidenceQualityPartial {
		t.Fatalf("Readiness = %#v, want partial score 40 because open finding blocks reliance", control.Readiness)
	}
}

func TestBuildControlEvidencePacketShowsMissingAndStaleExpectations(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	missing := BuildControlEvidencePacket(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
	})
	if got := missing.Controls[0].Status; got != ControlPostureMissingEvidence {
		t.Fatalf("missing Status = %q, want missing_evidence", got)
	}
	missingExpectation := missing.Controls[0].Evidence.Expectations[0]
	if missingExpectation.Status != ControlEvidenceExpectationMissing || missingExpectation.Quality != ControlEvidenceQualityMissing {
		t.Fatalf("missing expectation = %#v, want missing", missingExpectation)
	}

	stale := BuildControlEvidencePacket(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Evidence: []ControlEvidenceSignal{{
			ID:           "evidence-stale",
			RuleID:       "identity-mfa-required",
			EvidenceType: "identity_configuration",
			ObservedAt:   now.Add(-45 * 24 * time.Hour),
		}},
	})
	if got := stale.Controls[0].Status; got != ControlPostureStaleEvidence {
		t.Fatalf("stale Status = %q, want stale_evidence", got)
	}
	staleExpectation := stale.Controls[0].Evidence.Expectations[0]
	if staleExpectation.Status != ControlEvidenceExpectationStale || staleExpectation.Quality != ControlEvidenceQualityStale {
		t.Fatalf("stale expectation = %#v, want stale", staleExpectation)
	}
	if len(staleExpectation.StaleEvidenceIDs) != 1 || staleExpectation.StaleEvidenceIDs[0] != "evidence-stale" {
		t.Fatalf("StaleEvidenceIDs = %#v, want evidence-stale", staleExpectation.StaleEvidenceIDs)
	}
}

func TestBuildControlEvidencePacketMarksOptionalExpectations(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	index := testOptionalEvidencePacketIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		Frameworks: []FrameworkSelection{{
			ID:       "custom",
			Controls: []string{"IAM-2"},
		}},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	coverage := ResolveRuleCoverage(resolution, nil)

	packet := BuildControlEvidencePacket(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
	})

	if got := packet.Controls[0].Status; got != ControlPosturePassing {
		t.Fatalf("Status = %q, want passing: %#v", got, packet.Controls[0])
	}
	expectation := packet.Controls[0].Evidence.Expectations[0]
	if expectation.ID != "quarterly-access-review" || expectation.Status != ControlEvidenceExpectationOptional || expectation.Quality != ControlEvidenceQualityOptional || expectation.Required {
		t.Fatalf("expectation = %#v, want optional quarterly-access-review", expectation)
	}
}

func testOptionalEvidencePacketIndex(t *testing.T) *CatalogIndex {
	t.Helper()
	optional := false
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: custom
    name: Custom Framework
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-2
            title: Access reviews are retained
            evidence_expectations:
              - id: quarterly-access-review
                type: access_review
                required: false
`)
	if got := catalog.Frameworks[0].Families[0].Controls[0].EvidenceExpectations[0].Required; got == nil || *got != optional {
		t.Fatalf("optional fixture required = %v, want false", got)
	}
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	return index
}
