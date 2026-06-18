package compliance

import (
	"testing"
	"time"
)

func TestEvaluateControlPosturePassingWithMappedCustomControlEvidence(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	postures := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Evidence: []ControlEvidenceSignal{{
			ID:           "evidence-1",
			RuleID:       "identity-mfa-required",
			EvidenceType: "identity_configuration",
			Status:       "passing",
			ObservedAt:   now.Add(-2 * time.Hour),
		}},
	})

	if len(postures) != 1 {
		t.Fatalf("len(postures) = %d, want 1", len(postures))
	}
	posture := postures[0]
	if posture.Status != ControlPosturePassing {
		t.Fatalf("Status = %q, want passing: %#v", posture.Status, posture)
	}
	if got := posture.MappedRules; len(got) != 1 || got[0] != "identity-mfa-required" {
		t.Fatalf("MappedRules = %#v, want identity-mfa-required", got)
	}
	if got := posture.Evidence.EvidenceIDs; len(got) != 1 || got[0] != "evidence-1" {
		t.Fatalf("EvidenceIDs = %#v, want evidence-1", got)
	}
	if posture.Evidence.LatestEvidenceAt.IsZero() || posture.Evidence.EvidenceDueAt.IsZero() {
		t.Fatalf("evidence timestamps = latest %s due %s, want both set", posture.Evidence.LatestEvidenceAt, posture.Evidence.EvidenceDueAt)
	}
	if posture.Evidence.FreshnessSLA != "30d" {
		t.Fatalf("FreshnessSLA = %q, want 30d from required expectation", posture.Evidence.FreshnessSLA)
	}
}

func TestEvaluateControlPostureFailingBeatsFreshEvidence(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	postures := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Findings: []ControlFindingSignal{{
			ID:          "finding-1",
			RuleID:      "identity-mfa-required",
			Status:      "open",
			ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		}},
		Evidence: []ControlEvidenceSignal{{
			ID:           "evidence-1",
			RuleID:       "identity-mfa-required",
			EvidenceType: "identity_configuration",
			Status:       "passing",
			ObservedAt:   now.Add(-2 * time.Hour),
		}},
	})

	posture := postures[0]
	if posture.Status != ControlPostureFailing {
		t.Fatalf("Status = %q, want failing: %#v", posture.Status, posture)
	}
	if got := posture.Findings.OpenFindingIDs; len(got) != 1 || got[0] != "finding-1" {
		t.Fatalf("OpenFindingIDs = %#v, want finding-1", got)
	}
}

func TestEvaluateControlPostureMissingAndStaleEvidence(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	missing := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
	})
	if got := missing[0].Status; got != ControlPostureMissingEvidence {
		t.Fatalf("missing Status = %q, want missing_evidence: %#v", got, missing[0])
	}
	if got := missing[0].Evidence.MissingEvidenceIDs; len(got) != 1 || got[0] != "privileged-mfa-state" {
		t.Fatalf("MissingEvidenceIDs = %#v, want privileged-mfa-state", got)
	}

	stale := EvaluateControlPosture(ControlPostureInput{
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
	if got := stale[0].Status; got != ControlPostureStaleEvidence {
		t.Fatalf("stale Status = %q, want stale_evidence: %#v", got, stale[0])
	}
	if got := stale[0].Evidence.StaleEvidenceIDs; len(got) != 1 || got[0] != "evidence-stale" {
		t.Fatalf("StaleEvidenceIDs = %#v, want evidence-stale", got)
	}
}

func TestEvaluateControlPostureExceptionAndNotApplicableOverrides(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	exception := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Findings: []ControlFindingSignal{{
			ID:     "finding-1",
			RuleID: "identity-mfa-required",
			Status: "open",
		}},
		Overrides: []ControlPostureOverride{{
			ID:        "exception-1",
			RuleID:    "identity-mfa-required",
			Status:    ControlPostureException,
			Reason:    "Compensating access control accepted through quarter end.",
			ExpiresAt: now.Add(24 * time.Hour),
		}},
	})
	if got := exception[0].Status; got != ControlPostureException {
		t.Fatalf("exception Status = %q, want exception: %#v", got, exception[0])
	}
	if got := exception[0].Overrides.ExceptionIDs; len(got) != 1 || got[0] != "exception-1" {
		t.Fatalf("ExceptionIDs = %#v, want exception-1", got)
	}

	idlessException := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Findings: []ControlFindingSignal{{
			ID:     "finding-1",
			RuleID: "identity-mfa-required",
			Status: "open",
		}},
		Overrides: []ControlPostureOverride{{
			RuleID:    "identity-mfa-required",
			Status:    ControlPostureException,
			ExpiresAt: now.Add(24 * time.Hour),
		}},
	})
	if got := idlessException[0].Status; got != ControlPostureException {
		t.Fatalf("idless exception Status = %q, want exception: %#v", got, idlessException[0])
	}

	notApplicable := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Findings: []ControlFindingSignal{{
			ID:     "finding-1",
			RuleID: "identity-mfa-required",
			Status: "open",
		}},
		Overrides: []ControlPostureOverride{{
			ID:        "scope-1",
			RuleID:    "identity-mfa-required",
			Status:    ControlPostureNotApplicable,
			Reason:    "Privileged access is not in scope for this review.",
			ExpiresAt: now.Add(24 * time.Hour),
		}},
	})
	if got := notApplicable[0].Status; got != ControlPostureNotApplicable {
		t.Fatalf("not-applicable Status = %q, want not_applicable: %#v", got, notApplicable[0])
	}

	expiredException := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Findings: []ControlFindingSignal{{
			ID:     "finding-1",
			RuleID: "identity-mfa-required",
			Status: "open",
		}},
		Overrides: []ControlPostureOverride{{
			ID:        "exception-1",
			RuleID:    "identity-mfa-required",
			Status:    ControlPostureException,
			ExpiresAt: now.Add(-24 * time.Hour),
		}},
	})
	if got := expiredException[0].Status; got != ControlPostureFailing {
		t.Fatalf("expired exception Status = %q, want failing: %#v", got, expiredException[0])
	}
}

func TestEvaluateControlPostureManualReviewAndSummary(t *testing.T) {
	now := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	resolution, coverage := testPostureResolution(t)

	postures := EvaluateControlPosture(ControlPostureInput{
		Selection:    resolution,
		RuleCoverage: coverage,
		Now:          now,
		Evidence: []ControlEvidenceSignal{{
			ID:           "attestation-1",
			RuleID:       "identity-mfa-required",
			EvidenceType: "identity_configuration",
			ObservedAt:   now.Add(-2 * time.Hour),
			Manual:       true,
		}},
	})
	if got := postures[0].Status; got != ControlPostureManualReview {
		t.Fatalf("Status = %q, want manual_review: %#v", got, postures[0])
	}
	summary := SummarizeControlPosture(resolution.SelectionID, postures)
	if summary.Total != 1 || summary.ByStatus[ControlPostureManualReview] != 1 {
		t.Fatalf("summary = %#v, want one manual_review posture", summary)
	}
}

func testPostureResolution(t *testing.T) (SelectionResolution, RuleCoverage) {
	t.Helper()
	index := testPostureIndex(t)
	resolution, issues := ResolveControlSelection(index, ControlSelection{
		ID: "custom-iam",
		Frameworks: []FrameworkSelection{{
			ID:       "custom",
			Controls: []string{"IAM-1"},
		}},
	})
	if len(issues) != 0 {
		t.Fatalf("ResolveControlSelection() issues = %#v, want none", issues)
	}
	coverage := ResolveRuleCoverage(resolution, []RuleControlMapping{{
		RuleID:      "identity-mfa-required",
		ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
	}})
	return resolution, coverage
}

func testPostureIndex(t *testing.T) *CatalogIndex {
	t.Helper()
	catalog := loadTestCatalog(t, `
version: "2026-06-17"
frameworks:
  - id: soc2
    name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
            title: Logical access is restricted.
  - id: custom
    name: Custom Framework
    families:
      - id: IAM
        name: Identity Controls
        controls:
          - id: IAM-1
            title: Privileged access requires MFA
            owner_domain: identity
            tags: [identity, privileged_access]
            evidence_expectations:
              - id: privileged-mfa-state
                type: identity_configuration
                required: true
                freshness_sla: 30d
            maps_to:
              - framework_id: soc2
                control_id: CC6.1
`)
	index, issues := BuildCatalogIndex(catalog)
	if len(issues) != 0 {
		t.Fatalf("BuildCatalogIndex() issues = %#v, want none", issues)
	}
	return index
}
