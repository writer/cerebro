package compliance

import (
	"testing"
	"time"
)

func TestControlEvidenceRequirementIndexLooksUpRequirements(t *testing.T) {
	index := BuildControlEvidenceRequirementIndex(ControlEvidenceRequirementResolution{
		Version: "2026-07-04",
		Requirements: []ResolvedControlEvidenceRequirement{
			testResolvedEvidenceRequirement("CC6.1", "identity-access", "okta", "identity_user", []string{"user_id"}),
			testResolvedEvidenceRequirement("CC6.1", "governance-risk", "risk_register", "risk_record", []string{"risk_id"}),
			testResolvedEvidenceRequirement("CC7.1", "logging", "aws", "cloudtrail_trail", []string{"trail_arn"}),
		},
	})
	if index.Version() != "2026-07-04" {
		t.Fatalf("Version() = %q, want 2026-07-04", index.Version())
	}
	controlRequirements := index.RequirementsForControl(ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"})
	if len(controlRequirements) != 2 {
		t.Fatalf("RequirementsForControl() = %d, want 2", len(controlRequirements))
	}
	sourceRequirements := index.RequirementsForSource("OKTA", "IDENTITY_USER")
	if len(sourceRequirements) != 1 || sourceRequirements[0].ProfileID != "identity-access" {
		t.Fatalf("RequirementsForSource() = %#v, want identity-access requirement", sourceRequirements)
	}
	profileRequirements := index.RequirementsForProfile("logging")
	if len(profileRequirements) != 1 || profileRequirements[0].ControlID != "CC7.1" {
		t.Fatalf("RequirementsForProfile() = %#v, want CC7.1 logging requirement", profileRequirements)
	}
	keys := index.RequirementKeysForControl(ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"})
	if len(keys) != 2 || keys[0] != "SOC 2:CC6.1/governance-risk/risk_register/risk_record" || keys[1] != "SOC 2:CC6.1/identity-access/okta/identity_user" {
		t.Fatalf("RequirementKeysForControl() = %#v", keys)
	}
	controlRequirements[0].SourceRequirement.RequiredFields[0] = "mutated"
	again := index.RequirementsForControl(ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"})
	if again[0].SourceRequirement.RequiredFields[0] == "mutated" {
		t.Fatal("RequirementsForControl() returned mutable internal state")
	}
}

func TestAssessControlEvidenceRequirementsReportsOperatingStates(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	index := BuildControlEvidenceRequirementIndex(ControlEvidenceRequirementResolution{
		Version: "2026-07-04",
		Requirements: []ResolvedControlEvidenceRequirement{
			testResolvedEvidenceRequirement("CC6.1", "identity-access", "okta", "identity_user", []string{"user_id", "status"}),
			testResolvedEvidenceRequirement("CC6.1", "repository-access", "github", "repository_access", []string{"repository_id", "permission"}),
			testResolvedEvidenceRequirement("CC6.1", "governance-risk", "risk_register", "risk_record", []string{"risk_id"}),
			testResolvedEvidenceRequirement("CC6.1", "policy-document", "grc_policy_lifecycle", "policy_document", []string{"document_id"}),
		},
	})
	assessments := AssessControlEvidenceRequirements(ControlEvidenceRequirementAssessmentInput{
		Index:   index,
		Control: ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		Now:     now,
		Evidence: []ControlEvidenceRequirementSignal{
			{
				ID:          "okta-evidence",
				SourceID:    "okta",
				EntityType:  "identity_user",
				Fields:      []string{"user_id", "status"},
				ObservedAt:  now.Add(-time.Hour),
				ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			},
			{
				ID:          "github-evidence",
				SourceID:    "github",
				EntityType:  "repository_access",
				Fields:      []string{"repository_id"},
				ObservedAt:  now.Add(-time.Hour),
				ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			},
			{
				ID:          "risk-evidence",
				SourceID:    "risk_register",
				EntityType:  "risk_record",
				FieldValues: map[string]string{"risk_id": "risk-1"},
				ObservedAt:  now.Add(-48 * time.Hour),
				ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
			},
		},
	})
	byProfile := evidenceRequirementAssessmentsByProfile(assessments)
	if got := byProfile["identity-access"].Status; got != ControlEvidenceRequirementSatisfied {
		t.Fatalf("identity status = %q, want satisfied", got)
	}
	if got := byProfile["repository-access"].Status; got != ControlEvidenceRequirementMissingField {
		t.Fatalf("repository status = %q, want missing_fields", got)
	}
	if got := byProfile["repository-access"].MissingFields; len(got) != 1 || got[0] != "permission" {
		t.Fatalf("repository missing fields = %#v, want permission", got)
	}
	if got := byProfile["governance-risk"].Status; got != ControlEvidenceRequirementStale {
		t.Fatalf("governance status = %q, want stale", got)
	}
	if got := byProfile["governance-risk"].StaleEvidenceIDs; len(got) != 1 || got[0] != "risk-evidence" {
		t.Fatalf("governance stale evidence = %#v, want risk-evidence", got)
	}
	if got := byProfile["policy-document"].Status; got != ControlEvidenceRequirementMissing {
		t.Fatalf("policy document status = %q, want missing", got)
	}
}

func TestAssessControlEvidenceRequirementsMarksManualReview(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	requirement := testResolvedEvidenceRequirement("CC6.1", "owner-review", "control_owner_review", "control_evidence_packet", []string{"reviewer"})
	requirement.SourceRequirement.AssessmentMethods = []string{"examine", "interview"}
	index := BuildControlEvidenceRequirementIndex(ControlEvidenceRequirementResolution{
		Version:      "2026-07-04",
		Requirements: []ResolvedControlEvidenceRequirement{requirement},
	})
	assessments := AssessControlEvidenceRequirements(ControlEvidenceRequirementAssessmentInput{
		Index:   index,
		Control: ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		Now:     now,
		Evidence: []ControlEvidenceRequirementSignal{{
			ID:          "owner-review",
			SourceID:    "control_owner_review",
			EntityType:  "control_evidence_packet",
			Fields:      []string{"reviewer"},
			ObservedAt:  now.Add(-time.Hour),
			ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		}},
	})
	if len(assessments) != 1 {
		t.Fatalf("assessments = %d, want 1", len(assessments))
	}
	if assessments[0].Status != ControlEvidenceRequirementManualReview || !assessments[0].ManualReviewRequired {
		t.Fatalf("assessment = %#v, want manual review", assessments[0])
	}
}

func TestAssessControlEvidenceRequirementsTreatsTimestamplessFreshnessEvidenceAsStale(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	requirement := testResolvedEvidenceRequirement("CC6.1", "identity-access", "okta", "identity_user", []string{"user_id"})
	index := BuildControlEvidenceRequirementIndex(ControlEvidenceRequirementResolution{
		Version:      "2026-07-04",
		Requirements: []ResolvedControlEvidenceRequirement{requirement},
	})
	assessments := AssessControlEvidenceRequirements(ControlEvidenceRequirementAssessmentInput{
		Index:   index,
		Control: ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		Now:     now,
		Evidence: []ControlEvidenceRequirementSignal{{
			ID:          "timestampless",
			SourceID:    "okta",
			EntityType:  "identity_user",
			Fields:      []string{"user_id"},
			ControlRefs: []ControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.1"}},
		}},
	})
	if len(assessments) != 1 {
		t.Fatalf("assessments = %d, want 1", len(assessments))
	}
	if assessments[0].Status != ControlEvidenceRequirementStale {
		t.Fatalf("status = %q, want stale", assessments[0].Status)
	}
	if got := assessments[0].StaleEvidenceIDs; len(got) != 1 || got[0] != "timestampless" {
		t.Fatalf("stale evidence = %#v, want timestampless", got)
	}
}

func TestAssessControlEvidenceRequirementsRequiresScopedControlRefs(t *testing.T) {
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)
	requirement := testResolvedEvidenceRequirement("CC6.1", "identity-access", "okta", "identity_user", []string{"user_id"})
	index := BuildControlEvidenceRequirementIndex(ControlEvidenceRequirementResolution{
		Version:      "2026-07-04",
		Requirements: []ResolvedControlEvidenceRequirement{requirement},
	})
	assessments := AssessControlEvidenceRequirements(ControlEvidenceRequirementAssessmentInput{
		Index:   index,
		Control: ControlRef{FrameworkName: "SOC 2", ControlID: "CC6.1"},
		Now:     now,
		Evidence: []ControlEvidenceRequirementSignal{{
			ID:         "unscoped",
			SourceID:   "okta",
			EntityType: "identity_user",
			Fields:     []string{"user_id"},
			ObservedAt: now.Add(-time.Hour),
		}},
	})
	if len(assessments) != 1 {
		t.Fatalf("assessments = %d, want 1", len(assessments))
	}
	if assessments[0].Status != ControlEvidenceRequirementMissing {
		t.Fatalf("status = %q, want missing", assessments[0].Status)
	}
	if got := assessments[0].EvidenceIDs; len(got) != 0 {
		t.Fatalf("evidence ids = %#v, want none", got)
	}
}

func testResolvedEvidenceRequirement(controlID string, profileID string, sourceID string, entityType string, requiredFields []string) ResolvedControlEvidenceRequirement {
	return ResolvedControlEvidenceRequirement{
		FrameworkName:      "SOC 2",
		FrameworkVersion:   "2026",
		FrameworkLifecycle: "current",
		FamilyID:           "CC",
		FamilyName:         "Common Criteria",
		ControlID:          controlID,
		ControlTitle:       "Control " + controlID,
		ProfileID:          profileID,
		ProfileName:        profileID,
		SourceRequirement: ControlEvidenceSourceRequirement{
			SourceID:             sourceID,
			EntityType:           entityType,
			RequiredFields:       requiredFields,
			FreshnessWindow:      "24h",
			AssessmentMethods:    []string{"examine"},
			AuditorGradeEvidence: "Evidence identifies the source object and current control state.",
			ClaimStrength:        "source_backed",
			SufficiencyRule:      "source_period_state_exception",
			CoverageClaim:        "supports_control",
			OverclaimGuard:       "Do not claim broader framework coverage from this requirement alone.",
		},
	}
}

func evidenceRequirementAssessmentsByProfile(assessments []ControlEvidenceRequirementAssessment) map[string]ControlEvidenceRequirementAssessment {
	byProfile := map[string]ControlEvidenceRequirementAssessment{}
	for _, assessment := range assessments {
		byProfile[assessment.ProfileID] = assessment
	}
	return byProfile
}
