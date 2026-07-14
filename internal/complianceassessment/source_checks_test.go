package complianceassessment

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

func TestBuildSourceCheckSnapshotPreservesDistinctStatesAndActions(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*SourceCheckInput)
		want   SourceState
	}{
		{name: "supported", want: SourceSupported},
		{name: "partial", mutate: func(input *SourceCheckInput) { input.Support = SourceSupportPartial }, want: SourcePartial},
		{name: "stale health", mutate: func(input *SourceCheckInput) { input.Health = SourceHealthStale }, want: SourceStale},
		{name: "freshness expired", mutate: func(input *SourceCheckInput) { input.FreshUntil = now.Add(-time.Minute) }, want: SourceStale},
		{name: "failed", mutate: func(input *SourceCheckInput) { input.Health = SourceHealthFailed }, want: SourceFailed},
		{name: "unconfigured", mutate: func(input *SourceCheckInput) {
			input.Support = SourceSupportUnconfigured
			input.Health = SourceHealthUnknown
			input.RuntimeID = ""
			input.Certification = sourcecoverage.CertificationUnknown
			input.CertificationReceiptID = ""
		}, want: SourceUnconfigured},
		{name: "unsupported", mutate: func(input *SourceCheckInput) {
			input.Support = SourceSupportUnsupported
			input.Health = SourceHealthUnknown
			input.RuntimeID = ""
			input.Certification = sourcecoverage.CertificationUnknown
			input.CertificationReceiptID = ""
		}, want: SourceUnsupported},
		{name: "unknown certification", mutate: func(input *SourceCheckInput) {
			input.Certification = sourcecoverage.CertificationUnknown
			input.CertificationReceiptID = ""
		}, want: SourceUnknown},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := validSourceCheckInput(now, "source-a", "objective-a")
			if test.mutate != nil {
				test.mutate(&input)
			}
			snapshot, err := BuildSourceCheckSnapshot(input)
			if err != nil {
				t.Fatalf("BuildSourceCheckSnapshot() error = %v", err)
			}
			if snapshot.State != test.want || snapshot.SnapshotHash == "" || snapshot.ID == "" || len(snapshot.NextActions) == 0 {
				t.Fatalf("snapshot = %+v, want state %q with hash and action", snapshot, test.want)
			}
		})
	}
}

func TestObjectiveAssessmentRejectsAlteredSourceSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	snapshot, err := BuildSourceCheckSnapshot(validSourceCheckInput(now, "source-a", "objective-a"))
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot() error = %v", err)
	}
	snapshot.ReasonCodes = []ReasonCode{ReasonSatisfied}
	_, err = AssessObjectiveSourceChecks(ObjectiveSourceRequirement{ObjectiveID: "objective-a", Sources: []SourceCheckRequirement{{
		SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationLiveValidated,
	}}}, []SourceCheckSnapshot{snapshot})
	if !errors.Is(err, ErrInvalidSourceCheck) {
		t.Fatalf("AssessObjectiveSourceChecks(altered) error = %v, want ErrInvalidSourceCheck", err)
	}
}

func TestSourceCheckSnapshotHashIsCanonicalAndDoesNotMutateInput(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 123456789, time.UTC)
	input := validSourceCheckInput(now, "source-a", "objective-b")
	input.AffectedObjectiveIDs = []string{"objective-b", "objective-a"}
	input.UnsupportedFields = []string{"legacy_field", "admin_flag"}
	input.EvidenceIDs = []string{"evidence-b", "evidence-a"}
	first, err := BuildSourceCheckSnapshot(input)
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot(first) error = %v", err)
	}
	input.AffectedObjectiveIDs[0], input.AffectedObjectiveIDs[1] = input.AffectedObjectiveIDs[1], input.AffectedObjectiveIDs[0]
	input.UnsupportedFields[0], input.UnsupportedFields[1] = input.UnsupportedFields[1], input.UnsupportedFields[0]
	input.EvidenceIDs[0], input.EvidenceIDs[1] = input.EvidenceIDs[1], input.EvidenceIDs[0]
	second, err := BuildSourceCheckSnapshot(input)
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot(second) error = %v", err)
	}
	if first.ID != second.ID || first.SnapshotHash != second.SnapshotHash || !reflect.DeepEqual(first, second) {
		t.Fatalf("canonical source snapshots differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.CheckedAt.Nanosecond() != 123000000 {
		t.Fatalf("CheckedAt = %s, want millisecond precision", first.CheckedAt)
	}
}

func TestLowerCertificationCannotPassButEvidenceRemainsVisible(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	input := validSourceCheckInput(now, "source-a", "objective-a")
	input.Certification = sourcecoverage.CertificationCatalogDeclared
	input.CertificationReceiptID = "catalog-receipt-a"
	snapshot, err := BuildSourceCheckSnapshot(input)
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot() error = %v", err)
	}
	requirement := ObjectiveSourceRequirement{ObjectiveID: "objective-a", Sources: []SourceCheckRequirement{{
		SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated,
	}}}
	result, assessment, err := EvaluateObjectiveWithSourceChecks(validSourceEvaluateInput(now, "objective-a", "source-a"), requirement, []SourceCheckSnapshot{snapshot})
	if err != nil {
		t.Fatalf("EvaluateObjectiveWithSourceChecks() error = %v", err)
	}
	if assessment.State != SourceUnverified || len(assessment.CertificationGaps) != 1 {
		t.Fatalf("source assessment = %+v, want unverified gap", assessment)
	}
	if result.AutomatedOutcome == OutcomeSatisfied || result.EvidenceState != EvidenceUntrusted {
		t.Fatalf("objective result = %+v, lower trust must not pass", result)
	}
	if !containsString(assessment.EvidenceIDs, "source-evidence-a") || !containsString(assessment.CollectionReceipts, "collection-receipt-a") {
		t.Fatalf("insufficient-trust evidence was hidden: %+v", assessment)
	}
}

func TestFailedSourceOnlyLimitsAffectedObjective(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	failedInput := validSourceCheckInput(now, "source-a", "objective-a")
	failedInput.Health = SourceHealthFailed
	failed, err := BuildSourceCheckSnapshot(failedInput)
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot(failed) error = %v", err)
	}
	healthy, err := BuildSourceCheckSnapshot(validSourceCheckInput(now, "source-b", "objective-b"))
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot(healthy) error = %v", err)
	}
	snapshots := []SourceCheckSnapshot{failed, healthy}
	failedResult, failedAssessment, err := EvaluateObjectiveWithSourceChecks(validSourceEvaluateInput(now, "objective-a", "source-a"), ObjectiveSourceRequirement{
		ObjectiveID: "objective-a", Sources: []SourceCheckRequirement{{SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated}},
	}, snapshots)
	if err != nil {
		t.Fatalf("EvaluateObjectiveWithSourceChecks(failed) error = %v", err)
	}
	healthyResult, healthyAssessment, err := EvaluateObjectiveWithSourceChecks(validSourceEvaluateInput(now, "objective-b", "source-b"), ObjectiveSourceRequirement{
		ObjectiveID: "objective-b", Sources: []SourceCheckRequirement{{SourceID: "source-b", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated}},
	}, snapshots)
	if err != nil {
		t.Fatalf("EvaluateObjectiveWithSourceChecks(healthy) error = %v", err)
	}
	if failedAssessment.State != SourceFailed || failedResult.AutomatedOutcome != OutcomeIndeterminate {
		t.Fatalf("affected result = %+v / %+v", failedAssessment, failedResult)
	}
	if healthyAssessment.State != SourceSupported || healthyResult.AutomatedOutcome != OutcomeSatisfied {
		t.Fatalf("unaffected result = %+v / %+v, want supported satisfied", healthyAssessment, healthyResult)
	}
}

func TestUnsupportedFieldsOnlyLimitObjectivesThatRequireThem(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	input := validSourceCheckInput(now, "source-a", "objective-a")
	input.AffectedObjectiveIDs = []string{"objective-a", "objective-b"}
	input.UnsupportedFields = []string{"admin_flag"}
	snapshot, err := BuildSourceCheckSnapshot(input)
	if err != nil {
		t.Fatalf("BuildSourceCheckSnapshot() error = %v", err)
	}
	limited, err := AssessObjectiveSourceChecks(ObjectiveSourceRequirement{ObjectiveID: "objective-a", Sources: []SourceCheckRequirement{{
		SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated, RequiredFields: []string{"admin_flag"},
	}}}, []SourceCheckSnapshot{snapshot})
	if err != nil {
		t.Fatalf("AssessObjectiveSourceChecks(limited) error = %v", err)
	}
	unaffected, err := AssessObjectiveSourceChecks(ObjectiveSourceRequirement{ObjectiveID: "objective-b", Sources: []SourceCheckRequirement{{
		SourceID: "source-a", DimensionID: "dimension-a", MinimumCertification: sourcecoverage.CertificationFixtureValidated, RequiredFields: []string{"id"},
	}}}, []SourceCheckSnapshot{snapshot})
	if err != nil {
		t.Fatalf("AssessObjectiveSourceChecks(unaffected) error = %v", err)
	}
	if limited.State != SourcePartial || len(limited.UnsupportedFields) != 1 {
		t.Fatalf("limited assessment = %+v", limited)
	}
	if unaffected.State != SourceSupported || len(unaffected.UnsupportedFields) != 0 {
		t.Fatalf("unaffected assessment = %+v", unaffected)
	}
}

func validSourceCheckInput(now time.Time, sourceID, objectiveID string) SourceCheckInput {
	return SourceCheckInput{
		TenantID: "tenant-a", SourceID: sourceID, RuntimeID: sourceID + "-runtime", DimensionID: "dimension-a",
		Support: SourceSupportSupported, Health: SourceHealthHealthy,
		Certification: sourcecoverage.CertificationFixtureValidated, CertificationReceiptID: "fixture-receipt-a",
		Watermark: "watermark-a", CollectionReceiptID: "collection-receipt-a", CollectionReceiptHash: "sha256:" + strings.Repeat("a", 64),
		LastSuccessfulAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), AffectedObjectiveIDs: []string{objectiveID},
		EvidenceIDs: []string{"source-evidence-a"}, CheckedAt: now,
	}
}

func validSourceEvaluateInput(now time.Time, objectiveID, sourceID string) EvaluateInput {
	control := compliance.ControlRef{FrameworkName: "Example Framework", ControlID: "CC-1"}
	return EvaluateInput{
		ResultID: "result-" + objectiveID, ObjectiveID: objectiveID,
		Control: control, ScopeState: ScopeInScope,
		RequirementAssessments: []compliance.ControlEvidenceRequirementAssessment{{
			RequirementKey: "requirement-1", ControlRef: control, SourceID: sourceID, EntityType: "asset",
			Status: compliance.ControlEvidenceRequirementSatisfied, EvidenceIDs: []string{"source-evidence-a"},
		}},
		CoverageState: CoverageComplete, EvaluatorRevision: "evaluator-v1", Now: now,
	}
}
