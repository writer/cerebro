package complianceassessment

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

func TestCanonicalManifestNormalizesOrderTimeAndDoesNotMutateCaller(t *testing.T) {
	manifest := validManifest()
	originalFirstKind := manifest.Revisions[0].Kind
	firstBytes, err := CanonicalManifestBytes(manifest)
	if err != nil {
		t.Fatalf("CanonicalManifestBytes() error = %v", err)
	}
	shuffled := manifest
	shuffled.Revisions = append([]ManifestRevision(nil), manifest.Revisions...)
	shuffled.Receipts = append([]CollectionReceipt(nil), manifest.Receipts...)
	shuffled.Revisions[0], shuffled.Revisions[1] = shuffled.Revisions[1], shuffled.Revisions[0]
	shuffled.Receipts[0], shuffled.Receipts[1] = shuffled.Receipts[1], shuffled.Receipts[0]
	shuffled.EvaluationRunIDs = []string{"run-b", "run-a", "run-a"}
	secondBytes, err := CanonicalManifestBytes(shuffled)
	if err != nil {
		t.Fatalf("CanonicalManifestBytes(shuffled) error = %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("manifest order changed canonical bytes\nfirst=%s\nsecond=%s", firstBytes, secondBytes)
	}
	if manifest.Revisions[0].Kind != originalFirstKind {
		t.Fatal("NormalizeManifest mutated caller revisions")
	}
	if bytes.Contains(firstBytes, []byte("123456789")) || !bytes.Contains(firstBytes, []byte(".123Z")) {
		t.Fatalf("canonical timestamp was not truncated to milliseconds: %s", firstBytes)
	}
}

func TestUnknownEnumsSurviveDecodeAndFailCommandValidation(t *testing.T) {
	result := validObjectiveResult()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	data = bytes.Replace(data, []byte(`"evidence_state":"sufficient"`), []byte(`"evidence_state":"future_state"`), 1)
	var decoded ObjectiveResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode future enum: %v", err)
	}
	if decoded.EvidenceState != EvidenceState("future_state") {
		t.Fatalf("future enum was not retained: %q", decoded.EvidenceState)
	}
	if err := ValidateObjectiveResult(decoded); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("ValidateObjectiveResult() error = %v, want ErrInvalidResult", err)
	}

	input := validEvaluateInput()
	input.SourceState = SourceState("future_source_state")
	if _, err := EvaluateObjective(input); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("EvaluateObjective() error = %v, want ErrInvalidResult", err)
	}
	input = validEvaluateInput()
	input.RequirementAssessments[0].Status = compliance.ControlEvidenceRequirementAssessmentStatus("future_requirement_state")
	if _, err := EvaluateObjective(input); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("EvaluateObjective(future requirement) error = %v, want ErrInvalidResult", err)
	}
}

func TestCanonicalResultRejectsUnsupportedPass(t *testing.T) {
	result := validObjectiveResult()
	result.EvidenceState = EvidenceMissing
	if _, err := CanonicalResultBytes(result); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("CanonicalResultBytes() error = %v, want ErrInvalidResult", err)
	}
}

func validManifest() InputManifest {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	expected := uint64(2)
	timestamp := time.Date(2026, 7, 11, 12, 0, 0, 123456789, time.FixedZone("offset", -7*60*60))
	return InputManifest{
		ProgramID: "program-00000000000000000000000000000001", ScopeRevisionID: "scope-revision-00000000000000000000000000000001",
		PlanRevisionID: "assessment-plan-revision-00000000000000000000000000000001",
		PeriodStart:    timestamp.Add(-time.Hour), PeriodEnd: timestamp, CollectionCutoff: timestamp,
		RequestedScopeDigest: digestA, ResolvedObjectiveSetDigest: digestB, MappingSetDigest: digestA,
		Revisions: []ManifestRevision{
			{Kind: "profile", ID: "profile-1", RevisionID: "profile-r1", Version: 1, Digest: digestA},
			{Kind: "catalog", ID: "catalog-1", RevisionID: "catalog-r1", Version: 1, Digest: digestB},
		},
		Receipts: []CollectionReceipt{
			{Kind: "findings", RuntimeID: "runtime-1", QueryDigest: digestA, PageIndex: 1, Cursor: "a", RawCount: 1, Deduplicated: 1, Included: 1, ExpectedTotal: &expected, FirstKey: "b", LastKey: "b", Watermark: timestamp, Cutoff: timestamp, Completeness: CollectionComplete, PageDigest: digestB},
			{Kind: "findings", RuntimeID: "runtime-1", QueryDigest: digestA, PageIndex: 0, NextCursor: "a", RawCount: 1, Deduplicated: 1, Included: 1, ExpectedTotal: &expected, FirstKey: "a", LastKey: "a", Watermark: timestamp, Cutoff: timestamp, Completeness: CollectionComplete, PageDigest: digestA},
		},
		EvaluationRunIDs: []string{"run-a", "run-b"},
	}
}

func validObjectiveResult() ObjectiveResult {
	return ObjectiveResult{
		ID:         "assessment-result-00000000000000000000000000000001",
		ControlRef: compliance.ControlRef{FrameworkName: "Example Framework", ControlID: "CC-1"}, ObjectiveID: "objective-1",
		ScopeState: ScopeInScope, AutomatedOutcome: OutcomeSatisfied, DesignState: DesignEffective,
		OperatingEffectivenessState: OperatingEffective, EvidenceState: EvidenceSufficient,
		DispositionState: DispositionNone, Assurance: AssuranceHigh, AuditorState: AuditorNotReviewed,
		ReasonCodes: []ReasonCode{ReasonSatisfied}, NextActions: []NextAction{ActionNone},
		EvaluatorRevision: "evaluator-v1", EvaluatedAt: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
	}
}

func validEvaluateInput() EvaluateInput {
	return EvaluateInput{
		ResultID: "assessment-result-00000000000000000000000000000001", ObjectiveID: "objective-1",
		Control: compliance.ControlRef{FrameworkName: "Example Framework", ControlID: "CC-1"}, ScopeState: ScopeInScope,
		RequirementAssessments: []compliance.ControlEvidenceRequirementAssessment{{Status: compliance.ControlEvidenceRequirementSatisfied, EvidenceIDs: []string{"evidence-1"}}},
		CoverageState:          CoverageComplete, SourceState: SourceSupported, EvaluatorRevision: "evaluator-v1",
		Now: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
	}
}
