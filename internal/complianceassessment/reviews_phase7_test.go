package complianceassessment

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReviewRevisionsPreserveAutomatedHashAndRejectStaleWriter(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	automatedHash := "sha256:" + strings.Repeat("a", 64)
	evidenceIDs := []string{"evidence-b", "evidence-a"}
	review, first, err := NewReview("tenant-a", "run-a", "result-a", automatedHash, ReviewRevisionInput{
		Decision: ReviewAccept, EffectiveDisposition: DispositionNone, EffectiveAuditor: AuditorAccepted,
		Rationale: "Evidence supports the automated result.", ActorID: "reviewer-a", ActorRole: "control_reviewer",
		EvidenceIDs: evidenceIDs, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewReview() error = %v", err)
	}
	evidenceIDs[0] = "mutated"
	next, second, err := ReviseReview(review, 1, ReviewRevisionInput{
		Decision: ReviewRequestChanges, EffectiveDisposition: DispositionNone, EffectiveAuditor: AuditorChangesRequested,
		Rationale: "Collection scope needs clarification.", ActorID: "reviewer-b", ActorRole: "audit_reviewer",
		EvidenceIDs: []string{"evidence-c"}, CreatedAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("ReviseReview() error = %v", err)
	}
	if review.Version != 1 || review.CurrentRevision != 1 || next.Version != 2 || next.CurrentRevision != 2 {
		t.Fatalf("review versions = original %+v next %+v", review, next)
	}
	if first.AutomatedResultHash != automatedHash || second.AutomatedResultHash != automatedHash || second.PredecessorID != first.ID {
		t.Fatalf("review lineage changed automated basis: first %+v second %+v", first, second)
	}
	if len(first.EvidenceIDs) != 2 || first.EvidenceIDs[0] != "evidence-a" {
		t.Fatalf("first evidence IDs were not normalized and copied: %#v", first.EvidenceIDs)
	}
	if _, _, err := ReviseReview(next, 1, ReviewRevisionInput{}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("ReviseReview(stale) error = %v, want ErrVersionConflict", err)
	}
}

func TestReviewOverrideRequiresExplicitDisposition(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	_, _, err := NewReview("tenant-a", "run-a", "result-a", "sha256:"+strings.Repeat("b", 64), ReviewRevisionInput{
		Decision: ReviewOverride, EffectiveDisposition: DispositionNone, EffectiveAuditor: AuditorAccepted,
		Rationale: "Approved manual disposition.", ActorID: "reviewer-a", ActorRole: "control_reviewer", CreatedAt: now,
	})
	if !errors.Is(err, ErrInvalidReview) {
		t.Fatalf("NewReview(override) error = %v, want ErrInvalidReview", err)
	}
}

func TestWorkFingerprintOccurrencesAndReopenTriggers(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	basis := WorkFingerprintInput{
		TenantID: " tenant-a ", ProgramID: "program-a", ScopeRevisionID: "scope-r1", ControlID: "CC-1",
		ObjectiveID: "objective-a", Kind: WorkRefreshEvidence, SubjectID: "subject-a", Reason: ReasonEvidenceStale, SourceID: "source-a",
	}
	firstFingerprint, err := ComputeWorkFingerprint(basis)
	if err != nil {
		t.Fatalf("ComputeWorkFingerprint() error = %v", err)
	}
	basis.TenantID = "tenant-a"
	secondFingerprint, err := ComputeWorkFingerprint(basis)
	if err != nil || secondFingerprint != firstFingerprint {
		t.Fatalf("normalized fingerprint = %q, %v; want %q", secondFingerprint, err, firstFingerprint)
	}
	item, firstOccurrence, err := NewWorkItem(WorkItemInput{
		Basis: basis, OwnerID: "owner-a", DueAt: now.Add(24 * time.Hour), Priority: "high",
		Occurrence: WorkOccurrenceInput{AssessmentRunID: "run-a", ObjectiveResultID: "result-a", AutomatedResultHash: "sha256:" + strings.Repeat("c", 64), EvidenceIDs: []string{"evidence-a"}, OccurredAt: now},
	})
	if err != nil {
		t.Fatalf("NewWorkItem() error = %v", err)
	}
	withOccurrence, secondOccurrence, err := RecordWorkOccurrence(item, 1, WorkOccurrenceInput{
		AssessmentRunID: "run-b", ObjectiveResultID: "result-b", AutomatedResultHash: "sha256:" + strings.Repeat("d", 64), OccurredAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("RecordWorkOccurrence() error = %v", err)
	}
	if item.ID != withOccurrence.ID || item.Fingerprint != withOccurrence.Fingerprint || len(item.Occurrences) != 1 || len(withOccurrence.Occurrences) != 2 {
		t.Fatalf("cross-run work identity/history = original %+v next %+v", item, withOccurrence)
	}
	if firstOccurrence.AssessmentRunID == secondOccurrence.AssessmentRunID || firstOccurrence.ID == secondOccurrence.ID {
		t.Fatalf("occurrences were not run-specific: %+v %+v", firstOccurrence, secondOccurrence)
	}
	if _, _, err := RecordWorkOccurrence(withOccurrence, withOccurrence.Version, WorkOccurrenceInput{AssessmentRunID: "run-a"}); !errors.Is(err, ErrDuplicateOccurrence) {
		t.Fatalf("RecordWorkOccurrence(duplicate) error = %v, want ErrDuplicateOccurrence", err)
	}
	inProgress, _, err := ApplyWorkAction(withOccurrence, withOccurrence.Version, WorkActionInput{
		Action: WorkActionRemediate, Rationale: "Refresh the evidence source.", ActorID: "owner-a", At: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("ApplyWorkAction(remediate) error = %v", err)
	}
	resolved, _, err := ApplyWorkAction(inProgress, inProgress.Version, WorkActionInput{
		Action: WorkActionClose, Rationale: "The source refresh completed.", ActorID: "owner-a", At: now.Add(3 * time.Hour),
	})
	if err != nil {
		t.Fatalf("ApplyWorkAction(close) error = %v", err)
	}
	triggers := []WorkReopenTrigger{ReopenExceptionExpired, ReopenEvidenceStale, ReopenEvidenceRevoked, ReopenFindingReopened, ReopenSourceCoverageLost, ReopenScopeSubjectAdded}
	for _, trigger := range triggers {
		reopened, record, err := ReopenWorkItem(resolved, resolved.Version, trigger, "source-ref-a", "owner-b", "system", now.Add(48*time.Hour), now.Add(4*time.Hour))
		if err != nil {
			t.Fatalf("ReopenWorkItem(%s) error = %v", trigger, err)
		}
		if reopened.State != WorkOpen || reopened.OwnerID != "owner-b" || record.Trigger != trigger || record.RecordHash == "" {
			t.Fatalf("ReopenWorkItem(%s) = %+v / %+v", trigger, reopened, record)
		}
	}
}

func TestVerificationRequiredWorkCannotBeSelfClosed(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	item, _, err := NewWorkItem(WorkItemInput{
		Basis: WorkFingerprintInput{
			TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-r1", ControlID: "CC-1",
			ObjectiveID: "objective-a", Kind: WorkRemediateFinding, SubjectID: "subject-a", Reason: ReasonActiveFinding, SourceID: "source-a",
		},
		OwnerID: "owner-a", DueAt: now.Add(24 * time.Hour), Priority: "high", VerificationRequired: true,
		Occurrence: WorkOccurrenceInput{AssessmentRunID: "run-a", ObjectiveResultID: "result-a", AutomatedResultHash: "sha256:" + strings.Repeat("e", 64), OccurredAt: now},
	})
	if err != nil {
		t.Fatalf("NewWorkItem() error = %v", err)
	}
	inProgress, _, err := ApplyWorkAction(item, item.Version, WorkActionInput{Action: WorkActionRemediate, Rationale: "Apply the control change.", ActorID: "owner-a", At: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("ApplyWorkAction(remediate) error = %v", err)
	}
	if _, _, err := ApplyWorkAction(inProgress, inProgress.Version, WorkActionInput{Action: WorkActionClose, Rationale: "Close the work.", ActorID: "owner-a", At: now.Add(2 * time.Hour)}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ApplyWorkAction(close) error = %v, want ErrInvalidTransition", err)
	}
	if _, _, err := ApplyWorkAction(inProgress, inProgress.Version, WorkActionInput{Action: WorkActionVerify, Rationale: "Verify the change.", EvidenceIDs: []string{"evidence-a"}, ActorID: "owner-a", At: now.Add(2 * time.Hour)}); !errors.Is(err, ErrIndependentReview) {
		t.Fatalf("ApplyWorkAction(self verify) error = %v, want ErrIndependentReview", err)
	}
	resolved, _, err := ApplyWorkAction(inProgress, inProgress.Version, WorkActionInput{Action: WorkActionVerify, Rationale: "Verify the change.", EvidenceIDs: []string{"evidence-a"}, ActorID: "reviewer-a", At: now.Add(2 * time.Hour)})
	if err != nil || resolved.State != WorkResolved || resolved.VerifiedBy != "reviewer-a" {
		t.Fatalf("ApplyWorkAction(independent verify) = %+v, %v", resolved, err)
	}
}

func TestWorkActionsClearStateSpecificMetadata(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		state     WorkItemState
		action    WorkAction
		wantState WorkItemState
	}{
		{name: "verify blocked work", state: WorkBlocked, action: WorkActionVerify, wantState: WorkResolved},
		{name: "close blocked work", state: WorkBlocked, action: WorkActionClose, wantState: WorkResolved},
		{name: "accept blocked work", state: WorkBlocked, action: WorkActionAccept, wantState: WorkAccepted},
		{name: "supersede blocked work", state: WorkBlocked, action: WorkActionSupersede, wantState: WorkSuperseded},
		{name: "supersede snoozed work", state: WorkSnoozed, action: WorkActionSupersede, wantState: WorkSuperseded},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			current := WorkItem{
				ID: "work-a", State: testCase.state, OwnerID: "owner-a", RiskID: "risk-a", Version: 1,
				BlockerReason: "Waiting for source recovery.", SnoozeUntil: now.Add(time.Hour),
			}
			next, _, err := ApplyWorkAction(current, current.Version, WorkActionInput{
				Action: testCase.action, Rationale: "Advance the work item.", ActorID: "reviewer-a", At: now,
			})
			if err != nil {
				t.Fatalf("ApplyWorkAction(%s) error = %v", testCase.action, err)
			}
			if next.State != testCase.wantState || next.BlockerReason != "" || !next.SnoozeUntil.IsZero() {
				t.Fatalf("ApplyWorkAction(%s) = %+v", testCase.action, next)
			}
			if current.BlockerReason == "" || current.SnoozeUntil.IsZero() {
				t.Fatalf("ApplyWorkAction(%s) mutated current item: %+v", testCase.action, current)
			}
		})
	}
}
