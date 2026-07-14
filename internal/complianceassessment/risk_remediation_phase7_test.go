package complianceassessment

import (
	"errors"
	"testing"
	"time"
)

func TestAcceptedRiskRequiresBoundedDispositionAndExpires(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	risk, err := NewRisk(validRiskInput(now))
	if err != nil {
		t.Fatalf("NewRisk() error = %v", err)
	}
	assessing, err := TransitionRisk(risk, 1, RiskTransitionInput{To: RiskAssessing, At: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("TransitionRisk(assessing) error = %v", err)
	}
	if _, err := TransitionRisk(assessing, assessing.Version, RiskTransitionInput{To: RiskAccepted, Treatment: RiskTreatmentAccept, At: now.Add(2 * time.Hour)}); !errors.Is(err, ErrInvalidRisk) {
		t.Fatalf("TransitionRisk(incomplete acceptance) error = %v, want ErrInvalidRisk", err)
	}
	accepted, err := TransitionRisk(assessing, assessing.Version, RiskTransitionInput{
		To: RiskAccepted, Treatment: RiskTreatmentAccept, OwnerID: "risk-owner", Rationale: "Temporary business dependency.",
		CompensatingControls: []string{"daily review"}, Approval: &Approval{ID: "approval-a", ApprovedBy: "approver-a", ApprovedAt: now.Add(time.Hour)},
		ExpiresAt: now.Add(30 * 24 * time.Hour), At: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("TransitionRisk(accepted) error = %v", err)
	}
	if accepted.State != RiskAccepted || accepted.OwnerID == "" || accepted.Approval == nil {
		t.Fatalf("accepted risk = %+v", accepted)
	}
	expired, err := ExpireAcceptedRisk(accepted, accepted.Version, accepted.ExpiresAt)
	if err != nil || expired.State != RiskExpired {
		t.Fatalf("ExpireAcceptedRisk() = %+v, %v", expired, err)
	}
}

func TestApprovedExceptionRequiresLinkedRiskApprovalAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	exception, err := NewException(ExceptionInput{
		ID: "exception-a", TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-r1",
		ObjectiveID: "objective-a", SubjectID: "subject-a", VerificationRequired: true, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewException() error = %v", err)
	}
	if _, err := TransitionException(exception, 1, ExceptionTransitionInput{To: ExceptionApproved, At: now.Add(time.Hour)}); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("TransitionException(incomplete approval) error = %v, want ErrInvalidException", err)
	}
	approved, err := TransitionException(exception, 1, ExceptionTransitionInput{
		To: ExceptionApproved, RiskID: "risk-a", OwnerID: "owner-a", Rationale: "Migration window.",
		CompensatingControls: []string{"daily review"}, Approval: &Approval{ID: "approval-a", ApprovedBy: "approver-a", ApprovedAt: now},
		ExpiresAt: now.Add(7 * 24 * time.Hour), At: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("TransitionException(approved) error = %v", err)
	}
	expired, err := ExpireException(approved, approved.Version, approved.ExpiresAt)
	if err != nil || expired.State != ExceptionExpired {
		t.Fatalf("ExpireException() = %+v, %v", expired, err)
	}
}

func TestExpiredRiskRequiresFreshApprovalBeforeAcceptance(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	risk, err := NewRisk(validRiskInput(now))
	if err != nil {
		t.Fatalf("NewRisk() error = %v", err)
	}
	assessing, err := TransitionRisk(risk, risk.Version, RiskTransitionInput{To: RiskAssessing, At: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("TransitionRisk(assessing) error = %v", err)
	}
	accepted, err := TransitionRisk(assessing, assessing.Version, RiskTransitionInput{
		To: RiskAccepted, Treatment: RiskTreatmentAccept, Rationale: "Temporary business dependency.",
		CompensatingControls: []string{"daily review"}, Approval: &Approval{ID: "approval-a", ApprovedBy: "approver-a", ApprovedAt: now.Add(time.Hour)},
		ExpiresAt: now.Add(30 * 24 * time.Hour), At: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("TransitionRisk(accepted) error = %v", err)
	}
	expired, err := ExpireAcceptedRisk(accepted, accepted.Version, accepted.ExpiresAt)
	if err != nil {
		t.Fatalf("ExpireAcceptedRisk() error = %v", err)
	}
	reassessingAt := expired.ExpiresAt.Add(time.Hour)
	reassessing, err := TransitionRisk(expired, expired.Version, RiskTransitionInput{To: RiskAssessing, At: reassessingAt})
	if err != nil {
		t.Fatalf("TransitionRisk(reassessing) error = %v", err)
	}
	reacceptAt := reassessingAt.Add(time.Hour)
	renewal := RiskTransitionInput{To: RiskAccepted, ExpiresAt: reacceptAt.Add(30 * 24 * time.Hour), At: reacceptAt}
	if _, err := TransitionRisk(reassessing, reassessing.Version, renewal); !errors.Is(err, ErrInvalidRisk) {
		t.Fatalf("TransitionRisk(reused approval) error = %v, want ErrInvalidRisk", err)
	}
	renewal.Approval = &Approval{ID: "approval-b", ApprovedBy: "approver-b", ApprovedAt: accepted.Approval.ApprovedAt}
	if _, err := TransitionRisk(reassessing, reassessing.Version, renewal); !errors.Is(err, ErrInvalidRisk) {
		t.Fatalf("TransitionRisk(stale approval) error = %v, want ErrInvalidRisk", err)
	}
	renewal.Approval = &Approval{ID: "approval-c", ApprovedBy: "approver-c", ApprovedAt: reassessingAt}
	if renewed, err := TransitionRisk(reassessing, reassessing.Version, renewal); err != nil || renewed.State != RiskAccepted {
		t.Fatalf("TransitionRisk(fresh approval) = %+v, %v", renewed, err)
	}
}

func TestExpiredExceptionRequiresFreshApprovalBeforeApproval(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	exception, err := NewException(ExceptionInput{
		ID: "exception-a", TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-r1",
		ObjectiveID: "objective-a", SubjectID: "subject-a", VerificationRequired: true, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewException() error = %v", err)
	}
	approved, err := TransitionException(exception, exception.Version, ExceptionTransitionInput{
		To: ExceptionApproved, RiskID: "risk-a", OwnerID: "owner-a", Rationale: "Migration window.",
		CompensatingControls: []string{"daily review"}, Approval: &Approval{ID: "approval-a", ApprovedBy: "approver-a", ApprovedAt: now},
		ExpiresAt: now.Add(7 * 24 * time.Hour), At: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("TransitionException(approved) error = %v", err)
	}
	expired, err := ExpireException(approved, approved.Version, approved.ExpiresAt)
	if err != nil {
		t.Fatalf("ExpireException() error = %v", err)
	}
	proposedAt := expired.ExpiresAt.Add(time.Hour)
	proposed, err := TransitionException(expired, expired.Version, ExceptionTransitionInput{To: ExceptionProposed, At: proposedAt})
	if err != nil {
		t.Fatalf("TransitionException(proposed) error = %v", err)
	}
	reapproveAt := proposedAt.Add(time.Hour)
	renewal := ExceptionTransitionInput{To: ExceptionApproved, ExpiresAt: reapproveAt.Add(7 * 24 * time.Hour), At: reapproveAt}
	if _, err := TransitionException(proposed, proposed.Version, renewal); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("TransitionException(reused approval) error = %v, want ErrInvalidException", err)
	}
	renewal.Approval = &Approval{ID: approved.Approval.ID, ApprovedBy: "approver-b", ApprovedAt: proposedAt}
	if _, err := TransitionException(proposed, proposed.Version, renewal); !errors.Is(err, ErrInvalidException) {
		t.Fatalf("TransitionException(reused approval id) error = %v, want ErrInvalidException", err)
	}
	renewal.Approval = &Approval{ID: "approval-b", ApprovedBy: "approver-b", ApprovedAt: proposedAt}
	if renewed, err := TransitionException(proposed, proposed.Version, renewal); err != nil || renewed.State != ExceptionApproved {
		t.Fatalf("TransitionException(fresh approval) = %+v, %v", renewed, err)
	}
}

func TestRiskClosureRequiresIndependentVerification(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	risk, err := NewRisk(validRiskInput(now))
	if err != nil {
		t.Fatalf("NewRisk() error = %v", err)
	}
	assessing, _ := TransitionRisk(risk, risk.Version, RiskTransitionInput{To: RiskAssessing, At: now.Add(time.Hour)})
	planned, _ := TransitionRisk(assessing, assessing.Version, RiskTransitionInput{To: RiskTreatmentPlanned, Treatment: RiskTreatmentMitigate, OwnerID: "risk-owner", At: now.Add(2 * time.Hour)})
	mitigated, err := TransitionRisk(planned, planned.Version, RiskTransitionInput{To: RiskMitigated, At: now.Add(3 * time.Hour)})
	if err != nil {
		t.Fatalf("TransitionRisk(mitigated) error = %v", err)
	}
	if _, err := TransitionRisk(mitigated, mitigated.Version, RiskTransitionInput{To: RiskClosed, VerificationEvidenceIDs: []string{"evidence-a"}, VerifiedBy: "risk-owner", At: now.Add(4 * time.Hour)}); !errors.Is(err, ErrIndependentReview) {
		t.Fatalf("TransitionRisk(owner closure) error = %v, want ErrIndependentReview", err)
	}
	closed, err := TransitionRisk(mitigated, mitigated.Version, RiskTransitionInput{To: RiskClosed, VerificationEvidenceIDs: []string{"evidence-a"}, VerifiedBy: "reviewer-a", At: now.Add(4 * time.Hour)})
	if err != nil || closed.State != RiskClosed {
		t.Fatalf("TransitionRisk(independent closure) = %+v, %v", closed, err)
	}
}

func TestRemediationDependenciesIndependentVerificationAndReopen(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	plan, err := NewRemediationPlan(RemediationPlanInput{
		ID: "plan-a", TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-r1", RiskID: "risk-a", WorkItemID: "work-a",
		Treatment: RiskTreatmentMitigate, OwnerID: "plan-owner", TargetAt: now.Add(30 * 24 * time.Hour), RetestRequired: true, VerificationRequired: true,
		Milestones: []RemediationMilestoneInput{
			{ID: "milestone-a", Title: "Deploy change", OwnerID: "implementer-a", TargetAt: now.Add(7 * 24 * time.Hour), PlannedAction: "Deploy the control change."},
			{ID: "milestone-b", Title: "Retest control", OwnerID: "implementer-b", TargetAt: now.Add(14 * 24 * time.Hour), DependsOnIDs: []string{"milestone-a"}, PlannedAction: "Run the control test."},
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewRemediationPlan() error = %v", err)
	}
	active, err := ActivateRemediationPlan(plan, plan.Version, "plan-owner", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("ActivateRemediationPlan() error = %v", err)
	}
	if _, err := StartRemediationMilestone(active, active.Version, "milestone-b", "implementer-b", now.Add(2*time.Hour)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("StartRemediationMilestone(blocked dependency) error = %v, want ErrInvalidTransition", err)
	}
	active = mustStartMilestone(t, active, "milestone-a", "implementer-a", now.Add(2*time.Hour))
	active = mustCompleteMilestone(t, active, "milestone-a", "implementer-a", now.Add(3*time.Hour))
	if _, err := VerifyRemediationMilestone(active, active.Version, "milestone-a", []string{"verify-a"}, "implementer-a", now.Add(4*time.Hour)); !errors.Is(err, ErrIndependentReview) {
		t.Fatalf("VerifyRemediationMilestone(self) error = %v, want ErrIndependentReview", err)
	}
	active, err = VerifyRemediationMilestone(active, active.Version, "milestone-a", []string{"verify-a"}, "reviewer-a", now.Add(4*time.Hour))
	if err != nil {
		t.Fatalf("VerifyRemediationMilestone(a) error = %v", err)
	}
	active = mustStartMilestone(t, active, "milestone-b", "implementer-b", now.Add(5*time.Hour))
	active = mustCompleteMilestone(t, active, "milestone-b", "implementer-b", now.Add(6*time.Hour))
	active, err = VerifyRemediationMilestone(active, active.Version, "milestone-b", []string{"verify-b"}, "reviewer-a", now.Add(7*time.Hour))
	if err != nil {
		t.Fatalf("VerifyRemediationMilestone(b) error = %v", err)
	}
	if _, err := CloseRemediationPlan(active, active.Version, []string{"closure-proof"}, "plan-owner", now.Add(8*time.Hour)); !errors.Is(err, ErrIndependentReview) {
		t.Fatalf("CloseRemediationPlan(owner) error = %v, want ErrIndependentReview", err)
	}
	closed, err := CloseRemediationPlan(active, active.Version, []string{"closure-proof"}, "reviewer-b", now.Add(8*time.Hour))
	if err != nil || closed.State != RemediationClosed {
		t.Fatalf("CloseRemediationPlan() = %+v, %v", closed, err)
	}
	reopened, record, err := ReopenRemediationPlan(closed, closed.Version, ReopenEvidenceRevoked, "evidence-a", "system", now.Add(9*time.Hour))
	if err != nil || reopened.State != RemediationReopened || record.Trigger != ReopenEvidenceRevoked || record.RecordHash == "" {
		t.Fatalf("ReopenRemediationPlan() = %+v / %+v, %v", reopened, record, err)
	}
	for _, milestone := range reopened.Milestones {
		if milestone.State != MilestoneCompleted || milestone.VerifiedBy != "" || len(milestone.VerificationEvidenceIDs) != 0 {
			t.Fatalf("reopen did not invalidate milestone verification: %+v", milestone)
		}
	}
}

func validRiskInput(now time.Time) RiskInput {
	return RiskInput{
		ID: "risk-a", TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-r1", SubjectID: "subject-a", ObjectiveID: "objective-a",
		Title: "Control gap", BusinessContext: "The control gap affects assurance.", Likelihood: "possible", Impact: "material", Severity: "high",
		OwnerID: "risk-owner", VerificationRequired: true, CreatedAt: now,
	}
}

func mustStartMilestone(t *testing.T, plan RemediationPlan, milestoneID, actorID string, at time.Time) RemediationPlan {
	t.Helper()
	next, err := StartRemediationMilestone(plan, plan.Version, milestoneID, actorID, at)
	if err != nil {
		t.Fatalf("StartRemediationMilestone(%s) error = %v", milestoneID, err)
	}
	return next
}

func mustCompleteMilestone(t *testing.T, plan RemediationPlan, milestoneID, actorID string, at time.Time) RemediationPlan {
	t.Helper()
	next, err := CompleteRemediationMilestone(plan, plan.Version, milestoneID, "Completed planned action.", []string{"completion-" + milestoneID}, actorID, at)
	if err != nil {
		t.Fatalf("CompleteRemediationMilestone(%s) error = %v", milestoneID, err)
	}
	return next
}
