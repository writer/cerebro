package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/config"
)

func TestComplianceReviewSchemaIsTenantScopedAndComplete(t *testing.T) {
	joined := strings.Join(ensureComplianceReviewStatements, "\n")
	tables := []string{
		"compliance_reviews", "compliance_review_revisions", "compliance_risks",
		"compliance_exceptions", "compliance_work_items", "compliance_work_occurrences",
		"compliance_work_actions", "compliance_remediation_plans",
		"compliance_remediation_milestones", "compliance_review_event_receipts",
	}
	for _, table := range tables {
		if !strings.Contains(joined, "CREATE TABLE IF NOT EXISTS "+table) {
			t.Fatalf("schema is missing table %q", table)
		}
	}
	for _, statement := range ensureComplianceReviewStatements {
		if !strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS") {
			continue
		}
		if !strings.Contains(statement, "tenant_id TEXT NOT NULL") || !strings.Contains(statement, "PRIMARY KEY (tenant_id,") {
			t.Fatalf("table statement is not tenant scoped:\n%s", statement)
		}
	}
	if !strings.Contains(joined, "FOREIGN KEY (tenant_id, review_id)") ||
		!strings.Contains(joined, "FOREIGN KEY (tenant_id, work_item_id)") ||
		!strings.Contains(joined, "FOREIGN KEY (tenant_id, plan_id)") {
		t.Fatal("child tables are missing tenant-scoped foreign keys")
	}
}

func TestComplianceProjectionPayloadHashIncludesEventIdentity(t *testing.T) {
	now := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
	event := complianceProjectionEvent{
		metadata: ComplianceProjectionMetadata{EventID: "event-a", OccurredAt: now},
		tenantID: "tenant-a", kind: "risk", aggregateID: "risk-a", version: 1,
	}
	first, err := complianceProjectionPayloadHash(event, map[string]string{"state": "open"})
	if err != nil {
		t.Fatalf("complianceProjectionPayloadHash() error = %v", err)
	}
	second, err := complianceProjectionPayloadHash(event, map[string]string{"state": "open"})
	if err != nil || first != second {
		t.Fatalf("stable hashes = %q, %q, %v", first, second, err)
	}
	event.metadata.EventID = "event-b"
	changed, err := complianceProjectionPayloadHash(event, map[string]string{"state": "open"})
	if err != nil || changed == first {
		t.Fatalf("event identity did not change payload hash: %q, %q, %v", first, changed, err)
	}
}

func TestComplianceReviewProjectionPostgresIntegration(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CEREBRO_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set CEREBRO_POSTGRES_DSN to run compliance review projection integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(config.StateStoreConfig{Driver: config.StateStoreDriverPostgres, PostgresDSN: dsn})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	projector, err := NewComplianceReviewProjector(store)
	if err != nil {
		t.Fatalf("NewComplianceReviewProjector() error = %v", err)
	}
	tenantID := fmt.Sprintf("compliance-review-test-%d", time.Now().UnixNano())
	if err := store.ensureComplianceReviewTables(ctx); err != nil {
		t.Fatalf("ensureComplianceReviewTables() error = %v", err)
	}
	t.Cleanup(func() { cleanupComplianceReviewTenant(t, store, tenantID) })
	now := time.Now().UTC().Truncate(time.Millisecond)

	review, firstRevision, err := complianceassessment.NewReview(tenantID, "run-a", "result-a", "sha256:"+strings.Repeat("a", 64), complianceassessment.ReviewRevisionInput{
		Decision: complianceassessment.ReviewAccept, EffectiveDisposition: complianceassessment.DispositionNone,
		EffectiveAuditor: complianceassessment.AuditorAccepted, Rationale: "Evidence supports the result.",
		ActorID: "reviewer-a", ActorRole: "control_reviewer", EvidenceIDs: []string{"evidence-a"}, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewReview() error = %v", err)
	}
	reviewEvent := ComplianceProjectionMetadata{EventID: "review-created", ExpectedVersion: 0, OccurredAt: now}
	receipt, err := projector.ProjectReview(ctx, reviewEvent, review, firstRevision)
	if err != nil || !receipt.Applied || receipt.PayloadHash == "" {
		t.Fatalf("ProjectReview(create) = %+v, %v", receipt, err)
	}
	replayed, err := projector.ProjectReview(ctx, reviewEvent, review, firstRevision)
	if err != nil || replayed.Applied || replayed.PayloadHash != receipt.PayloadHash {
		t.Fatalf("ProjectReview(replay) = %+v, %v", replayed, err)
	}
	review, secondRevision, err := complianceassessment.ReviseReview(review, review.Version, complianceassessment.ReviewRevisionInput{
		Decision: complianceassessment.ReviewRequestChanges, EffectiveDisposition: complianceassessment.DispositionNone,
		EffectiveAuditor: complianceassessment.AuditorChangesRequested, Rationale: "Additional evidence is required.",
		ActorID: "reviewer-b", ActorRole: "audit_reviewer", CreatedAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ReviseReview() error = %v", err)
	}
	if _, err := projector.ProjectReview(ctx, ComplianceProjectionMetadata{EventID: "review-revised", ExpectedVersion: 1, OccurredAt: now.Add(time.Minute)}, review, secondRevision); err != nil {
		t.Fatalf("ProjectReview(revise) error = %v", err)
	}
	if _, err := projector.ProjectReview(ctx, ComplianceProjectionMetadata{EventID: "review-stale", ExpectedVersion: 1, OccurredAt: now.Add(2 * time.Minute)}, review, secondRevision); !errors.Is(err, ErrComplianceProjectionVersionConflict) {
		t.Fatalf("ProjectReview(stale) error = %v, want version conflict", err)
	}
	storedReview, err := store.GetComplianceReview(ctx, tenantID, review.ID)
	if err != nil || storedReview.Review.Version != 2 || len(storedReview.Revisions) != 2 {
		t.Fatalf("GetComplianceReview() = %+v, %v", storedReview, err)
	}
	if _, err := store.GetComplianceReview(ctx, "other-tenant", review.ID); !errors.Is(err, ErrComplianceProjectionNotFound) {
		t.Fatalf("cross-tenant GetComplianceReview() error = %v, want not found", err)
	}

	risk, err := complianceassessment.NewRisk(complianceassessment.RiskInput{
		ID: "risk-a", TenantID: tenantID, ProgramID: "program-a", ScopeRevisionID: "scope-r1",
		SubjectID: "subject-a", ObjectiveID: "objective-a", Title: "Control gap",
		BusinessContext: "The gap affects assurance.", Likelihood: "possible", Impact: "material", Severity: "high", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewRisk() error = %v", err)
	}
	riskEvent := ComplianceProjectionMetadata{EventID: "risk-created", ExpectedVersion: 0, OccurredAt: now}
	if _, err := projector.ProjectRisk(ctx, riskEvent, risk); err != nil {
		t.Fatalf("ProjectRisk() error = %v", err)
	}
	if _, err := projector.ProjectRisk(ctx, ComplianceProjectionMetadata{EventID: "risk-stale", ExpectedVersion: 0, OccurredAt: now.Add(time.Minute)}, risk); !errors.Is(err, ErrComplianceProjectionVersionConflict) {
		t.Fatalf("ProjectRisk(stale) error = %v, want version conflict", err)
	}
	if storedRisk, err := store.GetComplianceRisk(ctx, tenantID, risk.ID); err != nil || storedRisk.ID != risk.ID {
		t.Fatalf("GetComplianceRisk() = %+v, %v", storedRisk, err)
	}

	exception, err := complianceassessment.NewException(complianceassessment.ExceptionInput{
		ID: "exception-a", TenantID: tenantID, ProgramID: "program-a", ScopeRevisionID: "scope-r1",
		ObjectiveID: "objective-a", SubjectID: "subject-a", RiskID: risk.ID, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewException() error = %v", err)
	}
	if _, err := projector.ProjectException(ctx, ComplianceProjectionMetadata{EventID: riskEvent.EventID, ExpectedVersion: 0, OccurredAt: now}, exception); !errors.Is(err, ErrComplianceProjectionIdempotencyConflict) {
		t.Fatalf("ProjectException(reused event id) error = %v, want idempotency conflict", err)
	}
	if _, err := projector.ProjectException(ctx, ComplianceProjectionMetadata{EventID: "exception-created", ExpectedVersion: 0, OccurredAt: now}, exception); err != nil {
		t.Fatalf("ProjectException() error = %v", err)
	}
	if storedException, err := store.GetComplianceException(ctx, tenantID, exception.ID); err != nil || storedException.ID != exception.ID {
		t.Fatalf("GetComplianceException() = %+v, %v", storedException, err)
	}

	item, occurrence, err := complianceassessment.NewWorkItem(complianceassessment.WorkItemInput{
		Basis: complianceassessment.WorkFingerprintInput{
			TenantID: tenantID, ProgramID: "program-a", ScopeRevisionID: "scope-r1", ControlID: "CC-1",
			ObjectiveID: "objective-a", Kind: complianceassessment.WorkRemediateFinding,
			SubjectID: "subject-a", Reason: complianceassessment.ReasonActiveFinding, SourceID: "source-a",
		},
		OwnerID: "owner-a", DueAt: now.Add(24 * time.Hour), Priority: "high", RiskID: risk.ID,
		Occurrence: complianceassessment.WorkOccurrenceInput{
			AssessmentRunID: "run-a", ObjectiveResultID: "result-a",
			AutomatedResultHash: "sha256:" + strings.Repeat("b", 64), OccurredAt: now,
		},
	})
	if err != nil {
		t.Fatalf("NewWorkItem() error = %v", err)
	}
	if _, err := projector.ProjectWorkOccurrence(ctx, ComplianceProjectionMetadata{EventID: "work-observed", ExpectedVersion: 0, OccurredAt: now}, item, occurrence); err != nil {
		t.Fatalf("ProjectWorkOccurrence() error = %v", err)
	}
	item, action, err := complianceassessment.ApplyWorkAction(item, item.Version, complianceassessment.WorkActionInput{
		Action: complianceassessment.WorkActionRemediate, Rationale: "Apply the corrective change.", ActorID: "owner-a", At: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ApplyWorkAction() error = %v", err)
	}
	actionEvent := ComplianceProjectionMetadata{EventID: "work-remediated", ExpectedVersion: 1, OccurredAt: now.Add(time.Minute)}
	if _, err := projector.ProjectWorkAction(ctx, actionEvent, item, action); err != nil {
		t.Fatalf("ProjectWorkAction() error = %v", err)
	}
	if replay, err := projector.ProjectWorkAction(ctx, actionEvent, item, action); err != nil || replay.Applied {
		t.Fatalf("ProjectWorkAction(replay) = %+v, %v", replay, err)
	}
	storedWork, err := store.GetComplianceWorkItem(ctx, tenantID, item.ID)
	if err != nil || storedWork.Item.Version != 2 || len(storedWork.Occurrences) != 1 || len(storedWork.Actions) != 1 {
		t.Fatalf("GetComplianceWorkItem() = %+v, %v", storedWork, err)
	}

	plan, err := complianceassessment.NewRemediationPlan(complianceassessment.RemediationPlanInput{
		ID: "plan-a", TenantID: tenantID, ProgramID: "program-a", ScopeRevisionID: "scope-r1",
		RiskID: risk.ID, WorkItemID: item.ID, Treatment: complianceassessment.RiskTreatmentMitigate,
		OwnerID: "owner-a", TargetAt: now.Add(30 * 24 * time.Hour), VerificationRequired: true,
		Milestones: []complianceassessment.RemediationMilestoneInput{{
			ID: "milestone-a", Title: "Apply change", OwnerID: "owner-a",
			TargetAt: now.Add(7 * 24 * time.Hour), PlannedAction: "Apply the corrective change.",
		}}, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("NewRemediationPlan() error = %v", err)
	}
	if _, err := projector.ProjectRemediationPlan(ctx, ComplianceProjectionMetadata{EventID: "plan-created", ExpectedVersion: 0, OccurredAt: now}, plan); err != nil {
		t.Fatalf("ProjectRemediationPlan(create) error = %v", err)
	}
	plan, err = complianceassessment.ActivateRemediationPlan(plan, plan.Version, "owner-a", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("ActivateRemediationPlan() error = %v", err)
	}
	if _, err := projector.ProjectRemediationPlan(ctx, ComplianceProjectionMetadata{EventID: "plan-activated", ExpectedVersion: 1, OccurredAt: now.Add(time.Minute)}, plan); err != nil {
		t.Fatalf("ProjectRemediationPlan(activate) error = %v", err)
	}
	storedPlan, err := store.GetComplianceRemediationPlan(ctx, tenantID, plan.ID)
	if err != nil || storedPlan.Plan.Version != 2 || len(storedPlan.Milestones) != 1 || storedPlan.Milestones[0].ID != "milestone-a" {
		t.Fatalf("GetComplianceRemediationPlan() = %+v, %v", storedPlan, err)
	}
	storedReceipt, err := store.GetComplianceProjectionReceipt(ctx, tenantID, reviewEvent.EventID)
	if err != nil || storedReceipt.PayloadHash != receipt.PayloadHash || storedReceipt.AggregateVersion != 1 {
		t.Fatalf("GetComplianceProjectionReceipt() = %+v, %v", storedReceipt, err)
	}
}

func cleanupComplianceReviewTenant(t *testing.T, store *Store, tenantID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	queries := []string{
		"DELETE FROM compliance_review_event_receipts WHERE tenant_id = $1",
		"DELETE FROM compliance_remediation_milestones WHERE tenant_id = $1",
		"DELETE FROM compliance_remediation_plans WHERE tenant_id = $1",
		"DELETE FROM compliance_work_actions WHERE tenant_id = $1",
		"DELETE FROM compliance_work_occurrences WHERE tenant_id = $1",
		"DELETE FROM compliance_work_items WHERE tenant_id = $1",
		"DELETE FROM compliance_review_revisions WHERE tenant_id = $1",
		"DELETE FROM compliance_reviews WHERE tenant_id = $1",
		"DELETE FROM compliance_exceptions WHERE tenant_id = $1",
		"DELETE FROM compliance_risks WHERE tenant_id = $1",
	}
	for _, query := range queries {
		if _, err := store.db.ExecContext(ctx, query, tenantID); err != nil {
			t.Errorf("cleanup compliance review tenant: %v", err)
		}
	}
}
