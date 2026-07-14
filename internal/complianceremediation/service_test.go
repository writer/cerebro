package complianceremediation

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/ports"
)

func TestEncodeAggregateVersionRejectsInvalidRange(t *testing.T) {
	for _, version := range []uint64{0, uint64(math.MaxInt64) + 1} {
		if _, err := encodeAggregateVersion(version); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("encodeAggregateVersion(%d) error = %v, want ErrInvalidRequest", version, err)
		}
	}
	if got, err := encodeAggregateVersion(math.MaxInt64); err != nil || got != math.MaxInt64 {
		t.Fatalf("encodeAggregateVersion(MaxInt64) = (%d, %v)", got, err)
	}
}

func TestFailedResultWorkReplaysOldestFirstAndReopensAfterInvalidation(t *testing.T) {
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	runtime := newMemoryRuntime()
	service := New(runtime, runtime, runtime, runtime)
	input := failedResultInput(now)
	record, err := service.DeriveWork(context.Background(), input, "assessor-a")
	if err != nil {
		t.Fatalf("DeriveWork() error = %v", err)
	}
	record, err = service.ApplyWorkCommand(context.Background(), "tenant-a", record.Item.ID, WorkCommand{
		Operation: "action", ExpectedVersion: record.Item.Version, Action: complianceassessment.WorkActionRemediate,
		Rationale: "Apply the control change.", ActorID: "owner-a", At: now.Add(time.Hour),
	})
	if err != nil || record.Item.State != complianceassessment.WorkInProgress {
		t.Fatalf("ApplyWorkCommand(remediate) = %+v, %v", record.Item, err)
	}

	// Rebuild current state only from the append log. With page size one the
	// pager returns the action first; recovery must refetch and apply creation first.
	runtime.resetProjections()
	processed, err := service.RecoverProjections(context.Background(), 1)
	if err != nil || processed != 2 {
		t.Fatalf("RecoverProjections() = %d, %v", processed, err)
	}
	record, err = service.GetWorkItem(context.Background(), "tenant-a", record.Item.ID)
	if err != nil || record.Item.State != complianceassessment.WorkInProgress || record.Item.Version != 2 {
		t.Fatalf("recovered work = %+v, %v", record.Item, err)
	}

	before := len(runtime.events)
	_, err = service.ApplyWorkCommand(context.Background(), "tenant-a", record.Item.ID, WorkCommand{
		Operation: "action", ExpectedVersion: record.Item.Version, Action: complianceassessment.WorkActionVerify,
		Rationale: "Verify the control change.", EvidenceIDs: []string{"evidence-verify"}, ActorID: "owner-a", At: now.Add(2 * time.Hour),
	})
	if !errors.Is(err, complianceassessment.ErrIndependentReview) || len(runtime.events) != before {
		t.Fatalf("self verification error/events = %v/%d, want independent rejection before append", err, len(runtime.events))
	}
	record, err = service.ApplyWorkCommand(context.Background(), "tenant-a", record.Item.ID, WorkCommand{
		Operation: "action", ExpectedVersion: record.Item.Version, Action: complianceassessment.WorkActionVerify,
		Rationale: "Verify the control change.", EvidenceIDs: []string{"evidence-verify"}, ActorID: "reviewer-a", At: now.Add(2 * time.Hour),
	})
	if err != nil || record.Item.State != complianceassessment.WorkResolved || record.Item.VerifiedBy != "reviewer-a" {
		t.Fatalf("independent verification = %+v, %v", record.Item, err)
	}
	record, err = service.ApplyWorkCommand(context.Background(), "tenant-a", record.Item.ID, WorkCommand{
		Operation: "invalidate", ExpectedVersion: record.Item.Version,
		Trigger: complianceassessment.ReopenEvidenceRevoked, SourceRef: "evidence-verify",
		OwnerID: "owner-b", DueAt: now.Add(48 * time.Hour), ActorID: "system", At: now.Add(3 * time.Hour),
	})
	if err != nil || record.Item.State != complianceassessment.WorkOpen || record.Item.LastReopenTrigger != complianceassessment.ReopenEvidenceRevoked || record.Item.VerifiedBy != "" {
		t.Fatalf("invalidated work = %+v, %v", record.Item, err)
	}
}

func TestAppendSuccessProjectionFailureRecoversWork(t *testing.T) {
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	runtime := newMemoryRuntime()
	runtime.failProjection = true
	service := New(runtime, runtime, runtime, runtime)
	input := failedResultInput(now)
	_, err := service.DeriveWork(context.Background(), input, "assessor-a")
	if err == nil || len(runtime.events) != 1 || len(runtime.work) != 0 {
		t.Fatalf("append/projection failure state = err %v, events %d, work %d", err, len(runtime.events), len(runtime.work))
	}
	runtime.failProjection = false
	processed, err := service.RecoverProjections(context.Background(), 10)
	if err != nil || processed != 1 || len(runtime.work) != 1 {
		t.Fatalf("RecoverProjections() = %d, %v; work=%d", processed, err, len(runtime.work))
	}
}

func TestRemediationPlanRequiresIndependentVerificationAndReopens(t *testing.T) {
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	runtime := newMemoryRuntime()
	service := New(runtime, runtime, runtime, runtime)
	plan, err := service.CreateRemediationPlan(context.Background(), complianceassessment.RemediationPlanInput{
		ID: "plan-a", TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-a",
		RiskID: "risk-a", WorkItemID: "work-a", Treatment: complianceassessment.RiskTreatmentMitigate,
		OwnerID: "owner-a", TargetAt: now.Add(72 * time.Hour), CreatedAt: now,
		Milestones: []complianceassessment.RemediationMilestoneInput{{
			ID: "milestone-a", Title: "Deploy control", OwnerID: "implementer-a",
			TargetAt: now.Add(24 * time.Hour), PlannedAction: "Deploy the approved control change.",
		}},
	}, "owner-a")
	if err != nil || !plan.VerificationRequired {
		t.Fatalf("CreateRemediationPlan() = %+v, %v", plan, err)
	}
	plan = applyPlanCommand(t, service, plan, RemediationCommand{Operation: "activate", ActorID: "owner-a", At: now.Add(time.Hour)})
	plan = applyPlanCommand(t, service, plan, RemediationCommand{Operation: "start_milestone", MilestoneID: "milestone-a", ActorID: "implementer-a", At: now.Add(2 * time.Hour)})
	plan = applyPlanCommand(t, service, plan, RemediationCommand{
		Operation: "complete_milestone", MilestoneID: "milestone-a", CompletedAction: "Deployed the control change.",
		EvidenceIDs: []string{"completion-a"}, ActorID: "implementer-a", At: now.Add(3 * time.Hour),
	})
	_, err = service.ApplyRemediationCommand(context.Background(), plan.TenantID, plan.ID, RemediationCommand{
		Operation: "verify_milestone", ExpectedVersion: plan.Version, MilestoneID: "milestone-a",
		EvidenceIDs: []string{"verification-a"}, ActorID: "implementer-a", At: now.Add(4 * time.Hour),
	})
	if !errors.Is(err, complianceassessment.ErrIndependentReview) {
		t.Fatalf("self milestone verification error = %v", err)
	}
	plan = applyPlanCommand(t, service, plan, RemediationCommand{
		Operation: "verify_milestone", MilestoneID: "milestone-a", EvidenceIDs: []string{"verification-a"},
		ActorID: "reviewer-a", At: now.Add(4 * time.Hour),
	})
	_, err = service.ApplyRemediationCommand(context.Background(), plan.TenantID, plan.ID, RemediationCommand{
		Operation: "close", ExpectedVersion: plan.Version, EvidenceIDs: []string{"closure-a"}, ActorID: "owner-a", At: now.Add(5 * time.Hour),
	})
	if !errors.Is(err, complianceassessment.ErrIndependentReview) {
		t.Fatalf("owner closure error = %v", err)
	}
	plan = applyPlanCommand(t, service, plan, RemediationCommand{
		Operation: "close", EvidenceIDs: []string{"closure-a"}, ActorID: "reviewer-b", At: now.Add(5 * time.Hour),
	})
	if plan.State != complianceassessment.RemediationClosed {
		t.Fatalf("closed plan state = %q", plan.State)
	}
	plan = applyPlanCommand(t, service, plan, RemediationCommand{
		Operation: "invalidate", Trigger: complianceassessment.ReopenSourceCoverageLost,
		SourceRef: "runtime-a", ActorID: "system", At: now.Add(6 * time.Hour),
	})
	if plan.State != complianceassessment.RemediationReopened || plan.VerifiedBy != "" || plan.LastReopenTrigger != complianceassessment.ReopenSourceCoverageLost {
		t.Fatalf("reopened plan = %+v", plan)
	}
}

func applyPlanCommand(t *testing.T, service *Service, plan complianceassessment.RemediationPlan, command RemediationCommand) complianceassessment.RemediationPlan {
	t.Helper()
	command.ExpectedVersion = plan.Version
	next, err := service.ApplyRemediationCommand(context.Background(), plan.TenantID, plan.ID, command)
	if err != nil {
		t.Fatalf("ApplyRemediationCommand(%s) error = %v", command.Operation, err)
	}
	return next
}

func failedResultInput(now time.Time) DeriveWorkInput {
	digest := "sha256:" + strings.Repeat("a", 64)
	return DeriveWorkInput{
		TenantID: "tenant-a", ProgramID: "program-a", ScopeRevisionID: "scope-a",
		SubjectID: "subject-a", SourceID: "runtime-a", OwnerID: "owner-a",
		DueAt: now.Add(24 * time.Hour), Priority: "high", AssessmentRunID: "run-a", AutomatedResultHash: digest,
		Result: complianceassessment.ObjectiveResult{
			ID: "result-a", ControlRef: compliance.ControlRef{FrameworkID: "framework-a", ControlID: "control-a"}, ObjectiveID: "objective-a",
			ScopeState: complianceassessment.ScopeInScope, AutomatedOutcome: complianceassessment.OutcomeNotSatisfied,
			DesignState: complianceassessment.DesignIneffective, OperatingEffectivenessState: complianceassessment.OperatingIneffective,
			EvidenceState: complianceassessment.EvidenceSufficient, DispositionState: complianceassessment.DispositionNone,
			Assurance: complianceassessment.AssuranceHigh, AuditorState: complianceassessment.AuditorNotReviewed,
			ReasonCodes: []complianceassessment.ReasonCode{complianceassessment.ReasonActiveFinding},
			NextActions: []complianceassessment.NextAction{complianceassessment.ActionRemediate},
			FindingIDs:  []string{"finding-a"}, SourceRuntimeIDs: []string{"runtime-a"},
			EvaluatorRevision: "evaluator-a", EvaluatedAt: now,
		},
	}
}

type memoryRuntime struct {
	events         []*cerebrov1.EventEnvelope
	work           map[string]WorkItemRecord
	plans          map[string]complianceassessment.RemediationPlan
	receipts       map[string]struct{}
	failProjection bool
}

func newMemoryRuntime() *memoryRuntime {
	return &memoryRuntime{work: map[string]WorkItemRecord{}, plans: map[string]complianceassessment.RemediationPlan{}, receipts: map[string]struct{}{}}
}

func (m *memoryRuntime) Ping(context.Context) error { return nil }

func (m *memoryRuntime) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	m.events = append(m.events, event)
	return nil
}

func (m *memoryRuntime) ReplayPage(_ context.Context, request ports.ReplayRequest) (ports.ReplayPage, error) {
	filtered := make([]*cerebrov1.EventEnvelope, 0, len(m.events))
	for index := len(m.events) - 1; index >= 0; index-- {
		event := m.events[index]
		for _, kind := range request.KindPrefixes {
			if event.GetKind() == kind {
				filtered = append(filtered, event)
				break
			}
		}
	}
	start := 0
	if request.Cursor != "" {
		start = -1
		for index, event := range filtered {
			if event.GetId() == request.Cursor {
				start = index + 1
				break
			}
		}
		if start < 0 {
			return ports.ReplayPage{}, ports.ErrReplayCursorNotFound
		}
	}
	limit := int(request.Limit)
	if limit == 0 || limit > len(filtered)-start {
		limit = len(filtered) - start
	}
	end := start + limit
	page := ports.ReplayPage{Events: append([]*cerebrov1.EventEnvelope(nil), filtered[start:end]...), Complete: end == len(filtered)}
	if !page.Complete && len(page.Events) != 0 {
		page.NextCursor = page.Events[len(page.Events)-1].GetId()
	}
	return page, nil
}

func (m *memoryRuntime) GetWorkItem(_ context.Context, tenantID, workItemID string) (WorkItemRecord, error) {
	record, ok := m.work[tenantID+"\x00"+workItemID]
	if !ok {
		return WorkItemRecord{}, ErrNotFound
	}
	return record, nil
}

func (m *memoryRuntime) GetRemediationPlan(_ context.Context, tenantID, planID string) (complianceassessment.RemediationPlan, error) {
	plan, ok := m.plans[tenantID+"\x00"+planID]
	if !ok {
		return complianceassessment.RemediationPlan{}, ErrNotFound
	}
	return plan, nil
}

func (m *memoryRuntime) ProjectWorkOccurrence(_ context.Context, metadata ProjectionMetadata, item complianceassessment.WorkItem, occurrence complianceassessment.WorkOccurrence) error {
	if err := m.beforeProject(metadata); err != nil {
		return err
	}
	key := item.Basis.TenantID + "\x00" + item.ID
	record := m.work[key]
	record.Item = item
	record.Occurrences = append(record.Occurrences, occurrence)
	m.work[key] = record
	return nil
}

func (m *memoryRuntime) ProjectWorkAction(_ context.Context, metadata ProjectionMetadata, item complianceassessment.WorkItem, action complianceassessment.WorkActionRecord) error {
	if err := m.beforeProject(metadata); err != nil {
		return err
	}
	key := item.Basis.TenantID + "\x00" + item.ID
	record := m.work[key]
	record.Item = item
	record.Actions = append(record.Actions, action)
	m.work[key] = record
	return nil
}

func (m *memoryRuntime) ProjectWorkReopen(_ context.Context, metadata ProjectionMetadata, item complianceassessment.WorkItem, _ complianceassessment.WorkReopenRecord) error {
	if err := m.beforeProject(metadata); err != nil {
		return err
	}
	key := item.Basis.TenantID + "\x00" + item.ID
	record := m.work[key]
	record.Item = item
	m.work[key] = record
	return nil
}

func (m *memoryRuntime) ProjectRemediationReopen(ctx context.Context, metadata ProjectionMetadata, plan complianceassessment.RemediationPlan, _ complianceassessment.RemediationReopenRecord) error {
	return m.ProjectRemediationPlan(ctx, metadata, plan)
}

func (m *memoryRuntime) ProjectRemediationPlan(_ context.Context, metadata ProjectionMetadata, plan complianceassessment.RemediationPlan) error {
	if err := m.beforeProject(metadata); err != nil {
		return err
	}
	m.plans[plan.TenantID+"\x00"+plan.ID] = plan
	return nil
}

func (m *memoryRuntime) beforeProject(metadata ProjectionMetadata) error {
	if m.failProjection {
		return errors.New("projection unavailable")
	}
	if _, ok := m.receipts[metadata.EventID]; ok {
		return nil
	}
	m.receipts[metadata.EventID] = struct{}{}
	return nil
}

func (m *memoryRuntime) resetProjections() {
	m.work = map[string]WorkItemRecord{}
	m.plans = map[string]complianceassessment.RemediationPlan{}
	m.receipts = map[string]struct{}{}
}

func (m *memoryRuntime) String() string {
	return fmt.Sprintf("events=%d work=%d plans=%d", len(m.events), len(m.work), len(m.plans))
}
