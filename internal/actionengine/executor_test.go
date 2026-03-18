package actionengine

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

type fakeRunner struct {
	calls  []string
	fail   map[string]error
	before func(step Step, execution *Execution)
}

func (r *fakeRunner) RunStep(_ context.Context, step Step, _ Signal, execution *Execution) (string, error) {
	r.calls = append(r.calls, step.Type)
	if r.before != nil {
		r.before(step, execution)
	}
	if err := r.fail[step.Type]; err != nil {
		return "", err
	}
	return step.Type + ":ok", nil
}

func TestNewExecutionPersistsSubmittedWithoutStartedAt(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"), DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	executor := NewExecutor(store)
	execution := executor.NewExecution(Playbook{ID: "playbook-1", Name: "Queued Playbook"}, Signal{
		ID:        "sig-queued",
		Kind:      "finding.created",
		CreatedAt: time.Now().UTC(),
	})

	if execution.SubmittedAt.IsZero() {
		t.Fatal("expected submitted_at to be set")
	}
	if !execution.StartedAt.IsZero() {
		t.Fatalf("started_at = %v, want zero", execution.StartedAt)
	}

	env, err := store.store.LoadRun(context.Background(), DefaultNamespace, execution.ID)
	if err != nil {
		t.Fatalf("LoadRun: %v", err)
	}
	if env == nil {
		t.Fatal("expected persisted run envelope")
		return
	}
	if env.StartedAt != nil {
		t.Fatalf("envelope started_at = %v, want nil", env.StartedAt)
	}
	if env.SubmittedAt.IsZero() {
		t.Fatal("expected envelope submitted_at to be set")
	}

	loaded, err := store.LoadExecution(context.Background(), execution.ID)
	if err != nil {
		t.Fatalf("LoadExecution: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected persisted execution payload")
		return
	}
	if loaded.SubmittedAt.IsZero() {
		t.Fatal("expected persisted submitted_at")
	}
	if !loaded.StartedAt.IsZero() {
		t.Fatalf("persisted started_at = %v, want zero", loaded.StartedAt)
	}
}

func TestExecutorApprovalFlowAndStorePersistence(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"), DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	executor := NewExecutor(store)
	playbook := Playbook{
		ID:              "playbook-1",
		Name:            "Approval Playbook",
		Enabled:         true,
		RequireApproval: true,
		Steps: []Step{
			{ID: "step-1", Type: "notify", OnFailure: FailurePolicyAbort},
			{ID: "step-2", Type: "ticket", OnFailure: FailurePolicyAbort},
		},
	}
	signal := Signal{
		ID:           "sig-1",
		Kind:         "finding.created",
		ResourceID:   "asset-1",
		ResourceType: "bucket",
		Data: map[string]any{
			"finding_id": "finding-1",
		},
		CreatedAt: time.Now().UTC(),
	}
	runner := &fakeRunner{}

	execution := executor.NewExecution(playbook, signal)
	if err := executor.Execute(context.Background(), execution, playbook, signal, runner); err != nil {
		t.Fatalf("Execute awaiting approval: %v", err)
	}
	if execution.Status != StatusAwaitingApproval {
		t.Fatalf("status = %s, want %s", execution.Status, StatusAwaitingApproval)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no calls before approval, got %v", runner.calls)
	}

	if err := executor.Approve(context.Background(), execution, "alice", playbook, signal, runner); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if execution.Status != StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, StatusCompleted)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("runner calls = %v, want 2 calls", runner.calls)
	}

	loaded, err := store.LoadExecution(context.Background(), execution.ID)
	if err != nil {
		t.Fatalf("LoadExecution: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected persisted execution")
		return
	}
	if loaded.Status != StatusCompleted {
		t.Fatalf("persisted status = %s, want %s", loaded.Status, StatusCompleted)
	}

	events, err := store.LoadEvents(context.Background(), execution.ID)
	if err != nil {
		t.Fatalf("LoadEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected persisted action-engine events")
	}
}

func TestExecutorContinueOnFailureKeepsExecutionRunningUntilCompletion(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"), DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	executor := NewExecutor(store)
	playbook := Playbook{
		ID:      "playbook-continue",
		Name:    "Continue On Failure",
		Enabled: true,
		Steps: []Step{
			{ID: "step-1", Type: "notify", OnFailure: FailurePolicyContinue},
			{ID: "step-2", Type: "ticket", OnFailure: FailurePolicyAbort},
		},
	}
	signal := Signal{ID: "sig-continue", Kind: "finding.created", CreatedAt: time.Now().UTC()}
	var executionID string
	runner := &fakeRunner{
		fail: map[string]error{"notify": fmt.Errorf("notify failed")},
		before: func(step Step, execution *Execution) {
			if step.Type != "ticket" {
				return
			}
			loaded, err := store.LoadExecution(context.Background(), execution.ID)
			if err != nil {
				t.Fatalf("LoadExecution during continue: %v", err)
			}
			if loaded == nil {
				t.Fatal("expected persisted execution during continue")
				return
			}
			if loaded.Status != StatusRunning {
				t.Fatalf("persisted status during continue = %s, want %s", loaded.Status, StatusRunning)
			}
			if loaded.CompletedAt != nil {
				t.Fatalf("persisted completed_at during continue = %v, want nil", loaded.CompletedAt)
			}
			if len(loaded.Results) != 1 || loaded.Results[0].Status != StatusFailed {
				t.Fatalf("persisted results during continue = %#v, want one failed result", loaded.Results)
			}
		},
	}

	execution := executor.NewExecution(playbook, signal)
	executionID = execution.ID
	if err := executor.Execute(context.Background(), execution, playbook, signal, runner); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if execution.ID != executionID {
		t.Fatalf("execution id changed: %s vs %s", execution.ID, executionID)
	}
	if execution.Status != StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, StatusCompleted)
	}
	if execution.CompletedAt == nil {
		t.Fatal("expected completed_at after continue-on-failure run")
	}
	if len(execution.Results) != 2 {
		t.Fatalf("results = %#v, want two step results", execution.Results)
	}
	if execution.Results[0].Status != StatusFailed || execution.Results[1].Status != StatusCompleted {
		t.Fatalf("unexpected result statuses: %#v", execution.Results)
	}
}

func TestPlaybookMatchesSignalSeverityModes(t *testing.T) {
	signal := Signal{Kind: "finding", Severity: "critical"}
	exact := Playbook{
		Enabled: true,
		Triggers: []Trigger{{
			Kind:              "finding",
			Severity:          "high",
			SeverityMatchMode: SeverityMatchExact,
		}},
	}
	if PlaybookMatchesSignal(exact, signal) {
		t.Fatal("expected exact severity playbook not to match")
	}

	minimum := Playbook{
		Enabled: true,
		Triggers: []Trigger{{
			Kind:              "finding",
			Severity:          "high",
			SeverityMatchMode: SeverityMatchMinimum,
		}},
	}
	if !PlaybookMatchesSignal(minimum, signal) {
		t.Fatal("expected minimum severity playbook to match")
	}
}
