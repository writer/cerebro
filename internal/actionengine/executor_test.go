package actionengine

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

type fakeRunner struct {
	calls []string
	fail  map[string]error
}

func (r *fakeRunner) RunStep(_ context.Context, step Step, _ Signal, _ *Execution) (string, error) {
	r.calls = append(r.calls, step.Type)
	if err := r.fail[step.Type]; err != nil {
		return "", err
	}
	return step.Type + ":ok", nil
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
