package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/actionengine"
	"github.com/writer/cerebro/internal/remediation"
)

type apiFakeRemoteCaller struct {
	calls []string
}

func (f *apiFakeRemoteCaller) CallTool(_ context.Context, toolName string, _ json.RawMessage, _ time.Duration) (string, error) {
	f.calls = append(f.calls, toolName)
	return `{"ok":true}`, nil
}

func TestRemediationExecutionEndpointsUseSharedStoreAfterRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "remediation-api-restart.db")
	store, err := actionengine.NewSQLiteStore(dbPath, actionengine.DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	caller := &apiFakeRemoteCaller{}
	s1 := newTestServer(t)
	s1.app.RemediationExecutor = remediation.NewExecutor(s1.app.Remediation, s1.app.Ticketing, s1.app.Notifications, s1.app.Findings, s1.app.Webhooks)
	s1.app.RemediationExecutor.SetRemoteCaller(caller)
	s1.app.RemediationExecutor.SetSharedExecutor(actionengine.NewExecutor(store))
	if err := s1.app.Remediation.AddRule(remediation.Rule{
		ID:      "persisted-remediation-api-rule",
		Name:    "Persisted Remediation API Rule",
		Enabled: true,
		Trigger: remediation.Trigger{Type: remediation.TriggerManual},
		Actions: []remediation.Action{{Type: remediation.ActionSendCustomerComm}},
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	executions, err := s1.app.Remediation.Evaluate(context.Background(), remediation.Event{
		Type: remediation.TriggerManual,
		Data: map[string]any{"finding_id": "finding-remediation-api"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(executions) != 1 {
		t.Fatalf("expected one remediation execution, got %d", len(executions))
	}
	execution := executions[0]
	if err := s1.app.RemediationExecutor.Execute(context.Background(), execution); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if execution.Status != remediation.ExecutionApproval {
		t.Fatalf("status = %s, want %s", execution.Status, remediation.ExecutionApproval)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close store: %v", err)
	}

	restartedStore, err := actionengine.NewSQLiteStore(dbPath, actionengine.DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore restart: %v", err)
	}
	defer func() { _ = restartedStore.Close() }()
	s2 := newTestServer(t)
	s2.app.RemediationExecutor = remediation.NewExecutor(s2.app.Remediation, s2.app.Ticketing, s2.app.Notifications, s2.app.Findings, s2.app.Webhooks)
	s2.app.RemediationExecutor.SetRemoteCaller(caller)
	s2.app.RemediationExecutor.SetSharedExecutor(actionengine.NewExecutor(restartedStore))

	list := do(t, s2, http.MethodGet, "/api/v1/remediation/executions?limit=10", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 for persisted remediation execution list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	items, ok := listBody["executions"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one persisted remediation execution, got %#v", listBody["executions"])
	}
	if got := items[0].(map[string]any)["id"]; got != execution.ID {
		t.Fatalf("listed remediation execution id = %#v, want %s", got, execution.ID)
	}

	get := do(t, s2, http.MethodGet, "/api/v1/remediation/executions/"+execution.ID, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("expected 200 for persisted remediation execution get, got %d: %s", get.Code, get.Body.String())
	}
	getBody := decodeJSON(t, get)
	if getBody["id"] != execution.ID {
		t.Fatalf("expected remediation execution id %s, got %#v", execution.ID, getBody["id"])
	}

	approve := do(t, s2, http.MethodPost, "/api/v1/remediation/executions/"+execution.ID+"/approve", map[string]any{"approver_id": "alice"})
	if approve.Code != http.StatusOK {
		t.Fatalf("expected 200 for persisted remediation execution approve, got %d: %s", approve.Code, approve.Body.String())
	}
	if len(caller.calls) == 0 {
		t.Fatal("expected persisted remediation approval to invoke a remote tool")
	}
}
