package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/webhooks"
)

type fakeRemoteCallResult struct {
	output string
	err    error
}

type fakeRemoteCaller struct {
	calls     []string
	responses map[string][]fakeRemoteCallResult
}

func (f *fakeRemoteCaller) CallTool(_ context.Context, toolName string, _ json.RawMessage, _ time.Duration) (string, error) {
	f.calls = append(f.calls, toolName)
	queue := f.responses[toolName]
	if len(queue) == 0 {
		return "{}", nil
	}
	next := queue[0]
	f.responses[toolName] = queue[1:]
	return next.output, next.err
}

func TestEnsembleExecutor_UpdateCRMFieldFallsBackAcrossTools(t *testing.T) {
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"hubspot.update_contact": {
				{err: fmt.Errorf("hubspot unavailable")},
				{err: fmt.Errorf("hubspot unavailable")},
			},
			"salesforce.update_record": {
				{output: `{"ok":true}`},
			},
		},
	}
	executor := NewEnsembleExecutor(caller, nil)
	executor.maxAttempts = 2
	executor.baseBackoff = time.Millisecond
	executor.maxBackoff = time.Millisecond
	executor.sleep = func(context.Context, time.Duration) error { return nil }

	err := executor.Execute(context.Background(), Action{
		Type: ActionUpdateCRMField,
		Config: map[string]string{
			"field": "customer_health",
			"value": "at_risk",
		},
	}, &Execution{
		ID:       "exec-1",
		RuleID:   "rule-1",
		RuleName: "CRM Update",
		TriggerData: map[string]any{
			"finding_id": "finding-1",
		},
	})
	if err != nil {
		t.Fatalf("expected fallback tool to succeed, got %v", err)
	}

	want := []string{
		"hubspot.update_contact",
		"hubspot.update_contact",
		"salesforce.update_record",
	}
	if len(caller.calls) != len(want) {
		t.Fatalf("expected %d calls, got %d (%v)", len(want), len(caller.calls), caller.calls)
	}
	for i, expected := range want {
		if caller.calls[i] != expected {
			t.Fatalf("call %d = %q, want %q", i, caller.calls[i], expected)
		}
	}
}

func TestEnsembleExecutor_EscalateToOwnerCallsMessageAndTaskTools(t *testing.T) {
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"slack.send_message":  {{output: `{"ok":true}`}},
			"hubspot.create_task": {{output: `{"ok":true}`}},
		},
	}
	executor := NewEnsembleExecutor(caller, nil)

	err := executor.Execute(context.Background(), Action{
		Type:   ActionEscalateToOwner,
		Config: map[string]string{},
	}, &Execution{ID: "exec-2", RuleID: "rule-2", RuleName: "Escalate", TriggerData: map[string]any{"entity_id": "customer:acme"}})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(caller.calls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d (%v)", len(caller.calls), caller.calls)
	}
	if caller.calls[0] != "slack.send_message" || caller.calls[1] != "hubspot.create_task" {
		t.Fatalf("unexpected tool call order: %v", caller.calls)
	}
}

func TestEnsembleExecutor_RetriesWithExponentialBackoff(t *testing.T) {
	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"stripe.pause_subscription": {
				{err: fmt.Errorf("transient timeout")},
				{err: fmt.Errorf("transient timeout")},
				{output: `{"ok":true}`},
			},
		},
	}
	executor := NewEnsembleExecutor(caller, nil)
	executor.maxAttempts = 3
	executor.baseBackoff = 5 * time.Millisecond
	executor.maxBackoff = 20 * time.Millisecond
	sleeps := make([]time.Duration, 0)
	executor.sleep = func(_ context.Context, d time.Duration) error {
		sleeps = append(sleeps, d)
		return nil
	}

	err := executor.Execute(context.Background(), Action{
		Type: ActionPauseSubscription,
	}, &Execution{ID: "exec-3", RuleID: "rule-3", RuleName: "Pause Subscription"})
	if err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if len(caller.calls) != 3 {
		t.Fatalf("expected 3 attempts, got %d", len(caller.calls))
	}
	if len(sleeps) != 2 || sleeps[0] != 5*time.Millisecond || sleeps[1] != 10*time.Millisecond {
		t.Fatalf("unexpected retry backoff sequence: %v", sleeps)
	}
}

func TestEnsembleExecutor_EmitsActionAuditEvents(t *testing.T) {
	hooks := webhooks.NewServiceForTesting()
	eventsSeen := make([]webhooks.EventType, 0)
	hooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		eventsSeen = append(eventsSeen, event.Type)
		return nil
	})

	caller := &fakeRemoteCaller{
		responses: map[string][]fakeRemoteCallResult{
			"stripe.pause_subscription": {{err: fmt.Errorf("permanent failure")}},
		},
	}
	executor := NewEnsembleExecutor(caller, hooks)
	executor.maxAttempts = 1

	err := executor.Execute(context.Background(), Action{Type: ActionPauseSubscription}, &Execution{ID: "exec-4", RuleID: "rule-4", RuleName: "Pause"})
	if err == nil {
		t.Fatal("expected execution failure")
	}
	if len(eventsSeen) == 0 || eventsSeen[0] != webhooks.EventRemediationActionFailed {
		t.Fatalf("expected remediation.action.failed event, got %v", eventsSeen)
	}
}
