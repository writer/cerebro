package remediation

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/testutil"
	"github.com/writer/cerebro/internal/webhooks"
)

type fakeNotificationSender struct {
	events []notifications.Event
}

func (f *fakeNotificationSender) Send(_ context.Context, event notifications.Event) error {
	f.events = append(f.events, event)
	return nil
}

type fakeEventPublisher struct {
	eventTypes []webhooks.EventType
}

func (f *fakeEventPublisher) EmitWithErrors(_ context.Context, eventType webhooks.EventType, _ map[string]interface{}) error {
	f.eventTypes = append(f.eventTypes, eventType)
	return nil
}

type fakeFindingsWriter struct {
	resolved []string
}

func (f *fakeFindingsWriter) Resolve(id string) bool {
	f.resolved = append(f.resolved, id)
	return true
}

func TestExecutorUsesNotificationSenderInterface(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	if err := engine.AddRule(Rule{
		ID:      "notify",
		Name:    "Notify",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{Type: ActionNotifySlack}},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type: TriggerManual,
		Data: map[string]interface{}{"finding_id": "finding-1", "severity": "high"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	notifier := &fakeNotificationSender{}
	executor := NewExecutor(engine, nil, notifier, nil, nil)
	if err := executor.Execute(context.Background(), executions[0]); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("sent events = %d, want 1", len(notifier.events))
	}
}

func TestExecutorUsesEventPublisherInterfaceForApprovals(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	if err := engine.AddRule(Rule{
		ID:      "approval",
		Name:    "Approval",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{Type: ActionNotifySlack, RequiresApproval: true}},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{Type: TriggerManual})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	publisher := &fakeEventPublisher{}
	executor := NewExecutor(engine, nil, nil, nil, publisher)
	if err := executor.Execute(context.Background(), executions[0]); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(publisher.eventTypes) != 1 || publisher.eventTypes[0] != webhooks.EventApprovalRequested {
		t.Fatalf("unexpected approval events: %+v", publisher.eventTypes)
	}
}

func TestExecutorUsesFindingsWriterInterface(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	if err := engine.AddRule(Rule{
		ID:      "resolve",
		Name:    "Resolve",
		Enabled: true,
		Trigger: Trigger{Type: TriggerManual},
		Actions: []Action{{Type: ActionResolveFinding}},
	}); err != nil {
		t.Fatalf("add rule: %v", err)
	}

	executions, err := engine.Evaluate(context.Background(), Event{
		Type: TriggerManual,
		Data: map[string]interface{}{"finding_id": "finding-1"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	executions[0].TriggerData = map[string]interface{}{"finding_id": "finding-1"}

	writer := &fakeFindingsWriter{}
	executor := NewExecutor(engine, nil, nil, writer, nil)
	if err := executor.Execute(context.Background(), executions[0]); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(writer.resolved) != 1 || writer.resolved[0] != "finding-1" {
		t.Fatalf("resolved findings = %+v", writer.resolved)
	}
}
