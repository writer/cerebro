package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/notifications"
	"github.com/evalops/cerebro/internal/remediation"
	"github.com/evalops/cerebro/internal/webhooks"
)

func TestStartEventRemediation_ExecutesMatchingSignalRule(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := remediation.NewEngine(logger)
	if err := engine.AddRule(remediation.Rule{
		ID:      "signal-pause-subscription",
		Name:    "Signal Pause Subscription",
		Enabled: true,
		Trigger: remediation.Trigger{Type: remediation.TriggerSignalCreated},
		Actions: []remediation.Action{{
			Type:             remediation.ActionPauseSubscription,
			RequiresApproval: true,
		}},
	}); err != nil {
		t.Fatalf("failed to add remediation rule: %v", err)
	}

	hooks := webhooks.NewServiceForTesting()
	notifier := notifications.NewManager()

	app := &App{
		Logger:              logger,
		Webhooks:            hooks,
		Remediation:         engine,
		Notifications:       notifier,
		RemediationExecutor: remediation.NewExecutor(engine, nil, notifier, nil, hooks),
	}
	app.startEventRemediation(context.Background())

	if err := hooks.EmitWithErrors(context.Background(), webhooks.EventSignalCreated, map[string]any{
		"entity_id":   "customer-1",
		"signal_type": "signal.created",
	}); err != nil {
		t.Fatalf("emit signal event: %v", err)
	}

	executions := engine.ListExecutions(20)
	found := false
	for _, execution := range executions {
		if execution.RuleID == "signal-pause-subscription" {
			found = true
			if execution.Status != remediation.ExecutionApproval {
				t.Fatalf("expected execution status %q, got %q", remediation.ExecutionApproval, execution.Status)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected signal remediation rule to produce an execution")
	}
}

func TestStartEventRemediation_PropagationCanGateExecution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := remediation.NewEngine(logger)
	if err := engine.AddRule(remediation.Rule{
		ID:      "signal-graph-action",
		Name:    "Signal Graph Action",
		Enabled: true,
		Trigger: remediation.Trigger{Type: remediation.TriggerSignalCreated},
		Actions: []remediation.Action{{
			Type:             remediation.ActionPauseSubscription,
			RequiresApproval: true,
		}},
	}); err != nil {
		t.Fatalf("failed to add remediation rule: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{ID: "customer-1", Kind: graph.NodeKindCustomer, Name: "BigCo", Properties: map[string]any{"arr": 5000.0}})
	g.BuildIndex()

	hooks := webhooks.NewServiceForTesting()
	capture := &captureNotifier{}
	notifier := notifications.NewManager()
	notifier.AddNotifier(capture)

	app := &App{
		Logger:              logger,
		Webhooks:            hooks,
		Remediation:         engine,
		Notifications:       notifier,
		RemediationExecutor: remediation.NewExecutor(engine, nil, notifier, nil, hooks),
		SecurityGraph:       g,
		Propagation:         graph.NewPropagationEngine(g, graph.WithApprovalARRThreshold(1)),
	}
	app.startEventRemediation(context.Background())

	if err := hooks.EmitWithErrors(context.Background(), webhooks.EventSignalCreated, map[string]any{
		"entity_id": "customer-1",
	}); err != nil {
		t.Fatalf("emit signal event: %v", err)
	}

	executions := engine.ListExecutions(20)
	found := false
	for _, execution := range executions {
		if execution.RuleID == "signal-graph-action" {
			found = true
			if execution.Status != remediation.ExecutionPending {
				t.Fatalf("expected execution to remain %q when propagation gates execution, got %q", remediation.ExecutionPending, execution.Status)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected graph-action remediation execution")
	}

	if len(capture.events) == 0 {
		t.Fatal("expected propagation gating to emit review notification")
	}
	if capture.events[0].Type != notifications.EventReviewRequired {
		t.Fatalf("expected review required notification, got %q", capture.events[0].Type)
	}
}

func TestStartEventRemediation_PropagationUsesPersistedSnapshotWhenLiveGraphUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := remediation.NewEngine(logger)
	if err := engine.AddRule(remediation.Rule{
		ID:      "signal-snapshot-graph-action",
		Name:    "Signal Snapshot Graph Action",
		Enabled: true,
		Trigger: remediation.Trigger{Type: remediation.TriggerSignalCreated},
		Actions: []remediation.Action{{
			Type:             remediation.ActionPauseSubscription,
			RequiresApproval: true,
		}},
	}); err != nil {
		t.Fatalf("failed to add remediation rule: %v", err)
	}

	dir := t.TempDir()
	store, err := graph.NewGraphPersistenceStore(graph.GraphPersistenceOptions{
		LocalPath:    dir,
		MaxSnapshots: 4,
	})
	if err != nil {
		t.Fatalf("new graph persistence store: %v", err)
	}

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:         "customer-1",
		Kind:       graph.NodeKindCustomer,
		Name:       "BigCo",
		Properties: map[string]any{"arr": 2_000_000.0},
	})
	g.SetMetadata(graph.Metadata{
		BuiltAt:   time.Date(2026, 3, 19, 15, 30, 0, 0, time.UTC),
		NodeCount: 1,
	})
	if _, err := store.SaveGraph(g); err != nil {
		t.Fatalf("save graph snapshot: %v", err)
	}

	hooks := webhooks.NewServiceForTesting()
	capture := &captureNotifier{}
	notifier := notifications.NewManager()
	notifier.AddNotifier(capture)

	app := &App{
		Logger:              logger,
		Webhooks:            hooks,
		Remediation:         engine,
		Notifications:       notifier,
		RemediationExecutor: remediation.NewExecutor(engine, nil, notifier, nil, hooks),
		GraphSnapshots:      store,
	}
	app.startEventRemediation(context.Background())

	if err := hooks.EmitWithErrors(context.Background(), webhooks.EventSignalCreated, map[string]any{
		"entity_id": "customer-1",
	}); err != nil {
		t.Fatalf("emit signal event: %v", err)
	}

	executions := engine.ListExecutions(20)
	found := false
	for _, execution := range executions {
		if execution.RuleID == "signal-snapshot-graph-action" {
			found = true
			if execution.Status != remediation.ExecutionPending {
				t.Fatalf("expected execution to remain %q when persisted propagation gates execution, got %q", remediation.ExecutionPending, execution.Status)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected snapshot-backed graph-action remediation execution")
	}

	if len(capture.events) == 0 {
		t.Fatal("expected persisted propagation gating to emit review notification")
	}
	if capture.events[0].Type != notifications.EventReviewRequired {
		t.Fatalf("expected review required notification, got %q", capture.events[0].Type)
	}
}
