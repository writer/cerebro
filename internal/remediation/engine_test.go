package remediation

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/testutil"
)

func TestEngine_NewEngine(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}

	rules := engine.ListRules()
	if len(rules) == 0 {
		t.Error("expected default rules to be loaded")
	}
}

func TestEngine_ListRules(t *testing.T) {
	engine := NewEngine(testutil.Logger())
	rules := engine.ListRules()

	// Verify default rules exist
	ruleIDs := make(map[string]bool)
	for _, r := range rules {
		ruleIDs[r.ID] = true
	}

	expectedRules := []string{
		"auto-ticket-critical",
		"pagerduty-critical",
		"auto-ticket-high",
		"s3-public-notify",
		"identity-stale-user-remediation",
		"identity-excessive-privilege-remediation",
		"dspm-restricted-data-unencrypted-remediation",
		"dspm-confidential-data-public-remediation",
	}

	for _, id := range expectedRules {
		if !ruleIDs[id] {
			t.Errorf("expected rule %s to be loaded", id)
		}
	}
}

func TestEngine_GetRule(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	// Get existing rule
	rule, ok := engine.GetRule("auto-ticket-critical")
	if !ok {
		t.Error("expected to find auto-ticket-critical rule")
	}

	if rule.Name == "" {
		t.Error("rule name should not be empty")
	}

	if !rule.Enabled {
		t.Error("default rule should be enabled")
	}

	// Get non-existent rule
	_, ok = engine.GetRule("non-existent")
	if ok {
		t.Error("expected not to find non-existent rule")
	}
}

func TestEngine_EnableDisableRule(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	// Disable rule
	err := engine.DisableRule("auto-ticket-critical")
	if err != nil {
		t.Fatalf("DisableRule failed: %v", err)
	}

	rule, _ := engine.GetRule("auto-ticket-critical")
	if rule.Enabled {
		t.Error("rule should be disabled")
	}

	// Enable rule
	err = engine.EnableRule("auto-ticket-critical")
	if err != nil {
		t.Fatalf("EnableRule failed: %v", err)
	}

	rule, _ = engine.GetRule("auto-ticket-critical")
	if !rule.Enabled {
		t.Error("rule should be enabled")
	}

	// Disable non-existent rule
	err = engine.DisableRule("non-existent")
	if err == nil {
		t.Error("expected error for non-existent rule")
	}
}

func TestEngine_AddRule(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	rule := Rule{
		ID:          "test-rule",
		Name:        "Test Rule",
		Description: "A test rule",
		Enabled:     true,
		Trigger: Trigger{
			Type:     TriggerFindingCreated,
			Severity: "high",
		},
		Actions: []Action{
			{
				Type:   ActionNotifySlack,
				Config: map[string]string{"channel": "#test"},
			},
		},
	}

	err := engine.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Verify rule was created
	found, ok := engine.GetRule("test-rule")
	if !ok {
		t.Error("expected to find created rule")
	}

	if found.Name != "Test Rule" {
		t.Errorf("got name %s, want Test Rule", found.Name)
	}
}

func TestEngine_UpdateAndDeleteRule(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	err := engine.AddRule(Rule{
		ID:      "updatable-rule",
		Name:    "Original",
		Enabled: true,
		Trigger: Trigger{
			Type: TriggerFindingCreated,
		},
		Actions: []Action{{Type: ActionCreateTicket}},
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	err = engine.UpdateRule("updatable-rule", Rule{
		Name:    "Updated",
		Enabled: false,
		Trigger: Trigger{
			Type:     TriggerFindingCreated,
			Severity: "critical",
		},
		Actions: []Action{{Type: ActionNotifySlack, Config: map[string]string{"channel": "#security"}}},
	})
	if err != nil {
		t.Fatalf("UpdateRule failed: %v", err)
	}

	got, ok := engine.GetRule("updatable-rule")
	if !ok {
		t.Fatal("expected updated rule to exist")
	}
	if got.Name != "Updated" {
		t.Fatalf("expected updated name, got %s", got.Name)
	}
	if got.Enabled {
		t.Fatal("expected updated rule to be disabled")
	}
	if got.ID != "updatable-rule" {
		t.Fatalf("expected rule ID to remain updatable-rule, got %s", got.ID)
	}
	if len(got.Actions) != 1 || got.Actions[0].Type != ActionNotifySlack {
		t.Fatalf("expected updated actions to be applied, got %+v", got.Actions)
	}

	if err := engine.UpdateRule("missing-rule", Rule{Name: "Missing"}); err == nil {
		t.Fatal("expected update on missing rule to fail")
	}

	if err := engine.DeleteRule("updatable-rule"); err != nil {
		t.Fatalf("DeleteRule failed: %v", err)
	}
	if _, ok := engine.GetRule("updatable-rule"); ok {
		t.Fatal("expected deleted rule to be absent")
	}
	if err := engine.DeleteRule("updatable-rule"); err == nil {
		t.Fatal("expected second delete on missing rule to fail")
	}
}

func TestEngine_RuleWithActions(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	rule := Rule{
		ID:      "multi-action",
		Name:    "Multi Action Rule",
		Enabled: true,
		Trigger: Trigger{
			Type:     TriggerFindingCreated,
			Severity: "critical",
		},
		Actions: []Action{
			{Type: ActionCreateTicket, Config: map[string]string{"priority": "high"}},
			{Type: ActionNotifySlack, Config: map[string]string{"channel": "#alerts"}},
			{Type: ActionNotifyPagerDuty, Config: map[string]string{}},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	found, ok := engine.GetRule("multi-action")
	if !ok {
		t.Fatal("expected to find rule")
	}

	if len(found.Actions) != 3 {
		t.Errorf("expected 3 actions, got %d", len(found.Actions))
	}
}

func TestEngine_Evaluate(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	tests := []struct {
		name      string
		event     Event
		wantMatch bool
	}{
		{
			name: "critical finding matches critical rules",
			event: Event{
				Type:      TriggerFindingCreated,
				Severity:  "critical",
				FindingID: "test-123",
			},
			wantMatch: true,
		},
		{
			name: "high finding matches high rules",
			event: Event{
				Type:      TriggerFindingCreated,
				Severity:  "high",
				FindingID: "test-456",
			},
			wantMatch: true,
		},
		{
			name: "low finding no match",
			event: Event{
				Type:      TriggerFindingCreated,
				Severity:  "low",
				FindingID: "test-789",
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executions, err := engine.Evaluate(context.Background(), tt.event)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if tt.wantMatch && len(executions) == 0 {
				t.Error("expected executions but got none")
			}
			if !tt.wantMatch && len(executions) > 0 {
				t.Errorf("expected no executions but got %d", len(executions))
			}
		})
	}
}

func TestEngine_EvaluateCreatesExecution(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	event := Event{
		Type:      TriggerFindingCreated,
		Severity:  "critical",
		FindingID: "test-finding-123",
	}

	executions, err := engine.Evaluate(context.Background(), event)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(executions) == 0 {
		t.Fatal("expected at least one execution")
	}

	exec := executions[0]
	if exec.ID == "" {
		t.Error("execution ID should be generated")
	}

	if exec.Status != ExecutionPending {
		t.Errorf("unexpected status: %s", exec.Status)
	}

	if exec.TriggerData["finding_id"] != "test-finding-123" {
		t.Error("trigger data should contain finding_id")
	}
}

func TestEngine_GetExecution(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	event := Event{
		Type:      TriggerFindingCreated,
		Severity:  "critical",
		FindingID: "test-123",
	}

	executions, _ := engine.Evaluate(context.Background(), event)
	if len(executions) == 0 {
		t.Skip("no executions created")
	}

	exec := executions[0]

	// Get existing execution
	found, ok := engine.GetExecution(exec.ID)
	if !ok {
		t.Error("expected to find execution")
	}

	if found.ID != exec.ID {
		t.Errorf("got ID %s, want %s", found.ID, exec.ID)
	}

	// Get non-existent execution
	_, ok = engine.GetExecution("non-existent")
	if ok {
		t.Error("expected not to find non-existent execution")
	}
}

func TestEngine_ListExecutions(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	// Create multiple executions via Evaluate
	for i := 0; i < 5; i++ {
		event := Event{
			Type:      TriggerFindingCreated,
			Severity:  "critical",
			FindingID: "test-" + string(rune('0'+i)),
		}
		if _, err := engine.Evaluate(context.Background(), event); err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
	}

	executions := engine.ListExecutions(10)
	if len(executions) < 5 {
		t.Errorf("expected at least 5 executions, got %d", len(executions))
	}
}

func TestExecution_Status(t *testing.T) {
	statuses := []ExecutionStatus{
		ExecutionPending,
		ExecutionRunning,
		ExecutionApproval,
		ExecutionCompleted,
		ExecutionFailed,
		ExecutionCancelled,
	}

	for _, s := range statuses {
		if s == "" {
			t.Error("status should not be empty")
		}
	}
}

func TestTriggerType(t *testing.T) {
	triggers := []TriggerType{
		TriggerFindingCreated,
		TriggerFindingOpen,
		TriggerSignalCreated,
		TriggerSchedule,
		TriggerManual,
	}

	for _, tr := range triggers {
		if tr == "" {
			t.Error("trigger type should not be empty")
		}
	}
}

func TestActionType(t *testing.T) {
	actions := []ActionType{
		ActionCreateTicket,
		ActionNotifySlack,
		ActionNotifyPagerDuty,
		ActionResolveFinding,
		ActionRunWebhook,
		ActionTagResource,
		ActionUpdateCRMField,
		ActionTriggerWorkflow,
		ActionCreateReview,
		ActionEscalateToOwner,
		ActionPauseSubscription,
		ActionSendCustomerComm,
	}

	for _, a := range actions {
		if a == "" {
			t.Error("action type should not be empty")
		}
	}
}

func TestEngine_EvaluateSignalRuleWithConditions(t *testing.T) {
	engine := NewEngine(testutil.Logger())

	event := Event{
		Type:       TriggerSignalCreated,
		Severity:   "critical",
		PolicyID:   "hubspot-stale-deal",
		Domain:     "customer_health",
		SignalType: "business",
		Data: map[string]any{
			"domain": "customer_health",
		},
	}

	executions, err := engine.Evaluate(context.Background(), event)
	if err != nil {
		t.Fatalf("evaluate failed: %v", err)
	}
	if len(executions) == 0 {
		t.Fatal("expected signal executions for customer health critical signal")
	}
}
