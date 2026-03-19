package runtime

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/actionengine"
)

type noopActionHandler struct{}

func (noopActionHandler) KillProcess(ctx context.Context, resourceID string, pid int) error {
	return nil
}

func (noopActionHandler) IsolateContainer(ctx context.Context, containerID, namespace string) error {
	return nil
}

func (noopActionHandler) IsolateHost(ctx context.Context, resourceID, reason string) error {
	return nil
}

func (noopActionHandler) QuarantineFile(ctx context.Context, filePath, reason string) error {
	return nil
}

func (noopActionHandler) BlockIP(ctx context.Context, ip string) error {
	return nil
}

func (noopActionHandler) BlockDomain(ctx context.Context, domain string) error {
	return nil
}

func (noopActionHandler) RevokeCredentials(ctx context.Context, principalID, provider string) error {
	return nil
}

func (noopActionHandler) ScaleDown(ctx context.Context, resourceID string, replicas int) error {
	return nil
}

type recordingActionHandler struct {
	blockedIPs []string
}

func (h *recordingActionHandler) KillProcess(ctx context.Context, resourceID string, pid int) error {
	return nil
}

func (h *recordingActionHandler) IsolateContainer(ctx context.Context, containerID, namespace string) error {
	return nil
}

func (h *recordingActionHandler) IsolateHost(ctx context.Context, resourceID, reason string) error {
	return nil
}

func (h *recordingActionHandler) QuarantineFile(ctx context.Context, filePath, reason string) error {
	return nil
}

func (h *recordingActionHandler) BlockIP(ctx context.Context, ip string) error {
	h.blockedIPs = append(h.blockedIPs, ip)
	return nil
}

func (h *recordingActionHandler) BlockDomain(ctx context.Context, domain string) error {
	return nil
}

func (h *recordingActionHandler) RevokeCredentials(ctx context.Context, principalID, provider string) error {
	return nil
}

func (h *recordingActionHandler) ScaleDown(ctx context.Context, resourceID string, replicas int) error {
	return nil
}

type blockingActionHandler struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *blockingActionHandler) KillProcess(ctx context.Context, resourceID string, pid int) error {
	return nil
}

func (h *blockingActionHandler) IsolateContainer(ctx context.Context, containerID, namespace string) error {
	return nil
}

func (h *blockingActionHandler) IsolateHost(ctx context.Context, resourceID, reason string) error {
	return nil
}

func (h *blockingActionHandler) QuarantineFile(ctx context.Context, filePath, reason string) error {
	return nil
}

func (h *blockingActionHandler) BlockIP(ctx context.Context, ip string) error {
	h.once.Do(func() {
		close(h.started)
	})
	select {
	case <-h.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *blockingActionHandler) BlockDomain(ctx context.Context, domain string) error {
	return nil
}

func (h *blockingActionHandler) RevokeCredentials(ctx context.Context, principalID, provider string) error {
	return nil
}

func (h *blockingActionHandler) ScaleDown(ctx context.Context, resourceID string, replicas int) error {
	return nil
}

func TestExecuteActionUnsupportedType(t *testing.T) {
	engine := NewResponseEngine()
	engine.SetActionHandler(noopActionHandler{})

	err := engine.executeAction(context.Background(), PolicyAction{Type: ResponseActionType("unknown_action")}, &RuntimeFinding{})
	if err == nil {
		t.Fatal("expected error")
	}

	var actionErr *ResponseActionError
	if !errors.As(err, &actionErr) {
		t.Fatalf("expected ResponseActionError, got %T", err)
	}
	if actionErr.Code != "unsupported_action" {
		t.Errorf("expected code unsupported_action, got %s", actionErr.Code)
	}
	if len(actionErr.SupportedActions) == 0 {
		t.Errorf("expected supported actions to be populated")
	}
}

func TestProcessFindingDerivesTrustedActuationScope(t *testing.T) {
	engine := NewResponseEngine()
	engine.SetActionHandler(NewDefaultActionHandler(DefaultActionHandlerOptions{
		Blocklist: engine.Blocklist(),
	}))
	engine.policies = map[string]*ResponsePolicy{
		"auto-block-ip": {
			ID:      "auto-block-ip",
			Name:    "Auto Block IP",
			Enabled: true,
			Triggers: []PolicyTrigger{
				{Type: "finding", Category: CategoryReverseShell, Severity: "high"},
			},
			Actions: []PolicyAction{
				{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}},
			},
		},
	}

	execution, err := engine.ProcessFinding(context.Background(), &RuntimeFinding{
		ID:           "finding-auto-scope",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "event-auto-scope",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: "203.0.113.10",
			},
		},
	})
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil {
		t.Fatal("expected execution")
	}
	if execution.Status != StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, StatusCompleted)
	}
	if !engine.Blocklist().IsBlocked("203.0.113.10", "ip") {
		t.Fatal("expected destination IP to be added to blocklist")
	}
}

func TestApproveExecutionReusesStoredFindingContext(t *testing.T) {
	engine := NewResponseEngine()
	handler := &recordingActionHandler{}
	engine.SetActionHandler(handler)
	engine.policies = map[string]*ResponsePolicy{
		"approve-block-ip": {
			ID:              "approve-block-ip",
			Name:            "Approve Block IP",
			Enabled:         true,
			RequireApproval: true,
			Triggers: []PolicyTrigger{
				{Type: "finding", Category: CategoryReverseShell, Severity: "high"},
			},
			Actions: []PolicyAction{
				{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}},
			},
		},
	}

	finding := &RuntimeFinding{
		ID:           "finding-1",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "event-1",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: "203.0.113.10",
			},
		},
	}

	execution, err := engine.ProcessFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil {
		t.Fatal("expected execution")
	}
	if execution.Status != StatusApproval {
		t.Fatalf("status = %s, want %s", execution.Status, StatusApproval)
	}
	if execution.TriggerData == nil {
		t.Fatal("expected trigger data to be captured")
	}

	if err := engine.ApproveExecution(context.Background(), execution.ID, "alice"); err != nil {
		t.Fatalf("ApproveExecution: %v", err)
	}
	if execution.Status != StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, StatusCompleted)
	}
	if len(handler.blockedIPs) != 1 || handler.blockedIPs[0] != "203.0.113.10" {
		t.Fatalf("blocked IPs = %v, want [203.0.113.10]", handler.blockedIPs)
	}
}

func TestApproveExecutionDerivesTrustedActuationScope(t *testing.T) {
	engine := NewResponseEngine()
	engine.SetActionHandler(NewDefaultActionHandler(DefaultActionHandlerOptions{
		Blocklist: engine.Blocklist(),
	}))
	engine.policies = map[string]*ResponsePolicy{
		"approve-block-ip": {
			ID:              "approve-block-ip",
			Name:            "Approve Block IP",
			Enabled:         true,
			RequireApproval: true,
			Triggers: []PolicyTrigger{
				{Type: "finding", Category: CategoryReverseShell, Severity: "high"},
			},
			Actions: []PolicyAction{
				{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}},
			},
		},
	}

	execution, err := engine.ProcessFinding(context.Background(), &RuntimeFinding{
		ID:           "finding-approve-scope",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "event-approve-scope",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: "203.0.113.11",
			},
		},
	})
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil {
		t.Fatal("expected execution")
	}
	if execution.Status != StatusApproval {
		t.Fatalf("status = %s, want %s", execution.Status, StatusApproval)
	}

	if err := engine.ApproveExecution(context.Background(), execution.ID, "alice"); err != nil {
		t.Fatalf("ApproveExecution: %v", err)
	}
	if execution.Status != StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, StatusCompleted)
	}
	if !engine.Blocklist().IsBlocked("203.0.113.11", "ip") {
		t.Fatal("expected approved execution to block the destination IP")
	}
}

func TestCreatePolicyRejectsInvalidScaleDownReplicas(t *testing.T) {
	engine := NewResponseEngine()
	err := engine.CreatePolicy(&ResponsePolicy{
		ID:      "invalid-scale-down",
		Name:    "Invalid Scale Down",
		Enabled: true,
		Actions: []PolicyAction{{Type: ActionScaleDown, Parameters: map[string]string{"replicas": "invalid"}}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() == "" {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestApproveExecutionDoesNotHoldEngineLock(t *testing.T) {
	engine := NewResponseEngine()
	handler := &blockingActionHandler{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	engine.SetActionHandler(handler)
	engine.policies = map[string]*ResponsePolicy{
		"approve-block-ip": {
			ID:              "approve-block-ip",
			Name:            "Approve Block IP",
			Enabled:         true,
			RequireApproval: true,
			Triggers: []PolicyTrigger{
				{Type: "finding", Category: CategoryReverseShell, Severity: "high"},
			},
			Actions: []PolicyAction{
				{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}},
			},
		},
	}

	finding := &RuntimeFinding{
		ID:           "finding-lock-test",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "event-lock-test",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: "203.0.113.10",
			},
		},
	}

	execution, err := engine.ProcessFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil {
		t.Fatal("expected execution")
	}

	approveDone := make(chan error, 1)
	go func() {
		approveDone <- engine.ApproveExecution(context.Background(), execution.ID, "alice")
	}()

	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("approval execution never started")
	}

	listDone := make(chan struct{})
	go func() {
		_ = engine.ListPolicies()
		close(listDone)
	}()

	select {
	case <-listDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("ListPolicies blocked while approval action was running")
	}

	close(handler.release)

	select {
	case err := <-approveDone:
		if err != nil {
			t.Fatalf("ApproveExecution: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ApproveExecution did not finish")
	}
}

func TestRejectExecutionFailsOnceApprovalIsRunning(t *testing.T) {
	engine := NewResponseEngine()
	handler := &blockingActionHandler{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	engine.SetActionHandler(handler)
	engine.policies = map[string]*ResponsePolicy{
		"approve-block-ip": {
			ID:              "approve-block-ip",
			Name:            "Approve Block IP",
			Enabled:         true,
			RequireApproval: true,
			Triggers: []PolicyTrigger{
				{Type: "finding", Category: CategoryReverseShell, Severity: "high"},
			},
			Actions: []PolicyAction{
				{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}},
			},
		},
	}

	finding := &RuntimeFinding{
		ID:           "finding-reject-race",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "event-reject-race",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: "203.0.113.10",
			},
		},
	}

	execution, err := engine.ProcessFinding(context.Background(), finding)
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil {
		t.Fatal("expected execution")
	}

	approveDone := make(chan error, 1)
	go func() {
		approveDone <- engine.ApproveExecution(context.Background(), execution.ID, "alice")
	}()

	select {
	case <-handler.started:
	case <-time.After(2 * time.Second):
		t.Fatal("approval execution never started")
	}

	if err := engine.RejectExecution(execution.ID, "bob", "too late"); err == nil {
		t.Fatal("expected rejection to fail once approval is already running")
	}

	close(handler.release)

	select {
	case err := <-approveDone:
		if err != nil {
			t.Fatalf("ApproveExecution: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ApproveExecution did not finish")
	}

	if execution.Status != StatusCompleted {
		t.Fatalf("status = %s, want %s", execution.Status, StatusCompleted)
	}
}

func TestProcessFindingRespectsPolicyScope(t *testing.T) {
	engine := NewResponseEngine()
	engine.SetActionHandler(noopActionHandler{})
	engine.policies = map[string]*ResponsePolicy{
		"scoped-alert": {
			ID:      "scoped-alert",
			Name:    "Scoped Alert",
			Enabled: true,
			Triggers: []PolicyTrigger{{
				Type:     "finding",
				Category: CategoryReverseShell,
				Severity: "high",
			}},
			Scope: PolicyScope{
				Clusters:   []string{"prod-cluster"},
				Namespaces: []string{"payments"},
				Accounts:   []string{"123456789012"},
				Regions:    []string{"us-east-1"},
				Tags:       map[string]string{"env": "prod", "team": "payments"},
			},
			Actions: []PolicyAction{{Type: ActionAlert}},
		},
	}

	matching, err := engine.ProcessFinding(context.Background(), &RuntimeFinding{
		ID:           "finding-scope-match",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{Metadata: map[string]any{
			"cluster":    "prod-cluster",
			"namespace":  "payments",
			"account_id": "123456789012",
			"region":     "us-east-1",
			"tags": map[string]any{
				"env":  "prod",
				"team": "payments",
			},
		}},
	})
	if err != nil {
		t.Fatalf("ProcessFinding match: %v", err)
	}
	if matching == nil {
		t.Fatal("expected matching finding to create an execution")
	}

	mismatched, err := engine.ProcessFinding(context.Background(), &RuntimeFinding{
		ID:           "finding-scope-miss",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-2",
		ResourceType: "pod",
		Event: &RuntimeEvent{Metadata: map[string]any{
			"cluster":    "prod-cluster",
			"namespace":  "payments",
			"account_id": "123456789012",
			"region":     "us-east-1",
			"tags": map[string]any{
				"env":  "dev",
				"team": "payments",
			},
		}},
	})
	if err != nil {
		t.Fatalf("ProcessFinding mismatch: %v", err)
	}
	if mismatched != nil {
		t.Fatalf("expected out-of-scope finding to be ignored, got %#v", mismatched)
	}
}

func TestResponseEngineListsAndApprovesPersistedExecutionsAfterRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "runtime-executions.db")
	store, err := actionengine.NewSQLiteStore(dbPath, actionengine.DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	engine := NewResponseEngine()
	engine.policies = map[string]*ResponsePolicy{}
	engine.SetSharedExecutor(actionengine.NewExecutor(store))
	engine.SetActionHandler(noopActionHandler{})
	if err := engine.CreatePolicy(&ResponsePolicy{
		ID:              "persisted-runtime-policy",
		Name:            "Persisted Runtime Policy",
		Enabled:         true,
		RequireApproval: true,
		Triggers: []PolicyTrigger{{
			Type:     "finding",
			Category: CategoryReverseShell,
			Severity: "high",
		}},
		Actions: []PolicyAction{{Type: ActionBlockIP, Parameters: map[string]string{"target": "destination"}}},
	}); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	execution, err := engine.ProcessFinding(context.Background(), &RuntimeFinding{
		ID:           "persisted-runtime-finding",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "persisted-runtime-event",
			ResourceID:   "pod-1",
			ResourceType: "pod",
			Network: &NetworkEvent{
				SrcIP: "10.0.0.5",
				DstIP: "203.0.113.55",
			},
		},
	})
	if err != nil {
		t.Fatalf("ProcessFinding: %v", err)
	}
	if execution == nil || execution.Status != StatusApproval {
		t.Fatalf("expected awaiting approval execution, got %#v", execution)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close store: %v", err)
	}

	restartedStore, err := actionengine.NewSQLiteStore(dbPath, actionengine.DefaultNamespace)
	if err != nil {
		t.Fatalf("NewSQLiteStore restart: %v", err)
	}
	defer func() { _ = restartedStore.Close() }()
	restarted := NewResponseEngine()
	restarted.SetSharedExecutor(actionengine.NewExecutor(restartedStore))
	handler := &recordingActionHandler{}
	restarted.SetActionHandler(handler)

	listed := restarted.ListExecutions(10)
	if len(listed) != 1 || listed[0].ID != execution.ID {
		t.Fatalf("expected persisted execution to be listed after restart, got %#v", listed)
	}
	if listed[0].Status != StatusApproval {
		t.Fatalf("expected persisted execution status awaiting approval, got %#v", listed[0].Status)
	}

	if err := restarted.ApproveExecution(context.Background(), execution.ID, "alice"); err != nil {
		t.Fatalf("ApproveExecution after restart: %v", err)
	}
	if len(handler.blockedIPs) != 1 || handler.blockedIPs[0] != "203.0.113.55" {
		t.Fatalf("blocked IPs after restart approval = %v, want [203.0.113.55]", handler.blockedIPs)
	}
}

func TestDefaultContainmentPoliciesRequireApproval(t *testing.T) {
	engine := NewResponseEngine()
	policies := engine.ListPolicies()
	requireApproval := map[string]bool{}
	for _, policy := range policies {
		requireApproval[policy.ID] = policy.RequireApproval
	}

	for _, policyID := range []string{
		"auto-kill-crypto-miner",
		"auto-isolate-container-escape",
		"auto-kill-reverse-shell",
	} {
		if !requireApproval[policyID] {
			t.Fatalf("policy %s should require approval", policyID)
		}
	}
}
