package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
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

func TestApproveExecutionUsesSnapshottedPolicyWhenPolicyMutates(t *testing.T) {
	engine := NewResponseEngine()
	handler := &recordingActionHandler{}
	engine.SetActionHandler(handler)
	engine.policies = map[string]*ResponsePolicy{
		"approve-block-ip": {
			ID:              "approve-block-ip",
			Name:            "Approve Block IP",
			Enabled:         true,
			RequireApproval: true,
			Triggers: []PolicyTrigger{{
				Type:     "finding",
				Category: CategoryReverseShell,
				Severity: "high",
			}},
			Actions: []PolicyAction{{
				Type:       ActionBlockIP,
				Parameters: map[string]string{"target": "destination"},
			}},
		},
	}

	finding := &RuntimeFinding{
		ID:           "finding-snapshot",
		RuleID:       "reverse-shell",
		Category:     CategoryReverseShell,
		Severity:     "critical",
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			ID:           "event-snapshot",
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
	snapshot := runtimeResponsePolicyFromTriggerData(execution.TriggerData)
	if snapshot == nil {
		t.Fatal("expected policy snapshot in trigger data")
	}
	if got := snapshot.Actions[0].Parameters["target"]; got != "destination" {
		t.Fatalf("snapshot target = %q, want destination", got)
	}

	engine.policies["approve-block-ip"].Actions = []PolicyAction{{
		Type:       ActionBlockIP,
		Parameters: map[string]string{"target": "source"},
	}}

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
