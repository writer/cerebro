package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type recordingRemoteCaller struct {
	tool    string
	args    map[string]any
	timeout time.Duration
}

func (r *recordingRemoteCaller) CallTool(_ context.Context, toolName string, args json.RawMessage, timeout time.Duration) (string, error) {
	r.tool = toolName
	r.timeout = timeout
	if err := json.Unmarshal(args, &r.args); err != nil {
		return "", err
	}
	return `{"ok":true}`, nil
}

type recordingScaler struct {
	target   WorkloadTarget
	replicas int32
}

func (r *recordingScaler) ScaleDown(_ context.Context, target WorkloadTarget, replicas int32) error {
	r.target = target
	r.replicas = replicas
	return nil
}

type scaleDownCapturingHandler struct {
	resourceID string
	replicas   int
}

func (h *scaleDownCapturingHandler) KillProcess(ctx context.Context, resourceID string, pid int) error {
	return nil
}

func (h *scaleDownCapturingHandler) IsolateContainer(ctx context.Context, containerID, namespace string) error {
	return nil
}

func (h *scaleDownCapturingHandler) IsolateHost(ctx context.Context, instanceID, provider string) error {
	return nil
}

func (h *scaleDownCapturingHandler) QuarantineFile(ctx context.Context, resourceID, path string) error {
	return nil
}

func (h *scaleDownCapturingHandler) BlockIP(ctx context.Context, ip string) error {
	return nil
}

func (h *scaleDownCapturingHandler) BlockDomain(ctx context.Context, domain string) error {
	return nil
}

func (h *scaleDownCapturingHandler) RevokeCredentials(ctx context.Context, principalID, provider string) error {
	return nil
}

func (h *scaleDownCapturingHandler) ScaleDown(ctx context.Context, resourceID string, replicas int) error {
	h.resourceID = resourceID
	h.replicas = replicas
	return nil
}

func TestDefaultActionHandlerBlocklistActionsAddEntries(t *testing.T) {
	blocklist := NewBlocklist()
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{
		Blocklist: blocklist,
	})
	ctx := WithTrustedActuationScope(context.Background(), TrustedActuationScope{
		AllowNetworkContainment: true,
	})

	if err := handler.BlockIP(ctx, "203.0.113.10"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := handler.BlockDomain(ctx, "evil.example"); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}

	if !blocklist.IsBlocked("203.0.113.10", "ip") {
		t.Fatal("expected IP to be added to blocklist")
	}
	if !blocklist.IsBlocked("evil.example", "domain") {
		t.Fatal("expected domain to be added to blocklist")
	}
}

func TestDefaultActionHandlerKillProcessUsesRemoteCaller(t *testing.T) {
	caller := &recordingRemoteCaller{}
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{
		RemoteCaller: caller,
	})
	ctx := WithTrustedActuationScope(context.Background(), TrustedActuationScope{
		AllowedResourceIDs: []string{"pod-1"},
	})

	if err := handler.KillProcess(ctx, "pod-1", 4242); err != nil {
		t.Fatalf("KillProcess: %v", err)
	}

	if caller.tool != runtimeToolKillProcess {
		t.Fatalf("tool = %q, want %q", caller.tool, runtimeToolKillProcess)
	}
	if got := caller.args["resource_id"]; got != "pod-1" {
		t.Fatalf("resource_id = %#v, want pod-1", got)
	}
	if got := caller.args["pid"]; got != float64(4242) {
		t.Fatalf("pid = %#v, want 4242", got)
	}
}

func TestDefaultActionHandlerKillProcessRequiresEnsemble(t *testing.T) {
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{})

	err := handler.KillProcess(context.Background(), "pod-1", 4242)
	if err == nil {
		t.Fatal("expected error")
	}

	var capabilityErr *ActionCapabilityError
	if !errors.As(err, &capabilityErr) {
		t.Fatalf("expected ActionCapabilityError, got %T", err)
	}
	if capabilityErr.Code != "requires_ensemble" {
		t.Fatalf("code = %q, want requires_ensemble", capabilityErr.Code)
	}
}

func TestDefaultActionHandlerKillProcessRequiresTrustedScope(t *testing.T) {
	caller := &recordingRemoteCaller{}
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{
		RemoteCaller: caller,
	})

	err := handler.KillProcess(context.Background(), "pod-1", 4242)
	if err == nil {
		t.Fatal("expected error")
	}

	var capabilityErr *ActionCapabilityError
	if !errors.As(err, &capabilityErr) {
		t.Fatalf("expected ActionCapabilityError, got %T", err)
	}
	if capabilityErr.Code != "trusted_scope_required" {
		t.Fatalf("code = %q, want trusted_scope_required", capabilityErr.Code)
	}
}

func TestDefaultActionHandlerRemoteCallerCanBeBoundLater(t *testing.T) {
	caller := &recordingRemoteCaller{}
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{})
	handler.SetRemoteCaller(caller)
	ctx := WithTrustedActuationScope(context.Background(), TrustedActuationScope{
		AllowedResourceIDs: []string{"pod-1"},
	})

	if err := handler.KillProcess(ctx, "pod-1", 4242); err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	if caller.tool != runtimeToolKillProcess {
		t.Fatalf("tool = %q, want %q", caller.tool, runtimeToolKillProcess)
	}
}

func TestDefaultActionHandlerScaleDownUsesScaler(t *testing.T) {
	scaler := &recordingScaler{}
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{
		WorkloadScaler: scaler,
	})
	ctx := WithTrustedActuationScope(context.Background(), TrustedActuationScope{
		AllowedWorkloadTargets: []string{"deployment:prod/payments-api"},
	})

	if err := handler.ScaleDown(ctx, "deployment:prod/payments-api", 0); err != nil {
		t.Fatalf("ScaleDown: %v", err)
	}

	if scaler.target.String() != "deployment:prod/payments-api" {
		t.Fatalf("target = %q, want deployment:prod/payments-api", scaler.target.String())
	}
	if scaler.replicas != 0 {
		t.Fatalf("replicas = %d, want 0", scaler.replicas)
	}
}

func TestDefaultActionHandlerScaleDownRequiresTrustedTarget(t *testing.T) {
	scaler := &recordingScaler{}
	handler := NewDefaultActionHandler(DefaultActionHandlerOptions{
		WorkloadScaler: scaler,
	})

	err := handler.ScaleDown(context.Background(), "deployment:prod/payments-api", 0)
	if err == nil {
		t.Fatal("expected error")
	}

	var capabilityErr *ActionCapabilityError
	if !errors.As(err, &capabilityErr) {
		t.Fatalf("expected ActionCapabilityError, got %T", err)
	}
	if capabilityErr.Code != "trusted_scope_required" {
		t.Fatalf("code = %q, want trusted_scope_required", capabilityErr.Code)
	}
}

func TestDefaultActionHandlerScaleDownRejectsOutOfRangeReplicas(t *testing.T) {
	_, err := runtimeScaleReplicas32(maxRuntimeScaleReplicas + 1)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "replicas must be <=") {
		t.Fatalf("err = %v, want range error", err)
	}
}

func TestExecuteActionScaleDownUsesExplicitWorkloadTarget(t *testing.T) {
	engine := NewResponseEngine()
	handler := &scaleDownCapturingHandler{}
	engine.SetActionHandler(handler)

	err := engine.executeAction(context.Background(), PolicyAction{
		Type:       ActionScaleDown,
		Parameters: map[string]string{"replicas": "0"},
	}, &RuntimeFinding{
		ResourceID:   "pod-1",
		ResourceType: "pod",
		Event: &RuntimeEvent{
			Metadata: map[string]any{
				"workload_kind": "deployment",
				"workload_name": "payments-api",
				"namespace":     "prod",
			},
			Container: &ContainerEvent{
				Namespace: "prod",
				PodName:   "payments-api-6d4b9f8b69-42n5x",
			},
		},
	})
	if err != nil {
		t.Fatalf("executeAction: %v", err)
	}

	if handler.resourceID != "deployment:prod/payments-api" {
		t.Fatalf("resourceID = %q, want deployment:prod/payments-api", handler.resourceID)
	}
	if handler.replicas != 0 {
		t.Fatalf("replicas = %d, want 0", handler.replicas)
	}
}
