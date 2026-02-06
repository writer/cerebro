package runtime

import (
	"context"
	"errors"
	"testing"
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
