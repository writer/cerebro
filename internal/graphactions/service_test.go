package graphactions

import (
	"context"
	"errors"
	"testing"
)

func TestNormalizeTargetExtractsDisplayNameEmailAddress(t *testing.T) {
	target, err := NormalizeTarget(`Alice Example <alice@writer.com>`)
	if err != nil {
		t.Fatalf("NormalizeTarget() error = %v", err)
	}
	if target != "alice@writer.com" {
		t.Fatalf("target = %q, want parsed mailbox", target)
	}
}

func TestServiceExecuteRequiresFindingID(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	_, err := (Service{Client: client}).Execute(context.Background(), Input{
		Action: ActionIdentityOktaUnsuspendUser,
		Target: "alice@writer.com",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("target-only request reached access-approvals client")
	}
}

type stubAccessApprovalsClient struct {
	called bool
}

func (s *stubAccessApprovalsClient) SuspendOktaUser(context.Context, AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	s.called = true
	return &AccessApprovalsUserAction{ID: "action-1"}, nil
}

func (s *stubAccessApprovalsClient) UnsuspendOktaUser(context.Context, AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	s.called = true
	return &AccessApprovalsUserAction{ID: "action-1"}, nil
}

func (s *stubAccessApprovalsClient) ActionURL(string) string {
	return ""
}
