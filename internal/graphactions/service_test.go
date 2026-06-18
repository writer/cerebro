package graphactions

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/ports"
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

func TestServiceExecuteRejectsExplicitTargetOutsideFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	findings := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID: "finding-1",
		Attributes: map[string]string{
			"okta_user_urn": "urn:cerebro:writer:okta.user:alice@writer.com",
		},
	}}
	_, err := (Service{Client: client, Findings: findings}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
		Target:    "bob@other.example",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("cross-finding explicit target reached access-approvals client")
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

type stubFindingWorkflow struct {
	finding *ports.FindingRecord
}

func (s *stubFindingWorkflow) GetFinding(context.Context, string) (*ports.FindingRecord, error) {
	return s.finding, nil
}

func (s *stubFindingWorkflow) LinkFindingExternalRef(context.Context, string, ports.FindingExternalRef) (*ports.FindingRecord, error) {
	return s.finding, nil
}
