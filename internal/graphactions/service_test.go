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

func TestNormalizeTargetRejectsDisplayNameWithoutEmail(t *testing.T) {
	_, err := NormalizeTarget("Alice Example")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NormalizeTarget() error = %v, want ErrInvalidRequest", err)
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

func TestServiceExecuteDoesNotUseDisplayLabelAsTarget(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Attributes: map[string]string{
			"okta_user_label": "Alice Example",
		},
	}}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("label-only target reached access-approvals client")
	}
}

func TestServiceExecuteRejectsExplicitTargetOutsideFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	}}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
		Target:    "victim@tenant-b.example",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("cross-finding explicit target reached access-approvals client")
	}
}

func TestServiceExecuteRejectsExplicitTargetFromCrossTenantURN(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		ResourceURNs: []string{"urn:cerebro:tenant-b:okta_user:00uvictim"},
		Attributes: map[string]string{
			"identity_urns": "urn:cerebro:tenant-b:identity:email:victim@tenant-b.example",
		},
	}}
	for _, target := range []string{"00uvictim", "victim@tenant-b.example"} {
		_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
			FindingID: "finding-1",
			Action:    ActionIdentityOktaSuspendUser,
			Target:    target,
		})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Execute(%q) error = %v, want ErrInvalidRequest", target, err)
		}
	}
	if client.called {
		t.Fatalf("cross-tenant URN-derived target reached access-approvals client")
	}
}

func TestServiceExecuteDerivesTargetFromOktaUserURN(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		Title:        "User needs action",
		ResourceURNs: []string{"urn:cerebro:tenant-a:okta_user:00u123"},
	}}
	result, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result == nil || result.Target != "00u123" {
		t.Fatalf("Execute() target = %#v, want Okta user id from URN", result)
	}
	if got := client.request.EmailOrUserID; got != "00u123" {
		t.Fatalf("access-approvals target = %q, want 00u123", got)
	}
}

func TestServiceExecuteAllowsExplicitTargetMatchingFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Title:      "User needs action",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	}}
	result, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
		Target:    "Alice <alice@tenant-a.example>",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result == nil || result.Target != "alice@tenant-a.example" {
		t.Fatalf("Execute() target = %#v, want normalized finding target", result)
	}
	if !client.called {
		t.Fatalf("matching explicit target did not reach access-approvals client")
	}
	if got := client.request.EmailOrUserID; got != "alice@tenant-a.example" {
		t.Fatalf("access-approvals target = %q, want normalized finding target", got)
	}
}

type stubFindingWorkflow struct {
	finding *ports.FindingRecord
	ref     ports.FindingExternalRef
}

func (s *stubFindingWorkflow) GetFinding(context.Context, string) (*ports.FindingRecord, error) {
	return s.finding, nil
}

func (s *stubFindingWorkflow) LinkFindingExternalRef(_ context.Context, _ string, ref ports.FindingExternalRef) (*ports.FindingRecord, error) {
	s.ref = ref
	return s.finding, nil
}

type stubAccessApprovalsClient struct {
	called  bool
	request AccessApprovalsUserActionRequest
}

func (s *stubAccessApprovalsClient) SuspendOktaUser(_ context.Context, request AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	s.called = true
	s.request = request
	return &AccessApprovalsUserAction{ID: "action-1"}, nil
}

func (s *stubAccessApprovalsClient) UnsuspendOktaUser(_ context.Context, request AccessApprovalsUserActionRequest) (*AccessApprovalsUserAction, error) {
	s.called = true
	s.request = request
	return &AccessApprovalsUserAction{ID: "action-1"}, nil
}

func (s *stubAccessApprovalsClient) ActionURL(string) string {
	return ""
}
