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

func TestServiceExecuteRejectsFindingWithoutAllowedAction(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: &ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Status:     "open",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	}}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID: "finding-1",
		Action:    ActionIdentityOktaSuspendUser,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("policy-rejected action reached access-approvals client")
	}
}

func TestServiceExecuteRejectsReservedParameters(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	})}
	_, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
		FindingID:  "finding-1",
		Action:     ActionIdentityOktaSuspendUser,
		Parameters: map[string]string{"dry_run": "false"},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Execute() error = %v, want ErrInvalidRequest", err)
	}
	if client.called {
		t.Fatalf("parameter-rejected action reached access-approvals client")
	}
}

func TestServiceExecuteDoesNotUseDisplayLabelAsTarget(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		Attributes: map[string]string{
			"okta_user_label": "Alice Example",
		},
	})}
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
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	})}
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
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		ResourceURNs: []string{"urn:cerebro:tenant-b:okta_user:00uvictim"},
		Attributes: map[string]string{
			"identity_urns": "urn:cerebro:tenant-b:identity:email:victim@tenant-b.example",
		},
	})}
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
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		Title:        "User needs action",
		ResourceURNs: []string{"urn:cerebro:tenant-a:okta_user:00u123"},
	})}
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
	if client.request.TenantID != "tenant-a" || client.request.FindingID != "finding-1" || client.request.FindingRuleID != "rule-1" || client.request.ResourceURN != "urn:cerebro:tenant-a:okta_user:00u123" || client.request.SubjectURN != "urn:cerebro:tenant-a:okta_user:00u123" {
		t.Fatalf("access-approvals metadata = %#v", client.request)
	}
}

func TestServiceExecuteDerivesDelimitedOktaURNWithoutForwardingRawURN(t *testing.T) {
	for _, key := range []string{"okta_user_urn", "identity_urns"} {
		t.Run(key, func(t *testing.T) {
			client := &stubAccessApprovalsClient{}
			workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
				ID:       "finding-1",
				TenantID: "tenant-a",
				Title:    "User needs action",
				Attributes: map[string]string{
					key: "urn:cerebro:tenant-a:okta_user:00u123",
				},
			})}
			result, err := (Service{Findings: workflow, Client: client}).Execute(context.Background(), Input{
				FindingID: "finding-1",
				Action:    ActionIdentityOktaSuspendUser,
			})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if result == nil || result.Target != "00u123" {
				t.Fatalf("Execute() target = %#v, want Okta user id from delimited URN", result)
			}
			if got := client.request.EmailOrUserID; got != "00u123" {
				t.Fatalf("access-approvals target = %q, want extracted Okta user id", got)
			}
		})
	}
}

func TestServiceExecuteAllowsExplicitTargetMatchingFinding(t *testing.T) {
	client := &stubAccessApprovalsClient{}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:         "finding-1",
		TenantID:   "tenant-a",
		Title:      "User needs action",
		Attributes: map[string]string{"okta_user_email": "alice@tenant-a.example"},
	})}
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

func TestGraphActionFromAccessApprovalsFallsBackToResolvedTarget(t *testing.T) {
	action := GraphActionFromAccessApprovals(ActionIdentityOktaSuspendUser, &AccessApprovalsUserAction{ID: "action-1"}, "", "00u123")
	if action == nil || action.Target != "00u123" {
		t.Fatalf("GraphActionFromAccessApprovals() = %#v, want fallback target", action)
	}
}

func TestServiceReconcileRefreshesLinkedExternalRef(t *testing.T) {
	client := &stubAccessApprovalsClient{
		getAction: &AccessApprovalsUserAction{
			ID:     "action-1",
			Action: AccessApprovalsActionSuspend,
			Status: "succeeded",
			Target: "00u123",
		},
	}
	workflow := &stubFindingWorkflow{finding: eligibleFinding(&ports.FindingRecord{
		ID:       "finding-1",
		TenantID: "tenant-a",
		FindingWorkflow: ports.FindingWorkflow{
			ExternalRefs: []ports.FindingExternalRef{{
				System:     ProviderAccessApprovals,
				Kind:       RefKind,
				ExternalID: "action-1",
			}},
		},
		Attributes: map[string]string{"okta_user_urn": "urn:cerebro:tenant-a:okta_user:00u123"},
	})}
	result, err := (Service{Findings: workflow, Client: client}).Reconcile(context.Background(), ReconcileInput{
		FindingID:  "finding-1",
		ExternalID: "action-1",
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result == nil || result.Action == nil || result.Action.ExternalStatus != "succeeded" {
		t.Fatalf("Reconcile() result = %#v, want succeeded action", result)
	}
	if workflow.ref.ExternalStatus != "succeeded" {
		t.Fatalf("linked ref = %#v, want refreshed status", workflow.ref)
	}
}

func eligibleFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding.Attributes == nil {
		finding.Attributes = map[string]string{}
	}
	finding.Status = "open"
	finding.RuleID = "rule-1"
	finding.Attributes["graph_actions_allowed"] = ActionIdentityOktaSuspendUser + "," + ActionIdentityOktaUnsuspendUser
	return finding
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
	called    bool
	request   AccessApprovalsUserActionRequest
	getAction *AccessApprovalsUserAction
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

func (s *stubAccessApprovalsClient) GetOktaUserAction(context.Context, string) (*AccessApprovalsUserAction, error) {
	return s.getAction, nil
}

func (s *stubAccessApprovalsClient) ActionURL(string) string {
	return ""
}
