package findingapi

import (
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func TestApplyMCPGraphActionProposalReturnsTargetErrors(t *testing.T) {
	proposal := MCPActionProposalPayload{"finding_id": "finding-1"}
	err := ApplyMCPGraphActionProposal(proposal, eligibleGraphActionFinding(map[string]string{"okta_user_email": "alice@example.com"}), "execute_graph_action", MCPArguments{
		"graph_action": graphactions.ActionIdentityOktaSuspendUser,
		"target":       "other@example.com",
	}, "cerebro.graph_actions.write")
	if !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("ApplyMCPGraphActionProposal() error = %v, want ErrInvalidRequest", err)
	}
	if _, ok := proposal["endpoint"]; ok {
		t.Fatalf("proposal endpoint was set despite target error: %#v", proposal)
	}
}

func TestApplyMCPGraphActionProposalPopulatesValidProposal(t *testing.T) {
	proposal := MCPActionProposalPayload{
		"finding_id":             "finding-1",
		"external_id":            "ticket-123",
		"external_url":           "https://tickets.example/ticket-123",
		"external_status":        "open",
		"external_status_reason": "waiting",
		"lifecycle_owner":        "external_owned",
	}
	err := ApplyMCPGraphActionProposal(proposal, eligibleGraphActionFinding(map[string]string{"okta_user_email": "alice@example.com"}), "execute_graph_action", MCPArguments{
		"graph_action": graphactions.ActionIdentityOktaSuspendUser,
		"target":       "alice@example.com",
	}, "cerebro.graph_actions.write")
	if err != nil {
		t.Fatalf("ApplyMCPGraphActionProposal() error = %v", err)
	}
	if proposal["endpoint"] != "/platform/graph/actions" || proposal["target"] != "alice@example.com" || proposal["handoff_required"] != true {
		t.Fatalf("proposal = %#v, want graph action proposal fields populated", proposal)
	}
	for _, key := range []string{"external_id", "external_url", "external_status", "external_status_reason", "lifecycle_owner"} {
		if proposal[key] != "" {
			t.Fatalf("proposal[%q] = %#v, want stale external ref field cleared", key, proposal[key])
		}
	}
}

func TestApplyMCPGraphActionProposalClearsStaleExternalLifecycleFields(t *testing.T) {
	proposal := MCPActionProposalPayload{
		"finding_id":             "finding-1",
		"lifecycle_owner":        "external_owned",
		"external_system":        "jira",
		"external_ref_kind":      "ticket",
		"external_id":            "ENG-123",
		"external_url":           "https://jira.example.com/browse/ENG-123",
		"external_status":        "open",
		"external_status_reason": "waiting",
	}
	err := ApplyMCPGraphActionProposal(proposal, eligibleGraphActionFinding(map[string]string{"okta_user_email": "alice@example.com"}), "execute_graph_action", MCPArguments{
		"graph_action": graphactions.ActionIdentityOktaSuspendUser,
		"target":       "alice@example.com",
	}, "cerebro.graph_actions.write")
	if err != nil {
		t.Fatalf("ApplyMCPGraphActionProposal() error = %v", err)
	}
	if proposal["external_system"] != graphactions.ProviderAccessApprovals || proposal["external_ref_kind"] != graphactions.RefKind {
		t.Fatalf("proposal external ref routing = %#v, want access-approvals graph action", proposal)
	}
	for _, key := range []string{"lifecycle_owner", "external_id", "external_url", "external_status", "external_status_reason"} {
		if proposal[key] != "" {
			t.Fatalf("proposal[%q] = %#v, want stale external ref field cleared", key, proposal[key])
		}
	}
}

func eligibleGraphActionFinding(attrs map[string]string) *ports.FindingRecord {
	if attrs == nil {
		attrs = map[string]string{}
	}
	attrs["graph_actions_allowed"] = graphactions.ActionIdentityOktaSuspendUser + "," + graphactions.ActionIdentityOktaUnsuspendUser
	return &ports.FindingRecord{
		ID:         "finding-1",
		Status:     "open",
		Attributes: attrs,
	}
}
