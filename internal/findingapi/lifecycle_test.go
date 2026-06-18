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

func TestApplyMCPGraphActionProposalUsesCatalogProvider(t *testing.T) {
	proposal := MCPActionProposalPayload{"finding_id": "finding-1"}
	finding := eligibleGraphActionFinding(map[string]string{
		"cerebro_device_id": "dev-1",
	})
	finding.TenantID = "writer"
	finding.Attributes["graph_actions_allowed"] = graphactions.ActionEndpointCerebroRevokeDevice
	err := ApplyMCPGraphActionProposal(proposal, finding, "execute_graph_action", MCPArguments{
		"graph_action": graphactions.ActionEndpointCerebroRevokeDevice,
		"target":       "dev-1",
	}, "cerebro.graph_actions.write")
	if err != nil {
		t.Fatalf("ApplyMCPGraphActionProposal() error = %v", err)
	}
	if proposal["external_system"] != graphactions.ProviderCerebroDeviceAuth || proposal["external_ref_kind"] != graphactions.RefKind {
		t.Fatalf("proposal external ref routing = %#v, want cerebro-device-auth graph action", proposal)
	}
	if proposal["target"] != "dev-1" {
		t.Fatalf("proposal target = %#v, want dev-1", proposal["target"])
	}
}

func TestMCPActionInputPropertiesIncludesCatalogGraphActions(t *testing.T) {
	graphAction, ok := MCPActionInputProperties()["graph_action"].(map[string]any)
	if !ok {
		t.Fatalf("graph_action schema missing or invalid")
	}
	enum, ok := graphAction["enum"].([]string)
	if !ok {
		t.Fatalf("graph_action enum missing or invalid: %#v", graphAction["enum"])
	}
	allowed := map[string]struct{}{}
	for _, action := range enum {
		allowed[action] = struct{}{}
	}
	for _, spec := range graphactions.KnownActionSpecs() {
		if _, ok := allowed[spec.ID]; !ok {
			t.Fatalf("graph_action enum missing catalog action %q", spec.ID)
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
