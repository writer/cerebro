package findingapi

import (
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func TestApplyMCPGraphActionProposalReturnsTargetErrors(t *testing.T) {
	proposal := MCPActionProposalPayload{"finding_id": "finding-1"}
	err := ApplyMCPGraphActionProposal(proposal, &ports.FindingRecord{ID: "finding-1"}, "execute_graph_action", MCPArguments{
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
	proposal := MCPActionProposalPayload{"finding_id": "finding-1"}
	err := ApplyMCPGraphActionProposal(proposal, &ports.FindingRecord{
		ID:         "finding-1",
		Attributes: map[string]string{"okta_user_email": "alice@example.com"},
	}, "execute_graph_action", MCPArguments{
		"graph_action": graphactions.ActionIdentityOktaSuspendUser,
		"target":       "alice@example.com",
	}, "cerebro.graph_actions.write")
	if err != nil {
		t.Fatalf("ApplyMCPGraphActionProposal() error = %v", err)
	}
	if proposal["endpoint"] != "/platform/graph/actions" || proposal["target"] != "alice@example.com" || proposal["handoff_required"] != true {
		t.Fatalf("proposal = %#v, want graph action proposal fields populated", proposal)
	}
}
