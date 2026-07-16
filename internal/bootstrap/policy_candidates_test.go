package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/policycandidate"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

func TestPolicyCandidateViewOmitsPrivateOriginAndRawEvidence(t *testing.T) {
	candidate := &policycandidate.Candidate{
		ID: "pc_test", TenantID: "tenant-a", Status: policycandidate.StatusGrounded, Revision: 1,
		Hypothesis: "An active workload keeps a secret-bearing execution path.", Domain: "aws",
		Origin: policycandidate.Origin{Kind: "slack_thread", ExternalRef: "private-channel-and-thread"},
		GraphEvidence: &policyauthor.GraphEvidence{
			Nodes: []policyauthor.GraphEvidenceNode{{ID: "private-node-handle", SourceID: "aws", EntityType: "aws.task"}},
			Edges: []policyauthor.GraphEvidenceEdge{{FromID: "private-node-handle", ToID: "other-private-handle", SourceID: "aws", Relation: "depends_on"}},
		},
		Grounding: &policycandidate.GroundingReceipt{
			Execution: "current_graph", NodeCount: 1, EdgeCount: 1, ReceiptID: "ground_safe_receipt", ObservedAt: time.Unix(99, 0),
		},
		CoverageGap: &policycandidate.CoverageGapReceipt{Execution: "finding_rule_catalog", CatalogDigest: strings.Repeat("a", 64), ComparedRuleCount: 4, CandidateSignature: strings.Repeat("b", 64), ObservedAt: time.Unix(99, 0)},
		CreatedAt:   time.Unix(100, 0), UpdatedAt: time.Unix(100, 0),
	}
	encoded, err := json.Marshal(newPolicyCandidateView(candidate))
	if err != nil {
		t.Fatal(err)
	}
	payload := string(encoded)
	for _, forbidden := range []string{"private-channel-and-thread", "private-node-handle", "other-private-handle", "graph_evidence", "external_ref", "entity_urn", "bindings"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("view contains %q: %s", forbidden, payload)
		}
	}
	for _, required := range []string{`"origin_kind":"slack_thread"`, `"node_count":1`, `"edge_count":1`, `"aws.task"`, `"depends_on"`, `"receipt_id":"ground_safe_receipt"`, `"execution":"current_graph"`, `"execution":"finding_rule_catalog"`, `"compared_rule_count":4`} {
		if !strings.Contains(payload, required) {
			t.Fatalf("view missing %q: %s", required, payload)
		}
	}
}

func TestPolicyCandidateHTTPRoutesUseApplicationNamespace(t *testing.T) {
	routes := []string{
		"POST /policy-candidates", "GET /policy-candidates", "GET /policy-candidates/{candidateID}",
		"POST /policy-candidates/{candidateID}/prove", "POST /policy-candidates/{candidateID}/shadow",
	}
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		policy := httpRoutePolicyFor(method, path)
		if policy.Scope == "" {
			t.Fatalf("route %s has no auth policy", route)
		}
	}
}
