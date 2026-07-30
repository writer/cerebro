package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agentauthoring"
	"github.com/writer/cerebro/internal/policycandidate"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

func TestPolicyCandidateReadsUseConfiguredAuthority(t *testing.T) {
	legacy := &policyGraphStoreStub{stubGraphStore: &stubGraphStore{}}
	authority := &stubGraphStore{}
	app := &App{deps: Dependencies{
		GraphStore:      legacy,
		GraphQueries:    authority,
		PolicyAuthoring: &agentauthoring.Service{},
	}}

	service := app.policyCandidateService()
	if service.Graph != authority {
		t.Fatalf("policy candidate graph = %#v, want configured authority", service.Graph)
	}
	if service.Author == nil || any(service.Author.PolicyGraphStore) != any(legacy) {
		t.Fatalf("policy fixture store = %#v, want explicit compatibility store", service.Author)
	}
}

type policyGraphStoreStub struct {
	*stubGraphStore
}

func (*policyGraphStoreStub) DeleteProjectedEntity(context.Context, string) error {
	return nil
}

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
		"POST /policy-candidates/{candidateID}/experiments", "GET /policy-candidates/{candidateID}/experiments",
		"GET /policy-experiments/{experimentID}", "GET /policy-experiments/{experimentID}/observations",
		"POST /policy-experiments/{experimentID}/run",
	}
	for _, route := range routes {
		method, path, _ := strings.Cut(route, " ")
		policy := httpRoutePolicyFor(method, path)
		if policy.Scope == "" {
			t.Fatalf("route %s has no auth policy", route)
		}
	}
}

func TestPolicyExperimentHTTPRoutesRequireOperatorScope(t *testing.T) {
	for _, route := range []string{
		"POST /policy-candidates/candidate-1/experiments",
		"GET /policy-candidates/candidate-1/experiments",
		"GET /policy-experiments/experiment-1",
		"GET /policy-experiments/experiment-1/observations",
		"POST /policy-experiments/experiment-1/run",
	} {
		method, path, _ := strings.Cut(route, " ")
		if got := httpRoutePolicyFor(method, path).Scope; got != scopePolicyCandidatesWrite {
			t.Fatalf("route %s scope = %q, want %q", route, got, scopePolicyCandidatesWrite)
		}
	}
}

func TestPolicyExperimentObservationViewOmitsPrivateDatasetCase(t *testing.T) {
	encoded, err := json.Marshal(newPolicyExperimentObservationView(&policycandidate.PolicyExperimentObservation{
		ID: "peo_test", ExperimentID: "pex_test", TenantID: "tenant-a", Sequence: 1,
		Kind: "historical_case", CheckpointID: "checkpoint-safe", DatasetCaseID: "private-resource-urn",
		ReceiptDigest: strings.Repeat("a", 64), Metrics: map[string]float64{"matched": 1},
		ObservedAt: time.Unix(100, 0), CreatedAt: time.Unix(101, 0),
	}))
	if err != nil {
		t.Fatal(err)
	}
	payload := string(encoded)
	for _, forbidden := range []string{"private-resource-urn", "dataset_case_id", "tenant-a", "tenant_id"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("observation view contains %q: %s", forbidden, payload)
		}
	}
}
