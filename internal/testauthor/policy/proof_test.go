package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
)

func TestProvePassesProtectedAndRejectsWeakenedPolicy(t *testing.T) {
	artifacts, err := Author(Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prove(context.Background(), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Receipts) != 2 || !result.Receipts[0].Passed || !result.Receipts[1].Passed {
		t.Fatalf("receipts = %#v", result.Receipts)
	}
	if result.PolicyDigest == "" || result.TestDigest == "" {
		t.Fatalf("missing digests: %#v", result)
	}
}

func TestProveGraphRequiresAndExecutesInjectedStore(t *testing.T) {
	evidence := authoredGraphEvidence()
	artifacts, err := ArtifactsForRuleWithGraphEvidence(context.Background(), "aws", authoredGraphRule(), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	notRun, err := Prove(context.Background(), artifacts)
	if !errors.Is(err, ErrGraphStoreRequired) {
		t.Fatalf("Prove() error = %v, want ErrGraphStoreRequired", err)
	}
	if receipt := proofReceiptByGate(t, notRun, "graph_edge_ablation"); receipt.Execution != "not_run" || receipt.Passed {
		t.Fatalf("not-run receipts = %#v", notRun.Receipts)
	}
	if receipt := proofReceiptByGate(t, notRun, "graph_tenant_scope"); receipt.Execution != "in_process" || !receipt.Passed {
		t.Fatalf("tenant receipt = %#v", receipt)
	}

	store := newProofGraphStore()
	result, err := ProveWithGraphStore(context.Background(), artifacts, store)
	if err != nil {
		t.Fatal(err)
	}
	if store.executions < len(artifacts.Suite.Cases) {
		t.Fatalf("graph executions = %d, want every one of %d authored cases executed", store.executions, len(artifacts.Suite.Cases))
	}
	for _, gate := range []string{"graph_fixture_contract", "graph_multi_hop", "graph_query_safety", "graph_tenant_scope", "graph_edge_ablation", "graph_predicate_mutation", "graph_neighbor_isolation", "graph_execution"} {
		if receipt := proofReceiptByGate(t, result, gate); !receipt.Passed {
			t.Fatalf("%s receipt = %#v; all receipts = %#v", gate, receipt, result.Receipts)
		}
	}
}

func TestProveGraphRejectsSuiteWithoutTwoCausalEdgeAblations(t *testing.T) {
	evidence := authoredGraphEvidence()
	artifacts, err := ArtifactsForRuleWithGraphEvidence(context.Background(), "aws", authoredGraphRule(), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	filtered := artifacts.Suite.Cases[:0]
	for _, testCase := range artifacts.Suite.Cases {
		if strings.HasPrefix(testCase.Name, graphEdgeAblationCasePrefix) {
			continue
		}
		filtered = append(filtered, testCase)
	}
	artifacts.Suite.Cases = filtered
	result, err := Prove(context.Background(), artifacts)
	if !errors.Is(err, ErrGraphMultiHopQueryRequired) {
		t.Fatalf("Prove() error = %v, want multi-hop query error", err)
	}
	if receipt := proofReceiptByGate(t, result, "graph_multi_hop"); receipt.Passed {
		t.Fatalf("multi-hop receipt = %#v, want failed", receipt)
	}
}

func TestProveGraphRefusesUnsafeQueryBeforeGraphExecution(t *testing.T) {
	evidence := authoredGraphEvidence()
	artifacts, err := ArtifactsForRuleWithGraphEvidence(context.Background(), "aws", authoredGraphRule(), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Rule.Spec.Graph.Query = `MATCH (actor:Entity {tenant_id: $tenant_id}) MATCH (other:Entity) RETURN other.urn AS primary_urn LIMIT $row_limit`
	store := newProofGraphStore()
	result, err := ProveWithGraphStore(context.Background(), artifacts, store)
	if !errors.Is(err, ErrGraphTenantScopeRequired) {
		t.Fatalf("ProveWithGraphStore() error = %v, want tenant-scope refusal", err)
	}
	if store.executions != 0 {
		t.Fatalf("graph executions = %d, want none before refusal", store.executions)
	}
	if receipt := proofReceiptByGate(t, result, "graph_query_safety"); receipt.Passed {
		t.Fatalf("query safety receipt = %#v, want failed", receipt)
	}
}

func TestProveGraphAttributesEachReceiptToItsExecutedSubSuite(t *testing.T) {
	evidence := authoredGraphEvidence()
	artifacts, err := ArtifactsForRuleWithGraphEvidence(context.Background(), "aws", authoredGraphRule(), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	store := newProofGraphStore()
	store.ignorePredicates = true
	result, err := ProveWithGraphStore(context.Background(), artifacts, store)
	if err == nil {
		t.Fatal("ProveWithGraphStore() error = nil")
	}
	if receipt := proofReceiptByGate(t, result, "graph_edge_ablation"); !receipt.Passed {
		t.Fatalf("edge receipt = %#v, want independently passed", receipt)
	}
	if receipt := proofReceiptByGate(t, result, "graph_predicate_mutation"); receipt.Passed {
		t.Fatalf("predicate receipt = %#v, want failed mutant suite", receipt)
	}
	if receipt := proofReceiptByGate(t, result, "graph_execution"); receipt.Passed {
		t.Fatalf("aggregate receipt = %#v, want failed", receipt)
	}
}

func TestGraphProofExecutionNamespacesCannotCollide(t *testing.T) {
	evidence := authoredGraphEvidence()
	artifacts, err := ArtifactsForRuleWithGraphEvidence(context.Background(), "aws", authoredGraphRule(), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	first, err := isolateGraphProofSuite(artifacts.Suite, "execution-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := isolateGraphProofSuite(artifacts.Suite, "execution-b")
	if err != nil {
		t.Fatal(err)
	}
	firstURNs := map[string]struct{}{}
	for _, testCase := range first.Cases {
		if testCase.GraphFixture == nil {
			continue
		}
		if !strings.HasSuffix(testCase.GraphFixture.TenantID, "-proof-execution-a") {
			t.Fatalf("first tenant = %q", testCase.GraphFixture.TenantID)
		}
		for _, node := range testCase.GraphFixture.Nodes {
			firstURNs[node.URN] = struct{}{}
		}
	}
	for _, testCase := range second.Cases {
		if testCase.GraphFixture == nil {
			continue
		}
		if !strings.HasSuffix(testCase.GraphFixture.TenantID, "-proof-execution-b") {
			t.Fatalf("second tenant = %q", testCase.GraphFixture.TenantID)
		}
		for _, node := range testCase.GraphFixture.Nodes {
			if _, collision := firstURNs[node.URN]; collision {
				t.Fatalf("proof execution URN collision: %q", node.URN)
			}
		}
	}
	if strings.Contains(artifacts.Suite.Cases[0].GraphFixture.TenantID, "-proof-") {
		t.Fatalf("authored fixture was mutated: %q", artifacts.Suite.Cases[0].GraphFixture.TenantID)
	}
}

func proofReceiptByGate(t *testing.T, result ProofResult, gate string) ProofReceipt {
	t.Helper()
	for _, receipt := range result.Receipts {
		if receipt.Gate == gate {
			return receipt
		}
	}
	t.Fatalf("receipts = %#v, missing gate %q", result.Receipts, gate)
	return ProofReceipt{}
}

type proofGraphStore struct {
	entities         map[string]*ports.ProjectedEntity
	links            map[string]*ports.ProjectedLink
	executions       int
	ignorePredicates bool
}

func newProofGraphStore() *proofGraphStore {
	return &proofGraphStore{entities: map[string]*ports.ProjectedEntity{}, links: map[string]*ports.ProjectedLink{}}
}

func (s *proofGraphStore) Ping(context.Context) error { return nil }
func (s *proofGraphStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}
func (s *proofGraphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	s.entities[entity.URN] = entity
	return nil
}
func (s *proofGraphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	s.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = link
	return nil
}
func (s *proofGraphStore) DeleteProjectedEntity(_ context.Context, urn string) error {
	delete(s.entities, urn)
	for key, link := range s.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(s.links, key)
		}
	}
	return nil
}
func (s *proofGraphStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.executions++
	query := strings.ToLower(request.Query)
	for _, launch := range s.links {
		if launch.Relation != "acted_on" {
			continue
		}
		for _, dependency := range s.links {
			if dependency.Relation != "depends_on" || dependency.FromURN != launch.ToURN {
				continue
			}
			for _, roleEdge := range s.links {
				if roleEdge.Relation != "runs_as" || roleEdge.FromURN != dependency.ToURN {
					continue
				}
				task, definition := s.entities[launch.ToURN], s.entities[dependency.ToURN]
				if task == nil || definition == nil || s.entities[roleEdge.ToURN] == nil {
					continue
				}
				if !s.ignorePredicates && !proofGraphPredicatesMatch(query, launch, task, definition, roleEdge) {
					continue
				}
				resourceURNs := []string{launch.FromURN, launch.ToURN, dependency.ToURN, roleEdge.ToURN}
				evidence := make([]any, 0, len(resourceURNs))
				for _, urn := range resourceURNs {
					evidence = append(evidence, map[string]any{"urn": urn})
				}
				return []ports.CypherRow{{Values: map[string]any{
					"primary_urn": roleEdge.FromURN, "fingerprint_key": roleEdge.FromURN + "|" + roleEdge.ToURN,
					"summary": "causal ECS role path", "resource_urns": resourceURNs, "evidence": evidence,
				}}}, nil
			}
		}
	}
	return nil, nil
}

func proofGraphPredicatesMatch(query string, launch *ports.ProjectedLink, task, definition *ports.ProjectedEntity, roleEdge *ports.ProjectedLink) bool {
	checks := []struct {
		queryToken string
		attributes map[string]string
		key        string
		value      string
	}{
		{`"event_type":"runtask"`, launch.Attributes, "event_type", "runtask"},
		{"candidate", task.Attributes, "started_by", "candidate"},
		{`"status":"active"`, definition.Attributes, "status", "active"},
		{`"has_secret_bindings":"true"`, definition.Attributes, "has_secret_bindings", "true"},
		{`"role_usage":"execution"`, roleEdge.Attributes, "role_usage", "execution"},
	}
	for _, check := range checks {
		if !strings.Contains(query, check.queryToken) {
			continue
		}
		if !strings.Contains(strings.ToLower(check.attributes[check.key]), check.value) {
			return false
		}
	}
	return true
}

func TestProveRejectsSuiteThatSurvivesMutation(t *testing.T) {
	artifacts, err := Author(Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Suite.Cases = artifacts.Suite.Cases[:1]
	result, err := Prove(context.Background(), artifacts)
	if err == nil {
		t.Fatal("Prove() error = nil")
	}
	if len(result.Receipts) != 2 || result.Receipts[1].Passed {
		t.Fatalf("receipts = %#v", result.Receipts)
	}
}
