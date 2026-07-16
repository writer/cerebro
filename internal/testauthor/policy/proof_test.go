package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
)

func TestProvePassesProtectedAndRejectsWeakenedPolicy(t *testing.T) {
	artifacts, err := Author(Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Prove(t.Context(), artifacts)
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
	artifacts, err := ArtifactsForRuleWithGraphEvidence("aws", authoredGraphRule(), &evidence)
	if err != nil {
		t.Fatal(err)
	}
	notRun, err := Prove(t.Context(), artifacts)
	if !errors.Is(err, ErrGraphStoreRequired) {
		t.Fatalf("Prove() error = %v, want ErrGraphStoreRequired", err)
	}
	if len(notRun.Receipts) != 2 || notRun.Receipts[1].Execution != "not_run" || notRun.Receipts[1].Passed {
		t.Fatalf("not-run receipts = %#v", notRun.Receipts)
	}

	store := newProofGraphStore()
	result, err := ProveWithGraphStore(t.Context(), artifacts, store)
	if err != nil {
		t.Fatal(err)
	}
	if store.executions != 2 {
		t.Fatalf("graph executions = %d, want finding and passing cases", store.executions)
	}
	if len(result.Receipts) != 2 || !result.Receipts[0].Passed || !result.Receipts[1].Passed || result.Receipts[1].Execution != "graph_store" {
		t.Fatalf("graph receipts = %#v", result.Receipts)
	}
}

type proofGraphStore struct {
	entities   map[string]*ports.ProjectedEntity
	links      map[string]*ports.ProjectedLink
	executions int
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
func (s *proofGraphStore) ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.executions++
	var roleEdge *ports.ProjectedLink
	for _, link := range s.links {
		if link.Relation == "runs_as" {
			roleEdge = link
			break
		}
	}
	if roleEdge == nil {
		return nil, nil
	}
	evidence := make([]any, 0, len(s.entities))
	resourceURNs := make([]string, 0, len(s.entities))
	for urn := range s.entities {
		evidence = append(evidence, map[string]any{"urn": urn})
		resourceURNs = append(resourceURNs, urn)
	}
	return []ports.CypherRow{{Values: map[string]any{
		"primary_urn": roleEdge.FromURN, "fingerprint_key": roleEdge.FromURN + "|" + roleEdge.ToURN,
		"summary": "causal ECS role path", "resource_urns": resourceURNs, "evidence": evidence,
	}}}, nil
}

func TestProveRejectsSuiteThatSurvivesMutation(t *testing.T) {
	artifacts, err := Author(Intent{ID: "public-bucket", Domain: "aws", Name: "Public bucket", Description: "Flags public buckets.", Severity: "high", Conditions: []string{`cmp_eq(path(resource, "public"), true)`, `cmp_eq(path(resource, "approved"), false)`}, Frameworks: []findingdsl.PolicyFramework{{Name: "CIS", Controls: []string{"1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	artifacts.Suite.Cases = artifacts.Suite.Cases[:1]
	result, err := Prove(t.Context(), artifacts)
	if err == nil {
		t.Fatal("Prove() error = nil")
	}
	if len(result.Receipts) != 2 || result.Receipts[1].Passed {
		t.Fatalf("receipts = %#v", result.Receipts)
	}
}
