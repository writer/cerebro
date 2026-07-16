package policycandidate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/agentauthoring"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

type memoryStore struct{ records map[string]*Candidate }

func (s *memoryStore) CreatePolicyCandidate(_ context.Context, candidate *Candidate) error {
	if s.records == nil {
		s.records = map[string]*Candidate{}
	}
	s.records[candidate.ID] = cloneCandidate(candidate)
	return nil
}
func (s *memoryStore) GetPolicyCandidate(_ context.Context, id string) (*Candidate, error) {
	candidate := s.records[id]
	if candidate == nil {
		return nil, ErrNotFound
	}
	return cloneCandidate(candidate), nil
}
func (s *memoryStore) ListPolicyCandidates(_ context.Context, request ListRequest) ([]*Candidate, error) {
	var result []*Candidate
	for _, candidate := range s.records {
		if candidate.TenantID == request.TenantID && (request.Status == "" || candidate.Status == request.Status) {
			result = append(result, cloneCandidate(candidate))
		}
	}
	return result, nil
}
func (s *memoryStore) SavePolicyCandidate(_ context.Context, candidate *Candidate, expected int64) error {
	stored := s.records[candidate.ID]
	if stored == nil || stored.Revision != expected {
		return ErrConflict
	}
	s.records[candidate.ID] = cloneCandidate(candidate)
	return nil
}

type draftModel struct {
	raw     []byte
	request agentauthoring.StructuredDraftRequest
}

type coverageCatalog struct {
	queries []CoverageQuery
	err     error
}

func (c *coverageCatalog) ListCoverageQueries(_ context.Context, _ string, _ int) ([]CoverageQuery, error) {
	return append([]CoverageQuery(nil), c.queries...), c.err
}

func (m *draftModel) DraftJSON(_ context.Context, request agentauthoring.StructuredDraftRequest) ([]byte, error) {
	m.request = request
	return append([]byte(nil), m.raw...), nil
}

type graphStore struct {
	requests          []ports.CypherQueryRequest
	entities          map[string]*ports.ProjectedEntity
	links             map[string]*ports.ProjectedLink
	omitGroundingEdge bool
	useShadowRows     bool
	shadowRows        []ports.CypherRow
}

func newGraphStore() *graphStore {
	return &graphStore{entities: map[string]*ports.ProjectedEntity{}, links: map[string]*ports.ProjectedLink{}}
}
func (s *graphStore) Ping(context.Context) error { return nil }
func (s *graphStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}
func (s *graphStore) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	s.entities[entity.URN] = entity
	return nil
}
func (s *graphStore) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	s.links[link.FromURN+link.Relation+link.ToURN] = link
	return nil
}
func (s *graphStore) DeleteProjectedEntity(_ context.Context, urn string) error {
	delete(s.entities, urn)
	for key, link := range s.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(s.links, key)
		}
	}
	return nil
}
func (s *graphStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	if request.Query == groundingNodesQuery {
		return []ports.CypherRow{
			{Values: map[string]any{"urn": "urn:cerebro:tenant-a:aws:session:actor", "entity_type": "aws.session", "source_id": "aws", "attributes_json": `{}`}},
			{Values: map[string]any{"urn": "urn:cerebro:tenant-a:aws:task:task", "entity_type": "aws.task", "source_id": "aws", "attributes_json": `{}`}},
			{Values: map[string]any{"urn": "urn:cerebro:tenant-a:aws:task-definition:definition", "entity_type": "aws.task_definition", "source_id": "aws", "attributes_json": `{"status":"ACTIVE"}`}},
		}, nil
	}
	if request.Query == groundingEdgesQuery {
		rows := []ports.CypherRow{{Values: map[string]any{
			"from_urn": "urn:cerebro:tenant-a:aws:session:actor", "to_urn": "urn:cerebro:tenant-a:aws:task:task", "relation": "acted_on", "source_id": "aws", "attributes_json": `{}`,
		}}}
		if !s.omitGroundingEdge {
			rows = append(rows, ports.CypherRow{Values: map[string]any{
				"from_urn": "urn:cerebro:tenant-a:aws:task:task", "to_urn": "urn:cerebro:tenant-a:aws:task-definition:definition", "relation": "depends_on", "source_id": "aws", "attributes_json": `{}`,
			}})
		}
		return rows, nil
	}
	if s.useShadowRows {
		return append([]ports.CypherRow(nil), s.shadowRows...), nil
	}
	for _, actedOn := range s.links {
		if actedOn.Relation != "acted_on" {
			continue
		}
		for _, dependency := range s.links {
			if dependency.Relation == "depends_on" && dependency.FromURN == actedOn.ToURN {
				resourceURNs := []string{actedOn.FromURN, actedOn.ToURN, dependency.ToURN}
				return []ports.CypherRow{{Values: map[string]any{
					"primary_urn": dependency.ToURN, "fingerprint_key": dependency.ToURN,
					"summary": "path", "resource_urns": resourceURNs,
					"evidence": []any{map[string]any{"urn": actedOn.FromURN}, map[string]any{"urn": dependency.ToURN}},
				}}}, nil
			}
		}
	}
	return nil, nil
}

func TestCreateRejectsLiveIdentifiersAndPersistsGroundedDraft(t *testing.T) {
	store := &memoryStore{}
	service := Service{Store: store, Graph: newGraphStore(), Catalog: noOverlapCatalog(), Now: func() time.Time { return time.Unix(100, 0) }}
	request := validCreateRequest()
	request.Hypothesis = "Review arn:aws:iam::123456789012:role/private"
	if _, err := service.Create(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create() error = %v, want invalid request", err)
	}
	request.Hypothesis = "An active workload keeps a secret-bearing execution path."
	candidate, err := service.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Status != StatusGrounded || candidate.Revision != 1 || candidate.PRReady {
		t.Fatalf("candidate = %#v", candidate)
	}
	if candidate.CoverageGap == nil || candidate.CoverageGap.Execution != "finding_rule_catalog" || candidate.CoverageGap.ComparedRuleCount != 1 || len(candidate.CoverageGap.CandidateSignature) != 64 {
		t.Fatalf("coverage gap = %#v", candidate.CoverageGap)
	}
}

func TestCreateFailsClosedWithoutCurrentGraphGrounding(t *testing.T) {
	service := Service{Store: &memoryStore{}}
	if _, err := service.Create(context.Background(), validCreateRequest()); !errors.Is(err, ErrGraphUnavailable) {
		t.Fatalf("Create() error = %v, want graph unavailable", err)
	}
}

func TestCreateRejectsInventedTopology(t *testing.T) {
	graph := newGraphStore()
	graph.omitGroundingEdge = true
	service := Service{Store: &memoryStore{}, Graph: graph, Catalog: noOverlapCatalog()}
	if _, err := service.Create(context.Background(), validCreateRequest()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create() error = %v, want invalid request for absent current edge", err)
	}
}

func TestCreateRejectsInventedRiskAttribute(t *testing.T) {
	graph := newGraphStore()
	service := Service{Store: &memoryStore{}, Graph: graph, Catalog: noOverlapCatalog()}
	request := validCreateRequest()
	request.GraphEvidence.Nodes[2].Attributes["status"] = "INACTIVE"
	if _, err := service.Create(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create() error = %v, want invalid request for mismatched current attribute", err)
	}
}

func TestCreateRejectsOneHopEvidence(t *testing.T) {
	request := validCreateRequest()
	request.GraphEvidence.Nodes = request.GraphEvidence.Nodes[:2]
	request.GraphEvidence.Edges = request.GraphEvidence.Edges[:1]
	request.GraphEvidence.CriticalEdge = policyauthor.GraphEvidenceEdgeRef{FromID: "source-actor", ToID: "source-task", Relation: "acted_on"}
	request.GraphEvidence.EvidenceNodeIDs = []string{"source-actor", "source-task"}
	request.Grounding.Bindings = request.Grounding.Bindings[:2]
	service := Service{Store: &memoryStore{}, Graph: newGraphStore(), Catalog: noOverlapCatalog()}
	if _, err := service.Create(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create() error = %v, want invalid request for one-hop evidence", err)
	}
}

func TestCreateRejectsDisconnectedCriticalEdge(t *testing.T) {
	request := validCreateRequest()
	request.GraphEvidence.Nodes = append(request.GraphEvidence.Nodes, policyauthor.GraphEvidenceNode{ID: "source-extra", SourceID: "aws", EntityType: "aws.extra"})
	request.GraphEvidence.Edges = []policyauthor.GraphEvidenceEdge{
		{FromID: "source-actor", ToID: "source-task", SourceID: "aws", Relation: "acted_on"},
		{FromID: "source-definition", ToID: "source-extra", SourceID: "aws", Relation: "owns"},
	}
	request.GraphEvidence.CriticalEdge = policyauthor.GraphEvidenceEdgeRef{FromID: "source-definition", ToID: "source-extra", Relation: "owns"}
	request.Grounding.Bindings = append(request.Grounding.Bindings, GroundingBinding{NodeID: "source-extra", EntityURN: "urn:cerebro:tenant-a:aws:extra:extra"})
	service := Service{Store: &memoryStore{}, Graph: newGraphStore(), Catalog: noOverlapCatalog()}
	if _, err := service.Create(context.Background(), request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Create() error = %v, want invalid request for disconnected critical edge", err)
	}
}

func TestCreateRejectsExistingSupersetCoverage(t *testing.T) {
	catalog := &coverageCatalog{queries: []CoverageQuery{{
		CatalogKey: "existing-broader-rule", Query: `MATCH (task:Entity)-[dependency:RELATION]->(definition:Entity) RETURN task, dependency, definition LIMIT $row_limit`, SemanticsComplete: true,
		RequiredEntityTypes: []string{"aws.task", "aws.task_definition"},
		RequiredEdges:       []CoverageEdge{{FromEntityType: "aws.task", Relation: "depends_on", ToEntityType: "aws.task_definition"}},
		RequiredPredicates:  []CoveragePredicate{{EntityType: "aws.task_definition", Key: "status", Value: "ACTIVE"}},
	}}}
	service := Service{Store: &memoryStore{}, Graph: newGraphStore(), Catalog: catalog}
	if _, err := service.Create(context.Background(), validCreateRequest()); !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() error = %v, want conflict for broader existing coverage", err)
	}
}

func TestCoverageGapFailsClosedForIncompleteEvaluateRowsBranches(t *testing.T) {
	catalog := &coverageCatalog{queries: []CoverageQuery{{
		CatalogKey: "sentinelone-endpoint-active-infection", Query: `MATCH (agent:Entity)-[:RELATION]->(threat:Entity) RETURN agent, threat LIMIT $row_limit`,
		RequiredEntityTypes: []string{"sentinelone.agent", "sentinelone.threat"}, SemanticsComplete: false,
	}}}
	for _, evidence := range []policyauthor.GraphEvidence{
		{Nodes: []policyauthor.GraphEvidenceNode{{ID: "agent", EntityType: "sentinelone.agent", Attributes: map[string]string{"active_threats": "1"}}}},
		{Nodes: []policyauthor.GraphEvidenceNode{{ID: "threat", EntityType: "sentinelone.threat", Attributes: map[string]string{"is_infected": "true", "active_threats": "1"}}}},
	} {
		if _, err := verifyCoverageGap(context.Background(), catalog, "tenant-a", evidence, time.Now); !errors.Is(err, ErrCoverageUnavailable) {
			t.Fatalf("verifyCoverageGap() error = %v, want fail-closed coverage unavailable", err)
		}
	}
}

func TestProveExcludesOriginAndSourceHandlesFromModelContext(t *testing.T) {
	store := &memoryStore{}
	graph := newGraphStore()
	rule := graphRule()
	raw, _ := json.Marshal(rule)
	model := &draftModel{raw: raw}
	service := Service{Store: store, Author: &agentauthoring.Service{Model: model, PolicyGraphStore: graph}, Graph: graph, Catalog: noOverlapCatalog()}
	candidate, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	proved, err := service.Prove(context.Background(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if proved.Status != StatusProved || proved.Artifacts == nil || proved.Proof == nil || proved.PRReady {
		t.Fatalf("proved candidate = %#v", proved)
	}
	if model.request.TenantID != "tenant-a" {
		t.Fatalf("model tenant = %q, want tenant-a", model.request.TenantID)
	}
	encoded, _ := json.Marshal(model.request)
	for _, forbidden := range []string{"private-slack-ref", "source-actor", "source-task", "source-definition"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("model request contains %q: %s", forbidden, encoded)
		}
	}
}

func TestProveRechecksCatalogBeforeAuthoring(t *testing.T) {
	store := &memoryStore{}
	graph := newGraphStore()
	catalog := noOverlapCatalog()
	model := &draftModel{raw: []byte(`{}`)}
	service := Service{Store: store, Author: &agentauthoring.Service{Model: model, PolicyGraphStore: graph}, Graph: graph, Catalog: catalog}
	candidate, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	catalog.queries = []CoverageQuery{{
		CatalogKey: "rule-added-after-create", Query: `MATCH (task:Entity)-[dependency:RELATION]->(definition:Entity) RETURN definition LIMIT $row_limit`, SemanticsComplete: true,
		RequiredEntityTypes: []string{"aws.task", "aws.task_definition"}, RequiredEdges: []CoverageEdge{{FromEntityType: "aws.task", Relation: "depends_on", ToEntityType: "aws.task_definition"}},
		RequiredPredicates: []CoveragePredicate{{EntityType: "aws.task_definition", Key: "status", Value: "ACTIVE"}},
	}}
	if _, err := service.Prove(context.Background(), candidate.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("Prove() error = %v, want conflict for newly covered signature", err)
	}
	if model.request.Kind != "" {
		t.Fatalf("model was called before duplicate coverage rejection: %#v", model.request)
	}
}

func TestShadowSetsRuntimeBoundsAndReviewReadiness(t *testing.T) {
	store := &memoryStore{}
	graph := newGraphStore()
	graph.useShadowRows = true
	graph.shadowRows = []ports.CypherRow{{Values: map[string]any{"primary_urn": "local"}}}
	service := Service{Store: store, Graph: graph, Catalog: noOverlapCatalog()}
	candidate, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	candidate.Status = StatusProved
	candidate.Artifacts = &Artifacts{Rule: graphRule(), PolicyDigest: strings.Repeat("a", 64), TestDigest: strings.Repeat("b", 64)}
	candidate.Proof = &policyauthor.ProofResult{PolicyID: "candidate-graph-path"}
	if err := store.SavePolicyCandidate(context.Background(), candidate, 1); err != nil {
		t.Fatal(err)
	}
	shadowed, err := service.Shadow(context.Background(), candidate.ID)
	if err != nil {
		t.Fatal(err)
	}
	if shadowed.Status != StatusReadyForReview || !shadowed.PRReady || shadowed.Shadow == nil || shadowed.Shadow.ReceiptID == "" {
		t.Fatalf("shadowed candidate = %#v", shadowed)
	}
	request := graph.requests[len(graph.requests)-1]
	if request.RowLimit != MaxShadowRows+1 || request.Params["row_limit"] != MaxShadowRows+1 || request.Params["tenant_id"] != "tenant-a" {
		t.Fatalf("shadow request = %#v", request)
	}
}

func TestShadowZeroMatchesPreservesProvedState(t *testing.T) {
	store := &memoryStore{}
	graph := newGraphStore()
	graph.useShadowRows = true
	service := Service{Store: store, Graph: graph, Catalog: noOverlapCatalog()}
	candidate := createProvedCandidate(t, service, store)
	result, err := service.Shadow(context.Background(), candidate.ID)
	if err != nil || result == nil {
		t.Fatalf("Shadow() result = %#v error = %v, want explicit non-ready receipt", result, err)
	}
	if result.Status != StatusProved || result.PRReady || result.Shadow == nil || result.Shadow.MatchCount != 0 || result.Shadow.Truncated {
		t.Fatalf("shadow result = %#v", result)
	}
	stored, _ := store.GetPolicyCandidate(context.Background(), candidate.ID)
	if stored.Status != StatusProved || stored.PRReady {
		t.Fatalf("stored candidate = %#v", stored)
	}
}

func TestShadowTruncatedMatchesPreservesProvedState(t *testing.T) {
	store := &memoryStore{}
	graph := newGraphStore()
	graph.useShadowRows = true
	for index := 0; index < MaxShadowRows+1; index++ {
		graph.shadowRows = append(graph.shadowRows, ports.CypherRow{Values: map[string]any{"primary_urn": "local"}})
	}
	service := Service{Store: store, Graph: graph, Catalog: noOverlapCatalog()}
	candidate := createProvedCandidate(t, service, store)
	result, err := service.Shadow(context.Background(), candidate.ID)
	if err != nil || result == nil {
		t.Fatalf("Shadow() result = %#v error = %v, want explicit truncated receipt", result, err)
	}
	if result.Status != StatusProved || result.PRReady || result.Shadow == nil || !result.Shadow.Truncated {
		t.Fatalf("shadow result = %#v", result)
	}
}

func createProvedCandidate(t *testing.T, service Service, store *memoryStore) *Candidate {
	t.Helper()
	candidate, err := service.Create(context.Background(), validCreateRequest())
	if err != nil {
		t.Fatal(err)
	}
	candidate.Status = StatusProved
	candidate.Artifacts = &Artifacts{Rule: graphRule(), PolicyDigest: strings.Repeat("a", 64), TestDigest: strings.Repeat("b", 64)}
	candidate.Proof = &policyauthor.ProofResult{PolicyID: "candidate-graph-path"}
	if err := store.SavePolicyCandidate(context.Background(), candidate, 1); err != nil {
		t.Fatal(err)
	}
	return candidate
}

func validCreateRequest() CreateRequest {
	return CreateRequest{
		TenantID: "tenant-a", Hypothesis: "An active workload keeps a secret-bearing execution path.", Domain: "aws",
		Origin: Origin{Kind: "slack_thread", ExternalRef: "private-slack-ref"},
		GraphEvidence: &policyauthor.GraphEvidence{
			Nodes:        []policyauthor.GraphEvidenceNode{{ID: "source-actor", SourceID: "aws", EntityType: "aws.session"}, {ID: "source-task", SourceID: "aws", EntityType: "aws.task"}, {ID: "source-definition", SourceID: "aws", EntityType: "aws.task_definition", Attributes: map[string]string{"status": "ACTIVE"}}},
			Edges:        []policyauthor.GraphEvidenceEdge{{FromID: "source-actor", ToID: "source-task", SourceID: "aws", Relation: "acted_on"}, {FromID: "source-task", ToID: "source-definition", SourceID: "aws", Relation: "depends_on"}},
			CriticalEdge: policyauthor.GraphEvidenceEdgeRef{FromID: "source-task", ToID: "source-definition", Relation: "depends_on"}, EvidenceNodeIDs: []string{"source-actor", "source-definition"},
		},
		Grounding: GroundingRequest{Bindings: []GroundingBinding{
			{NodeID: "source-actor", EntityURN: "urn:cerebro:tenant-a:aws:session:actor"},
			{NodeID: "source-task", EntityURN: "urn:cerebro:tenant-a:aws:task:task"},
			{NodeID: "source-definition", EntityURN: "urn:cerebro:tenant-a:aws:task-definition:definition"},
		}},
	}
}

func noOverlapCatalog() *coverageCatalog {
	return &coverageCatalog{queries: []CoverageQuery{{
		CatalogKey:          "existing-bucket-rule",
		Query:               `MATCH (bucket:Entity {tenant_id: $tenant_id}) WHERE bucket.entity_type = 'aws.bucket' RETURN bucket LIMIT $row_limit`,
		RequiredEntityTypes: []string{"aws.bucket"}, SemanticsComplete: true,
	}}}
}

func graphRule() findingdsl.PolicyFindingRule {
	return findingdsl.NewPolicyRule(findingdsl.NewPolicyRuleInput{
		ID: "candidate-graph-path", Name: "Candidate graph path", Description: "Finds a current causal graph path.", Severity: "high",
		Graph:      findingdsl.PolicyRuleGraphFinding{Query: `MATCH (actor:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'acted_on'}]->(task:Entity)-[:RELATION {relation: 'depends_on'}]->(definition:Entity) RETURN definition.urn AS primary_urn, definition.urn AS fingerprint_key, 'path' AS summary, [actor.urn, task.urn, definition.urn] AS resource_urns, [{urn: actor.urn}, {urn: definition.urn}] AS evidence LIMIT $row_limit`, RowLimit: 100, RequiredColumns: []string{"primary_urn", "fingerprint_key", "summary", "resource_urns"}},
		Frameworks: []findingdsl.PolicyFramework{{Name: "SOC 2", Controls: []string{"CC6.1"}}},
	})
}

func cloneCandidate(candidate *Candidate) *Candidate {
	payload, _ := json.Marshal(candidate)
	var cloned Candidate
	_ = json.Unmarshal(payload, &cloned)
	return &cloned
}
