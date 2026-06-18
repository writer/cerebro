package graphagent

import (
	"context"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

func TestValidatorRejectsUnsafeCypher(t *testing.T) {
	tests := []struct {
		name   string
		cypher string
		reason string
	}{
		{
			name:   "create token",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) CREATE (x) RETURN e.urn LIMIT 25`,
			reason: "forbidden",
		},
		{
			name:   "load csv",
			cypher: `LOAD CSV FROM 'file:///tmp/x.csv' AS row MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn LIMIT 25`,
			reason: "forbidden",
		},
		{
			name:   "periodic apoc",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) CALL apoc.periodic.iterate('a','b',{}) RETURN e.urn LIMIT 25`,
			reason: "apoc",
		},
		{
			name:   "apoc function",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN apoc.convert.fromJsonMap(e.attributes_json).source_family AS source_family LIMIT 25`,
			reason: "APOC",
		},
		{
			name:   "escaped apoc function",
			cypher: "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN `apoc.convert.fromJsonMap`(e.attributes_json).source_family AS source_family LIMIT 25",
			reason: "APOC",
		},
		{
			name:   "missing limit",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn`,
			reason: "LIMIT",
		},
		{
			name:   "limit too high",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn LIMIT 101`,
			reason: "exceeds",
		},
		{
			name:   "missing tenant",
			cypher: `MATCH (e:Entity) RETURN e.urn LIMIT 25`,
			reason: "tenant_id",
		},
		{
			name:   "unscoped second entity",
			cypher: `MATCH (a:Entity {tenant_id: $tenant_id}) MATCH (b:Entity) RETURN b.urn LIMIT 25`,
			reason: "every node",
		},
		{
			name: "comment marker inside string does not hide unscoped match",
			cypher: `MATCH (a:Entity {tenant_id:$tenant_id})
WITH a, 'x //' AS c MATCH (b:Entity)
RETURN b.urn AS urn LIMIT 25`,
			reason: "every node",
		},
		{
			name:   "write clause after comment marker inside string",
			cypher: `MATCH (a:Entity {tenant_id:$tenant_id}) WITH 'x //' AS c CREATE (b:Entity) RETURN b LIMIT 25`,
			reason: "forbidden",
		},
		{
			name:   "unlabeled second node",
			cypher: `MATCH (a:Entity {tenant_id: $tenant_id}), (b) RETURN b LIMIT 25`,
			reason: "every node",
		},
		{
			name:   "neutralized tenant predicate",
			cypher: `MATCH (e:Entity) WHERE e.tenant_id = $tenant_id OR true RETURN e LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "pattern comprehension unscoped nodes",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN [(x:Entity)-[:RELATION]->(y:Entity) | x.urn][0..10] AS leaks LIMIT 1`,
			reason: "inline tenant_id",
		},
		{
			name:   "with boundary drops scoped variable",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) WITH count(*) AS n MATCH (e) RETURN e.urn LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "union boundary resets scoped variables",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS urn LIMIT 25 UNION MATCH (e) RETURN e.urn AS urn LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "union branch limit too high",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS urn LIMIT 1000 UNION MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e.urn AS urn LIMIT 25`,
			reason: "exceeds",
		},
		{
			name:   "call subquery has independent scope",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) CALL { MATCH (e) RETURN e.urn AS leaked LIMIT 25 } RETURN leaked LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "global read procedure",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) WITH count(*) AS _ CALL db.labels() YIELD label RETURN label LIMIT 25`,
			reason: "procedure CALL",
		},
		{
			name:   "unwind expansion",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) UNWIND range(1, 1000000) AS i RETURN e.urn, i LIMIT 1`,
			reason: "row-expanding",
		},
		{
			name:   "collect expansion before limit",
			cypher: `MATCH (e:Entity {tenant_id: $tenant_id}) RETURN collect(e.attributes_json) AS attributes LIMIT 1`,
			reason: "row-expanding",
		},
		{
			name:   "escaped collect expansion before limit",
			cypher: "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN `collect`(e.attributes_json) AS attributes LIMIT 1",
			reason: "row-expanding",
		},
		{
			name:   "escaped range expansion before limit",
			cypher: "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN `range`(1, 1000000) AS ids LIMIT 1",
			reason: "row-expanding",
		},
		{
			name:   "call local binding cannot escape",
			cypher: `MATCH (seed:Entity {tenant_id: $tenant_id}) CALL { WITH seed MATCH (seed)-[:RELATION]->(tmp:Entity {tenant_id: $tenant_id}) RETURN 1 AS keep LIMIT 1 } MATCH (tmp) RETURN tmp.urn LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "expression local binding cannot escape",
			cypher: `MATCH (seed:Entity {tenant_id: $tenant_id}) WITH [(tmp:Entity {tenant_id: $tenant_id})-[:RELATION]->(:Entity {tenant_id: $tenant_id}) | tmp.urn][0] AS first MATCH (tmp) RETURN tmp.urn LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "existential subquery binding cannot escape",
			cypher: `MATCH (seed:Entity {tenant_id: $tenant_id}) WHERE EXISTS { MATCH (tmp:Entity {tenant_id: $tenant_id}) RETURN tmp LIMIT 1 } MATCH (tmp) RETURN tmp.urn LIMIT 25`,
			reason: "inline tenant_id",
		},
		{
			name:   "unparseable nested property pattern fails closed",
			cypher: `MATCH (seed:Entity {tenant_id: $tenant_id}) RETURN [(x:Entity {metadata: {tenant_id: $tenant_id}}) | x.urn] AS urn LIMIT 25`,
			reason: "every node",
		},
	}

	validator := NewValidator(nil, ValidatorOptions{})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := validator.validate(context.Background(), tt.cypher, map[string]any{"tenant_id": "example"})
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.OK {
				t.Fatalf("Validate() ok = true, want false")
			}
			if !strings.Contains(result.Reason, tt.reason) {
				t.Fatalf("reason = %q, want substring %q", result.Reason, tt.reason)
			}
		})
	}
}

func TestValidatorPreservesCodeForOversizedUnionLimit(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, _, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS urn
LIMIT 1000
UNION
MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.OK {
		t.Fatalf("Validate() ok = true, want false")
	}
	if result.Code != "limit_exceeded" {
		t.Fatalf("code = %q, want limit_exceeded; result = %#v", result.Code, result)
	}
}

func FuzzValidatorMaliciousCorpus(f *testing.F) {
	for _, cypher := range []string{
		`MATCH (a:Entity {tenant_id:$tenant_id}) WITH 'x //' AS c CREATE (b:Entity) RETURN b LIMIT 25`,
		`MATCH (a:Entity {tenant_id:$tenant_id}) WITH "/*" AS c MATCH (b:Entity) RETURN b LIMIT 25`,
		`MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 25 UNION MATCH (x:Entity {tenant_id: $tenant_id}) RETURN x LIMIT 1000`,
		`MATCH (seed:Entity {tenant_id: $tenant_id}) RETURN [(x:Entity {metadata: {tenant_id: $tenant_id}}) | x.urn] AS urn LIMIT 25`,
		`LOAD CSV FROM 'https://example.test/x.csv' AS row RETURN row LIMIT 1`,
		`MATCH (e:Entity {tenant_id:$tenant_id}) CALL db.labels() YIELD label RETURN label LIMIT 25`,
	} {
		f.Add(cypher)
	}
	validator := NewValidator(nil, ValidatorOptions{})
	f.Fuzz(func(t *testing.T, cypher string) {
		if len(cypher) > 4096 {
			t.Skip("query too large for validator fuzz seed")
		}
		_, _, _ = validator.validate(context.Background(), cypher, map[string]any{"tenant_id": "example"})
	})
}

func TestValidatorAcceptsBoundedTenantScopedRead(t *testing.T) {
	store := &validatorStore{}
	validator := NewValidator(store, ValidatorOptions{Explain: true})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS urn
ORDER BY urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
	if len(store.requests) != 1 || !strings.HasPrefix(store.requests[0].Query, "MATCH") {
		t.Fatalf("EXPLAIN requests = %#v", store.requests)
	}
}

func TestValidatorAcceptsAPOCVariablePropertyAccess(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (apoc:Entity {tenant_id: $tenant_id})
RETURN apoc.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsScopedRelationshipReadWithReturnFunctions(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (src:Entity {tenant_id: $tenant_id})-[r:RELATION]->(dst:Entity {tenant_id: $tenant_id})
RETURN src.urn AS src, dst.urn AS dst, coalesce(src.label, src.urn) AS label
ORDER BY label
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsEscapedLimitAlias(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS `+"`limit`"+`
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsBoundVariableReuse(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
OPTIONAL MATCH (e)-[:RELATION]->(b:Entity {tenant_id: $tenant_id})
RETURN b.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsWithProjectedBoundVariable(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
WITH e
MATCH (e)-[:RELATION]->(b:Entity {tenant_id: $tenant_id})
RETURN b.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsLowercaseDistinctWithProjection(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
WITH distinct e
MATCH (e)-[:RELATION]->(b:Entity {tenant_id: $tenant_id})
RETURN b.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsCallSubqueryWithImportedScopedVariable(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
CALL {
  WITH e
  MATCH (e)-[:RELATION]->(b:Entity {tenant_id: $tenant_id})
  RETURN b.urn AS urn
  LIMIT 25
}
RETURN urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsReturnedScopedSubqueryVariable(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (seed:Entity {tenant_id: $tenant_id})
CALL {
  WITH seed
  MATCH (seed)-[:RELATION]->(tmp:Entity {tenant_id: $tenant_id})
  RETURN tmp
  LIMIT 25
}
MATCH (tmp)-[:RELATION]->(b:Entity {tenant_id: $tenant_id})
RETURN b.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorAcceptsUnionBranchesWithImportedScopedVariable(t *testing.T) {
	validator := NewValidator(nil, ValidatorOptions{})
	result, limit, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
CALL {
  WITH e
  MATCH (e)-[:RELATION]->(b:Entity {tenant_id: $tenant_id})
  RETURN b AS hit
  LIMIT 25
  UNION
  WITH e
  MATCH (e)-[:OTHER]->(b:Entity {tenant_id: $tenant_id})
  RETURN b AS hit
  LIMIT 25
}
RETURN hit.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !result.OK {
		t.Fatalf("Validate() = %#v, want ok", result)
	}
	if limit != 25 {
		t.Fatalf("limit = %d, want 25", limit)
	}
}

func TestValidatorRejectsAllNodesScanOverLimit(t *testing.T) {
	store := &validatorStore{plan: &ports.CypherPlan{Root: &ports.CypherPlanNode{
		Operator:  "AllNodesScan",
		Arguments: map[string]any{"EstimatedRows": 2_000_001},
	}}}
	validator := NewValidator(store, ValidatorOptions{Explain: true, AllNodesScanLimit: 1_000_000})
	result, _, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.OK {
		t.Fatalf("Validate() ok = true, want false")
	}
	if !strings.Contains(result.Reason, "AllNodesScan") {
		t.Fatalf("reason = %q, want AllNodesScan", result.Reason)
	}
}

func TestValidatorDefaultsToExplainWhenStoreSupportsPlans(t *testing.T) {
	store := &validatorStore{plan: &ports.CypherPlan{Root: &ports.CypherPlanNode{
		Operator:  "AllNodesScan",
		Arguments: map[string]any{"EstimatedRows": 2_000_001},
	}}}
	validator := NewValidator(store, ValidatorOptions{AllNodesScanLimit: 1_000_000})
	result, _, err := validator.validate(context.Background(), `MATCH (e:Entity {tenant_id: $tenant_id})
RETURN e.urn AS urn
LIMIT 25`, map[string]any{"tenant_id": "example"})
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.OK {
		t.Fatalf("Validate() ok = true, want false")
	}
	if len(store.requests) != 1 {
		t.Fatalf("EXPLAIN requests = %d, want 1", len(store.requests))
	}
}

type validatorStore struct {
	requests []ports.CypherQueryRequest
	rows     []ports.CypherRow
	plan     *ports.CypherPlan
	err      error
}

func (s *validatorStore) Ping(context.Context) error { return nil }

func (s *validatorStore) PutEntity(context.Context, *ports.ProjectedEntity) error { return nil }

func (s *validatorStore) PutRelation(context.Context, *ports.ProjectedLink) error { return nil }

func (s *validatorStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, ports.ErrGraphEntityNotFound
}

func (s *validatorStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	if s.err != nil {
		return nil, s.err
	}
	return s.rows, nil
}

func (s *validatorStore) ExplainReadCypher(_ context.Context, request ports.CypherQueryRequest) (*ports.CypherPlan, error) {
	s.requests = append(s.requests, request)
	if s.err != nil {
		return nil, s.err
	}
	return s.plan, nil
}

var _ ports.GraphQueryStore = (*validatorStore)(nil)
