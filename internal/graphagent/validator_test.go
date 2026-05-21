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
			reason: "every Entity",
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
