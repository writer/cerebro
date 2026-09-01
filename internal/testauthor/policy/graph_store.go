package policy

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/ports"
)

// CompatibilityGraphTestStore confines authored-policy query execution to the
// test-authoring infrastructure boundary. Product and domain services receive
// only findingdsl's typed policy-fixture operation.
type CompatibilityGraphTestStore struct {
	projection findingdsl.PolicyGraphFixtureStore
	queries    ports.RawCypherQueryStore
}

func NewCompatibilityGraphTestStore(projection findingdsl.PolicyGraphFixtureStore, queries ports.RawCypherQueryStore) *CompatibilityGraphTestStore {
	return &CompatibilityGraphTestStore{projection: projection, queries: queries}
}

func (s *CompatibilityGraphTestStore) Ping(ctx context.Context) error {
	if s == nil || s.projection == nil {
		return errors.New("policy graph fixture projection is unavailable")
	}
	return s.projection.Ping(ctx)
}

func (s *CompatibilityGraphTestStore) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	if s == nil || s.projection == nil {
		return errors.New("policy graph fixture projection is unavailable")
	}
	return s.projection.UpsertProjectedEntity(ctx, entity)
}

func (s *CompatibilityGraphTestStore) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if s == nil || s.projection == nil {
		return errors.New("policy graph fixture projection is unavailable")
	}
	return s.projection.UpsertProjectedLink(ctx, link)
}

func (s *CompatibilityGraphTestStore) DeleteProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if s == nil || s.projection == nil {
		return errors.New("policy graph fixture projection is unavailable")
	}
	return s.projection.DeleteProjectedLink(ctx, link)
}

func (s *CompatibilityGraphTestStore) DeleteProjectedEntity(ctx context.Context, urn string) error {
	if s == nil || s.projection == nil {
		return errors.New("policy graph fixture projection is unavailable")
	}
	return s.projection.DeleteProjectedEntity(ctx, urn)
}

func (s *CompatibilityGraphTestStore) EvaluatePolicyGraph(ctx context.Context, request findingdsl.PolicyGraphEvaluationRequest) ([]map[string]any, error) {
	if s == nil || s.queries == nil {
		return nil, errors.New("policy graph fixture query authority is unavailable")
	}
	tenantID := strings.TrimSpace(request.TenantID)
	query := strings.TrimSpace(request.Rule.Spec.Graph.Query)
	rowLimit := request.Rule.Spec.Graph.RowLimit
	if tenantID == "" || query == "" || rowLimit <= 0 {
		return nil, errors.New("policy graph fixture query, tenant, and row limit are required")
	}
	params := make(map[string]any, len(request.Rule.Spec.Graph.Params)+2)
	for key, value := range request.Rule.Spec.Graph.Params {
		params[key] = value
	}
	params["tenant_id"] = tenantID
	params["row_limit"] = int64(rowLimit)
	rows, err := s.queries.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: query, Params: params, RowLimit: rowLimit})
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.Values)
	}
	return result, nil
}

var _ findingdsl.PolicyGraphTestStore = (*CompatibilityGraphTestStore)(nil)
