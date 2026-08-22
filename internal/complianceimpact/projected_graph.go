package complianceimpact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceintegration"
	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	impactProjectionSourceID   = "compliance"
	impactProjectionEntityType = "compliance.impact_revision"
	impactDependencyRelation   = "compliance_depends_on"
	maxFactDependencies        = ports.MaxCypherQueryRows - 1
)

const getImpactFactQuery = `MATCH (fact:Entity {urn: $urn, tenant_id: $tenant_id, entity_type: $entity_type})
RETURN fact.attributes_json AS attributes`

const countImpactDependenciesQuery = `MATCH (fact:Entity {urn: $urn, tenant_id: $tenant_id, entity_type: $entity_type})
OPTIONAL MATCH (fact)-[edge:RELATION {relation: $relation, tenant_id: $tenant_id}]->(dependency:Entity {tenant_id: $tenant_id, entity_type: $entity_type})
RETURN count(edge) AS dependency_count`

const listImpactDependenciesQuery = `MATCH (fact:Entity {urn: $urn, tenant_id: $tenant_id, entity_type: $entity_type})-[edge:RELATION {relation: $relation, tenant_id: $tenant_id}]->(dependency:Entity {tenant_id: $tenant_id, entity_type: $entity_type})
RETURN dependency.attributes_json AS attributes, edge.attributes_json AS edge_attributes
ORDER BY dependency.urn, edge.attributes_json`

const listImpactDependentsQuery = `MATCH (dependent:Entity {tenant_id: $tenant_id, entity_type: $entity_type})-[edge:RELATION {relation: $relation, tenant_id: $tenant_id}]->(dependency:Entity {urn: $dependency_urn, tenant_id: $tenant_id, entity_type: $entity_type})
WHERE dependent.urn > $after_cursor
RETURN DISTINCT dependent.urn AS cursor, dependent.attributes_json AS attributes
ORDER BY cursor
LIMIT $row_limit`

// GraphProjector writes exact immutable compliance facts into the shared graph
// projection. It stores identifiers and revision metadata only; lifecycle data
// remains in its owning service and append log.
type GraphProjector struct {
	graph ports.ProjectionGraphStore
}

func NewGraphProjector(graph ports.ProjectionGraphStore) (*GraphProjector, error) {
	if graph == nil {
		return nil, ErrImpactProjectionUnavailable
	}
	return &GraphProjector{graph: graph}, nil
}

func (p *GraphProjector) ProjectFact(ctx context.Context, fact complianceintegration.DomainFact) error {
	if p == nil || p.graph == nil {
		return ErrImpactProjectionUnavailable
	}
	root, err := projectedImpactEntity(fact.Revision())
	if err != nil {
		return err
	}
	entities := []*ports.ProjectedEntity{root}
	links := make([]*ports.ProjectedLink, 0, len(fact.Dependencies()))
	seen := map[string]struct{}{root.URN: {}}
	for _, dependency := range fact.Dependencies() {
		entity, entityErr := projectedImpactEntity(dependency.Revision())
		if entityErr != nil {
			return entityErr
		}
		if _, ok := seen[entity.URN]; !ok {
			seen[entity.URN] = struct{}{}
			entities = append(entities, entity)
		}
		links = append(links, &ports.ProjectedLink{
			TenantID: root.TenantID, SourceID: impactProjectionSourceID,
			FromURN: root.URN, ToURN: entity.URN, Relation: impactDependencyRelation,
			Attributes: map[string]string{"dependency_relation": dependency.Relation()},
		})
	}
	if err := ports.ValidateProjectedTenantScopes(entities, links); err != nil {
		return err
	}
	if batch, ok := p.graph.(ports.ProjectionGraphBatchStore); ok {
		if err := batch.UpsertProjectedEntities(ctx, entities); err != nil {
			return fmt.Errorf("project compliance impact entities: %w", err)
		}
		if len(links) != 0 {
			if err := batch.UpsertProjectedLinks(ctx, links); err != nil {
				return fmt.Errorf("project compliance impact dependencies: %w", err)
			}
			return nil
		}
		return nil
	}
	for _, entity := range entities {
		if err := p.graph.UpsertProjectedEntity(ctx, entity); err != nil {
			return fmt.Errorf("project compliance impact entity: %w", err)
		}
	}
	for _, link := range links {
		if err := p.graph.UpsertProjectedLink(ctx, link); err != nil {
			return fmt.Errorf("project compliance impact dependency: %w", err)
		}
	}
	return nil
}

// ProjectedGraph reads the exact-revision projection through bounded read-only
// Cypher. It is intentionally independent from the Neo4j driver so tests and
// alternate graph stores can implement the same port.
type ProjectedGraph struct {
	queries ports.RawCypherQueryStore
}

func NewProjectedGraph(queries ports.RawCypherQueryStore) (*ProjectedGraph, error) {
	if queries == nil {
		return nil, ErrInvalidGraph
	}
	return &ProjectedGraph{queries: queries}, nil
}

func (g *ProjectedGraph) GetComplianceImpactFact(ctx context.Context, tenantID string, requested ports.ComplianceImpactRevisionRef) (ports.ComplianceImpactDomainFact, error) {
	if g == nil || g.queries == nil {
		return ports.ComplianceImpactDomainFact{}, ErrInvalidGraph
	}
	revision, err := adaptPortRevision(requested)
	if err != nil || revision.TenantID() != strings.TrimSpace(tenantID) {
		return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: invalid exact revision", ErrInvalidGraph)
	}
	urn, err := impactRevisionURN(revision)
	if err != nil {
		return ports.ComplianceImpactDomainFact{}, err
	}
	params := impactQueryParams(tenantID)
	params["urn"] = urn
	rows, err := g.queries.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: getImpactFactQuery, Params: params, RowLimit: 2})
	if err != nil {
		return ports.ComplianceImpactDomainFact{}, err
	}
	if len(rows) == 0 {
		return ports.ComplianceImpactDomainFact{}, ports.ErrComplianceImpactRevisionNotFound
	}
	if len(rows) != 1 {
		return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: duplicate exact revision", ErrInvalidGraph)
	}
	stored, err := impactRevisionFromRow(rows[0])
	if err != nil || !stored.Equal(revision) {
		return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: projected revision does not match request", ErrInvalidGraph)
	}
	countRows, err := g.queries.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: countImpactDependenciesQuery, Params: params, RowLimit: 1})
	if err != nil {
		return ports.ComplianceImpactDomainFact{}, err
	}
	if len(countRows) != 1 {
		return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: dependency count is unavailable", ErrInvalidGraph)
	}
	count, ok := nonnegativeInt(countRows[0].Values["dependency_count"])
	if !ok || count > maxFactDependencies {
		return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: exact revision has an invalid dependency count", ErrInvalidGraph)
	}
	dependencies := make([]ports.ComplianceImpactDependencyRef, 0, count)
	if count != 0 {
		rows, readErr := g.queries.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: listImpactDependenciesQuery, Params: params, RowLimit: count})
		if readErr != nil {
			return ports.ComplianceImpactDomainFact{}, readErr
		}
		if len(rows) != count {
			return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: dependency count changed during read", ErrInvalidGraph)
		}
		for _, row := range rows {
			dependency, decodeErr := impactRevisionFromRow(row)
			if decodeErr != nil || dependency.TenantID() != tenantID {
				return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: projected dependency is invalid", ErrInvalidGraph)
			}
			edgeAttributes, decodeErr := decodeGraphAttributes(row.Values["edge_attributes"])
			if decodeErr != nil || strings.TrimSpace(edgeAttributes["dependency_relation"]) == "" {
				return ports.ComplianceImpactDomainFact{}, fmt.Errorf("%w: projected dependency relation is invalid", ErrInvalidGraph)
			}
			dependencies = append(dependencies, ports.ComplianceImpactDependencyRef{Revision: portRevision(dependency), Relation: edgeAttributes["dependency_relation"]})
		}
	}
	return ports.ComplianceImpactDomainFact{Revision: portRevision(stored), Dependencies: dependencies}, nil
}

func (g *ProjectedGraph) ListComplianceImpactDependents(ctx context.Context, request ports.ComplianceImpactDependentRequest) (ports.ComplianceImpactDependentPage, error) {
	if g == nil || g.queries == nil || request.Limit == 0 || request.Limit >= ports.MaxCypherQueryRows {
		return ports.ComplianceImpactDependentPage{}, ErrInvalidGraph
	}
	tenantID := strings.TrimSpace(request.TenantID)
	afterCursor := strings.TrimSpace(request.AfterCursor)
	dependency, err := adaptPortRevision(request.Dependency)
	if err != nil || dependency.TenantID() != tenantID {
		return ports.ComplianceImpactDependentPage{}, fmt.Errorf("%w: invalid dependency revision", ErrInvalidGraph)
	}
	urn, err := impactRevisionURN(dependency)
	if err != nil {
		return ports.ComplianceImpactDependentPage{}, err
	}
	params := impactQueryParams(tenantID)
	params["dependency_urn"] = urn
	params["after_cursor"] = afterCursor
	params["row_limit"] = int(request.Limit) + 1
	rows, err := g.queries.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: listImpactDependentsQuery, Params: params, RowLimit: int(request.Limit) + 1})
	if err != nil {
		return ports.ComplianceImpactDependentPage{}, err
	}
	complete := len(rows) <= int(request.Limit)
	if !complete {
		rows = rows[:request.Limit]
	}
	page := ports.ComplianceImpactDependentPage{Dependents: make([]ports.ComplianceImpactRevisionRef, 0, len(rows)), Complete: complete}
	lastCursor := ""
	for _, row := range rows {
		cursor, ok := row.Values["cursor"].(string)
		if !ok || strings.TrimSpace(cursor) == "" || cursor <= lastCursor || (afterCursor != "" && cursor <= afterCursor) {
			return ports.ComplianceImpactDependentPage{}, fmt.Errorf("%w: dependent cursor is invalid", ErrInvalidGraph)
		}
		revision, decodeErr := impactRevisionFromRow(row)
		if decodeErr != nil || revision.TenantID() != tenantID {
			return ports.ComplianceImpactDependentPage{}, fmt.Errorf("%w: projected dependent is invalid", ErrInvalidGraph)
		}
		expectedCursor, urnErr := impactRevisionURN(revision)
		if urnErr != nil || cursor != expectedCursor {
			return ports.ComplianceImpactDependentPage{}, fmt.Errorf("%w: dependent cursor does not match its exact revision", ErrInvalidGraph)
		}
		page.Dependents = append(page.Dependents, portRevision(revision))
		lastCursor = cursor
	}
	if !complete {
		page.NextCursor = lastCursor
	}
	return page, nil
}

func projectedImpactEntity(revision complianceintegration.RevisionRef) (*ports.ProjectedEntity, error) {
	urn, err := impactRevisionURN(revision)
	if err != nil {
		return nil, err
	}
	return &ports.ProjectedEntity{
		URN: urn, TenantID: revision.TenantID(), SourceID: impactProjectionSourceID,
		EntityType: impactProjectionEntityType,
		Label:      revision.Domain() + "/" + string(revision.Kind()) + "/" + revision.ID() + "@" + revision.RevisionID(),
		Attributes: map[string]string{
			"tenant_id": revision.TenantID(), "domain": revision.Domain(), "fact_kind": string(revision.Kind()),
			"stable_id": revision.ID(), "revision_id": revision.RevisionID(), "revision_version": strconv.FormatUint(revision.Version(), 10),
			"content_digest": string(revision.Canonical().ContentDigest), "last_modified": revision.Canonical().LastModified.Format(time.RFC3339Nano),
		},
	}, nil
}

func impactRevisionURN(revision complianceintegration.RevisionRef) (string, error) {
	if revision.ExactKey() == "" {
		return "", ErrInvalidGraph
	}
	exactID := cerebrourn.StableExternalID(revision.ExactKey(), "revision-missing")
	return cerebrourn.Mint(revision.TenantID(), "compliance_impact_revision",
		cerebrourn.EncodeSegment(revision.Domain()), cerebrourn.EncodeSegment(string(revision.Kind())),
		cerebrourn.EncodeSegment(revision.ID()), cerebrourn.EncodeSegment(revision.RevisionID()), exactID)
}

func impactQueryParams(tenantID string) map[string]any {
	return map[string]any{
		"tenant_id": strings.TrimSpace(tenantID), "entity_type": impactProjectionEntityType,
		"relation": impactDependencyRelation,
	}
}

func impactRevisionFromRow(row ports.CypherRow) (complianceintegration.RevisionRef, error) {
	attributes, err := decodeGraphAttributes(row.Values["attributes"])
	if err != nil {
		return complianceintegration.RevisionRef{}, err
	}
	version, err := strconv.ParseUint(attributes["revision_version"], 10, 64)
	if err != nil {
		return complianceintegration.RevisionRef{}, err
	}
	lastModified, err := time.Parse(time.RFC3339Nano, attributes["last_modified"])
	if err != nil {
		return complianceintegration.RevisionRef{}, err
	}
	return adaptPortRevision(ports.ComplianceImpactRevisionRef{
		TenantID: attributes["tenant_id"], Domain: attributes["domain"], Kind: attributes["fact_kind"],
		ID: attributes["stable_id"], RevisionID: attributes["revision_id"], Version: version,
		ContentDigest: attributes["content_digest"], LastModified: lastModified,
	})
}

func decodeGraphAttributes(value any) (map[string]string, error) {
	switch typed := value.(type) {
	case string:
		result := map[string]string{}
		if err := json.Unmarshal([]byte(typed), &result); err != nil {
			return nil, err
		}
		return result, nil
	case map[string]string:
		return typed, nil
	case map[string]any:
		result := make(map[string]string, len(typed))
		for key, raw := range typed {
			text, ok := raw.(string)
			if !ok {
				return nil, errors.New("graph attribute is not a string")
			}
			result[key] = text
		}
		return result, nil
	default:
		return nil, errors.New("graph attributes are unavailable")
	}
}

func nonnegativeInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, typed >= 0
	case int64:
		if typed < 0 || typed > int64(^uint(0)>>1) {
			return 0, false
		}
		return int(typed), true
	case float64:
		value := int(typed)
		return value, typed >= 0 && float64(value) == typed
	default:
		return 0, false
	}
}
