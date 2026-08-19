package graphquery

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultPersonAccessPathLimit = 25
	maxPersonAccessPathLimit     = 100
	defaultPersonAccessPathDepth = 3
	maxPersonAccessPathDepth     = 4
)

type PersonAccessPathRequest struct {
	TenantID    string
	PersonURN   string
	PersonQuery string
	Limit       uint32
	Depth       uint32
}

type PersonAccessPathResult struct {
	TenantID string                  `json:"tenant_id"`
	Filters  PersonAccessPathFilters `json:"filters"`
	Counts   PersonAccessPathCounts  `json:"counts"`
	Paths    []PersonAccessPath      `json:"paths"`
}

type PersonAccessPathFilters struct {
	PersonURN   string `json:"person_urn,omitempty"`
	PersonQuery string `json:"person_query,omitempty"`
	Limit       int    `json:"limit"`
	Depth       int    `json:"depth"`
}

type PersonAccessPathCounts struct {
	Paths int `json:"paths"`
}

type PersonAccessPath struct {
	Person        GraphEntityRef `json:"person"`
	Identity      GraphEntityRef `json:"identity"`
	Principal     GraphEntityRef `json:"principal"`
	AccessTarget  GraphEntityRef `json:"access_target"`
	RelationChain []string       `json:"relation_chain"`
}

func (s *Service) GetPersonAccessPaths(ctx context.Context, request PersonAccessPathRequest) (*PersonAccessPathResult, error) {
	if s == nil || s.rawCypher == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	personURN := strings.TrimSpace(request.PersonURN)
	personQuery := strings.ToLower(strings.TrimSpace(request.PersonQuery))
	if personURN == "" && personQuery == "" {
		return nil, fmt.Errorf("%w: person_urn or person_query is required", ErrInvalidRequest)
	}
	if personURN != "" {
		if err := validateCerebroURN(personURN); err != nil {
			return nil, err
		}
		if urnTenant := tenantFromCerebroURN(personURN); urnTenant != "" && urnTenant != tenantID {
			return nil, fmt.Errorf("%w: person_urn tenant must match tenant_id", ErrInvalidRequest)
		}
	}
	limit := normalizePersonAccessPathLimit(request.Limit)
	params := map[string]any{
		"access_relations": []string{"assigned_to", "member_of", "can_admin", "can_perform", "can_assume", "can_impersonate", "runs_as"},
		"person_query":     personQuery,
		"person_urn":       personURN,
		"sample_limit":     int64(limit),
		"tenant_id":        tenantID,
	}
	rows, err := s.rawCypher.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query:    personAccessPathQuery(normalizePersonAccessPathDepth(request.Depth)),
		Params:   params,
		RowLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	paths := personAccessPathsFromRows(rows)
	return &PersonAccessPathResult{
		TenantID: tenantID,
		Filters: PersonAccessPathFilters{
			PersonURN:   personURN,
			PersonQuery: personQuery,
			Limit:       limit,
			Depth:       normalizePersonAccessPathDepth(request.Depth),
		},
		Counts: PersonAccessPathCounts{Paths: len(paths)},
		Paths:  paths,
	}, nil
}

func normalizePersonAccessPathLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultPersonAccessPathLimit
	case limit > maxPersonAccessPathLimit:
		return maxPersonAccessPathLimit
	default:
		return int(limit)
	}
}

func normalizePersonAccessPathDepth(depth uint32) int {
	switch {
	case depth == 0:
		return defaultPersonAccessPathDepth
	case depth > maxPersonAccessPathDepth:
		return maxPersonAccessPathDepth
	default:
		return int(depth)
	}
}

func tenantFromCerebroURN(urn string) string {
	parts := strings.Split(strings.TrimSpace(urn), ":")
	if len(parts) >= 3 && parts[0] == "urn" && parts[1] == "cerebro" {
		return strings.TrimSpace(parts[2])
	}
	return ""
}

func personAccessPathQuery(depth int) string {
	return fmt.Sprintf(`MATCH (person:Entity {tenant_id: $tenant_id, entity_type: 'person'})
WHERE ($person_urn = '' OR person.urn = $person_urn)
  AND ($person_query = ''
       OR toLower(coalesce(person.label, '')) CONTAINS $person_query
       OR toLower(coalesce(person.attributes_json, '')) CONTAINS $person_query)
MATCH (person)-[person_identity:RELATION {relation: 'same_actor'}]-(identity:Entity {tenant_id: $tenant_id})
MATCH (principal:Entity {tenant_id: $tenant_id})-[principal_identity:RELATION {relation: 'represents_identity'}]->(identity)
MATCH path = (principal)-[:RELATION*1..%d]->(target:Entity {tenant_id: $tenant_id})
WHERE person_identity.tenant_id = $tenant_id
  AND principal_identity.tenant_id = $tenant_id
  AND all(node IN nodes(path) WHERE node.tenant_id = $tenant_id)
  AND all(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $access_relations)
  AND target.urn <> person.urn
  AND target.urn <> identity.urn
RETURN person.urn AS person_urn,
       person.entity_type AS person_entity_type,
       person.label AS person_label,
       identity.urn AS identity_urn,
       identity.entity_type AS identity_entity_type,
       identity.label AS identity_label,
       principal.urn AS principal_urn,
       principal.entity_type AS principal_entity_type,
       principal.label AS principal_label,
       target.urn AS target_urn,
       target.entity_type AS target_entity_type,
       target.label AS target_label,
       [rel IN relationships(path) | rel.relation] AS relation_chain
ORDER BY person.label, principal.label, target.label
LIMIT $sample_limit`, depth)
}

func personAccessPathsFromRows(rows []ports.CypherRow) []PersonAccessPath {
	paths := make([]PersonAccessPath, 0, len(rows))
	for _, row := range rows {
		if row.Values == nil {
			continue
		}
		path := PersonAccessPath{
			Person:        GraphEntityRef{URN: cypherString(row, "person_urn"), EntityType: cypherString(row, "person_entity_type"), Label: cypherString(row, "person_label")},
			Identity:      GraphEntityRef{URN: cypherString(row, "identity_urn"), EntityType: cypherString(row, "identity_entity_type"), Label: cypherString(row, "identity_label")},
			Principal:     GraphEntityRef{URN: cypherString(row, "principal_urn"), EntityType: cypherString(row, "principal_entity_type"), Label: cypherString(row, "principal_label")},
			AccessTarget:  GraphEntityRef{URN: cypherString(row, "target_urn"), EntityType: cypherString(row, "target_entity_type"), Label: cypherString(row, "target_label")},
			RelationChain: cypherStringList(row.Values["relation_chain"]),
		}
		if path.Person.URN == "" || path.Identity.URN == "" || path.Principal.URN == "" || path.AccessTarget.URN == "" || len(path.RelationChain) == 0 {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}
