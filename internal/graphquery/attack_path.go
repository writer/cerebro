package graphquery

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultAttackPathLimit = 25
	maxAttackPathLimit     = 100
)

type AttackPathRequest struct {
	TenantID  string
	AccountID string
	Limit     uint32
}

type AttackPathResult struct {
	TenantID        string            `json:"tenant_id"`
	Filters         AttackPathFilters `json:"filters"`
	Counts          AttackPathCounts  `json:"counts"`
	Paths           []AttackPath      `json:"paths"`
	NeighborhoodURN string            `json:"neighborhood_hint,omitempty"`
}

type AttackPathFilters struct {
	AccountID string `json:"account_id,omitempty"`
	Limit     int    `json:"limit"`
}

type AttackPathCounts struct {
	Paths                int `json:"paths"`
	ExposedResources     int `json:"exposed_resources"`
	PrivilegedPrincipals int `json:"privileged_principals"`
	CloudAccounts        int `json:"cloud_accounts"`
}

type AttackPath struct {
	PublicPrincipal GraphEntityRef `json:"public_principal"`
	ExposedResource GraphEntityRef `json:"exposed_resource"`
	CloudAccount    GraphEntityRef `json:"cloud_account"`
	Principal       GraphEntityRef `json:"principal"`
	Permission      GraphEntityRef `json:"permission"`
	ReachRelation   string         `json:"reach_relation"`
	AccessRelation  string         `json:"access_relation"`
	RelationChain   []string       `json:"relation_chain,omitempty"`
}

func (s *Service) GetAttackPaths(ctx context.Context, request AttackPathRequest) (*AttackPathResult, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	limit := normalizeAttackPathLimit(request.Limit)
	params := attackPathParams(tenantID, request)
	result := &AttackPathResult{
		TenantID: tenantID,
		Filters: AttackPathFilters{
			AccountID: strings.TrimSpace(request.AccountID),
			Limit:     limit,
		},
	}

	countRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: attackPathCountsQuery, Params: params, RowLimit: 1})
	if err != nil {
		return nil, err
	}
	if len(countRows) > 0 {
		result.Counts = attackPathCountsFromRow(countRows[0])
	}

	pathRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: attackPathSamplesQuery, Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.Paths = attackPathsFromRows(pathRows)
	if len(result.Paths) > 0 {
		result.NeighborhoodURN = result.Paths[0].ExposedResource.URN
	}
	return result, nil
}

func normalizeAttackPathLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultAttackPathLimit
	case limit > maxAttackPathLimit:
		return maxAttackPathLimit
	default:
		return int(limit)
	}
}

func attackPathParams(tenantID string, request AttackPathRequest) map[string]any {
	return map[string]any{
		"account_id":          strings.TrimSpace(request.AccountID),
		"sample_limit":        int64(normalizeAttackPathLimit(request.Limit)),
		"tenant_id":           tenantID,
		"traversal_relations": attackPathTraversalRelations,
	}
}

const attackPathPattern = `MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(exposed:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND ($account_id = '' OR account.label = $account_id OR account.urn CONTAINS $account_id)
MATCH proof_path = (exposed)-[:RELATION*1..4]-(principal:Entity {tenant_id: $tenant_id})
WHERE all(node IN nodes(proof_path) WHERE node.tenant_id = $tenant_id)
  AND all(rel IN relationships(proof_path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $traversal_relations)
MATCH (principal)-[access:RELATION]->(permission:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account)
WHERE access.relation IN ['can_admin', 'can_perform', 'can_assume', 'can_impersonate']
  AND (
    access.relation <> 'can_perform'
    OR coalesce(access.attributes_json, '') CONTAINS '"is_admin":"true"'
    OR coalesce(access.attributes_json, '') CONTAINS '"privilege_level":"admin"'
    OR coalesce(access.attributes_json, '') CONTAINS 'AdministratorAccess'
    OR coalesce(access.attributes_json, '') CONTAINS '"permission":"*"'
  )
WITH public, reach, exposed, account, principal, access, permission, proof_path
ORDER BY length(proof_path), principal.label, principal.urn, permission.label, permission.urn
WITH public, reach, exposed, account, principal, access, permission, head(collect(proof_path)) AS proof_path`

var attackPathTraversalRelations = []string{
	"assigned_to",
	"attached_to",
	"can_assume",
	"can_impersonate",
	"depends_on",
	"member_of",
	"runs_as",
}

const attackPathCountsQuery = attackPathPattern + `
RETURN count(*) AS path_count,
       count(DISTINCT exposed) AS exposed_resource_count,
       count(DISTINCT principal) AS privileged_principal_count,
       count(DISTINCT account) AS cloud_account_count`

const attackPathSamplesQuery = attackPathPattern + `
RETURN public.urn AS public_urn,
       public.entity_type AS public_entity_type,
       public.label AS public_label,
       exposed.urn AS exposed_urn,
       exposed.entity_type AS exposed_entity_type,
       exposed.label AS exposed_label,
       account.urn AS account_urn,
       account.entity_type AS account_entity_type,
       account.label AS account_label,
       principal.urn AS principal_urn,
       principal.entity_type AS principal_entity_type,
       principal.label AS principal_label,
       permission.urn AS permission_urn,
       permission.entity_type AS permission_entity_type,
       permission.label AS permission_label,
       reach.relation AS reach_relation,
       access.relation AS access_relation,
       [rel IN relationships(proof_path) | rel.relation] AS relation_chain
ORDER BY account.label, exposed.label, principal.label, permission.label
LIMIT $sample_limit`

func attackPathCountsFromRow(row ports.CypherRow) AttackPathCounts {
	return AttackPathCounts{
		Paths:                cypherInt(row, "path_count"),
		ExposedResources:     cypherInt(row, "exposed_resource_count"),
		PrivilegedPrincipals: cypherInt(row, "privileged_principal_count"),
		CloudAccounts:        cypherInt(row, "cloud_account_count"),
	}
}

func attackPathsFromRows(rows []ports.CypherRow) []AttackPath {
	result := make([]AttackPath, 0, len(rows))
	for _, row := range rows {
		path := AttackPath{
			PublicPrincipal: GraphEntityRef{URN: cypherString(row, "public_urn"), EntityType: cypherString(row, "public_entity_type"), Label: cypherString(row, "public_label")},
			ExposedResource: GraphEntityRef{URN: cypherString(row, "exposed_urn"), EntityType: cypherString(row, "exposed_entity_type"), Label: cypherString(row, "exposed_label")},
			CloudAccount:    GraphEntityRef{URN: cypherString(row, "account_urn"), EntityType: cypherString(row, "account_entity_type"), Label: cypherString(row, "account_label")},
			Principal:       GraphEntityRef{URN: cypherString(row, "principal_urn"), EntityType: cypherString(row, "principal_entity_type"), Label: cypherString(row, "principal_label")},
			Permission:      GraphEntityRef{URN: cypherString(row, "permission_urn"), EntityType: cypherString(row, "permission_entity_type"), Label: cypherString(row, "permission_label")},
			ReachRelation:   cypherString(row, "reach_relation"),
			AccessRelation:  cypherString(row, "access_relation"),
			RelationChain:   cypherStringList(row.Values["relation_chain"]),
		}
		if path.PublicPrincipal.URN == "" || path.ExposedResource.URN == "" || path.CloudAccount.URN == "" || path.Principal.URN == "" || path.Permission.URN == "" || len(path.RelationChain) == 0 {
			continue
		}
		result = append(result, path)
	}
	return result
}
