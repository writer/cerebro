package attackpath

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/writer/cerebro/internal/graphpaths"
	"github.com/writer/cerebro/internal/ports"
)

const (
	DefaultLimit = 25
	MaxLimit     = 100
	DefaultDepth = 4
	MaxDepth     = 6
)

var (
	ErrRuntimeUnavailable = errors.New("attack path runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid attack path request")
)

type Engine struct {
	store ports.GraphQueryStore
	depth int
}

type Request struct {
	TenantID  string
	AccountID string
	Limit     uint32
}

type Result struct {
	TenantID        string  `json:"tenant_id"`
	Filters         Filters `json:"filters"`
	Counts          Counts  `json:"counts"`
	Paths           []Path  `json:"paths"`
	NeighborhoodURN string  `json:"neighborhood_hint,omitempty"`
}

type Filters struct {
	AccountID string `json:"account_id,omitempty"`
	Limit     int    `json:"limit"`
}

type Counts struct {
	Paths                int `json:"paths"`
	ExposedResources     int `json:"exposed_resources"`
	PrivilegedPrincipals int `json:"privileged_principals"`
	CloudAccounts        int `json:"cloud_accounts"`
}

type Path struct {
	PublicPrincipal NodeRef  `json:"public_principal"`
	ExposedResource NodeRef  `json:"exposed_resource"`
	CloudAccount    NodeRef  `json:"cloud_account"`
	Principal       NodeRef  `json:"principal"`
	Permission      NodeRef  `json:"permission"`
	ReachRelation   string   `json:"reach_relation"`
	AccessRelation  string   `json:"access_relation"`
	RelationChain   []string `json:"relation_chain,omitempty"`
	TraversalEdges  []Edge   `json:"traversal_edges,omitempty"`
}

type Edge struct {
	From      NodeRef `json:"from"`
	Relation  string  `json:"relation"`
	To        NodeRef `json:"to"`
	Direction string  `json:"direction,omitempty"`
}

type NodeRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

func New(store ports.GraphQueryStore) *Engine {
	return &Engine{store: store, depth: DefaultDepth}
}

func (e *Engine) Traverse(ctx context.Context, request Request) (*Result, error) {
	if e == nil || e.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	limit := NormalizeLimit(request.Limit)
	params := params(tenantID, request)
	result := &Result{
		TenantID: tenantID,
		Filters: Filters{
			AccountID: strings.TrimSpace(request.AccountID),
			Limit:     limit,
		},
	}

	countRows, err := e.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: CountsQuery(e.depth), Params: params, RowLimit: 1})
	if err != nil {
		return nil, err
	}
	if len(countRows) > 0 {
		result.Counts = CountsFromRow(countRows[0])
	}

	pathRows, err := e.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: SamplesQuery(e.depth), Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.Paths = PathsFromRows(pathRows)
	if len(result.Paths) > 0 {
		result.NeighborhoodURN = result.Paths[0].ExposedResource.URN
	}
	return result, nil
}

func NormalizeLimit(limit uint32) int {
	switch {
	case limit == 0:
		return DefaultLimit
	case limit > MaxLimit:
		return MaxLimit
	default:
		return int(limit)
	}
}

func NormalizeDepth(depth int) int {
	switch {
	case depth <= 0:
		return DefaultDepth
	case depth > MaxDepth:
		return MaxDepth
	default:
		return depth
	}
}

func params(tenantID string, request Request) map[string]any {
	return map[string]any{
		"account_id":          strings.TrimSpace(request.AccountID),
		"access_relations":    privilegedAccessRelations(),
		"sample_limit":        int64(NormalizeLimit(request.Limit)),
		"tenant_id":           strings.TrimSpace(tenantID),
		"traversal_relations": graphpaths.CloudExposurePrivilegeTraversalRelations(),
	}
}

func privilegedAccessRelations() []string {
	return []string{"can_admin", "can_perform", "can_assume", "can_impersonate"}
}

func CountsQuery(depth int) string {
	return pattern(NormalizeDepth(depth)) + `
RETURN count(*) AS path_count,
       count(DISTINCT exposed) AS exposed_resource_count,
       count(DISTINCT principal) AS privileged_principal_count,
       count(DISTINCT account) AS cloud_account_count`
}

func SamplesQuery(depth int) string {
	return pattern(NormalizeDepth(depth)) + `
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
       [rel IN relationships(proof_path) | rel.relation] AS relation_chain,
       [idx IN range(0, length(proof_path) - 1) | {
         from_urn: nodes(proof_path)[idx].urn,
         from_label: nodes(proof_path)[idx].label,
         from_entity_type: nodes(proof_path)[idx].entity_type,
         relation: relationships(proof_path)[idx].relation,
         to_urn: nodes(proof_path)[idx + 1].urn,
         to_label: nodes(proof_path)[idx + 1].label,
         to_entity_type: nodes(proof_path)[idx + 1].entity_type,
         direction: CASE WHEN startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx] THEN 'forward' ELSE 'reverse' END
       }] AS traversal_edges
ORDER BY account.label, exposed.label, principal.label, permission.label
LIMIT $sample_limit`
}

func pattern(depth int) string {
	return fmt.Sprintf(`MATCH (public:Entity {tenant_id: $tenant_id})-[reach:RELATION {relation: 'can_reach'}]->(exposed:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND ($account_id = '' OR account.label = $account_id OR account.urn CONTAINS $account_id)
MATCH proof_path = (exposed)-[:RELATION*1..%d]-(principal:Entity {tenant_id: $tenant_id})
WHERE all(node IN nodes(proof_path) WHERE node.tenant_id = $tenant_id)
  AND all(rel IN relationships(proof_path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $traversal_relations)
  AND %s
MATCH (principal)-[access:RELATION]->(permission:Entity {tenant_id: $tenant_id})-[:RELATION {relation: 'belongs_to'}]->(account)
WHERE access.relation IN $access_relations
  AND (
    access.relation <> 'can_perform'
    OR coalesce(access.attributes_json, '') CONTAINS '"is_admin":"true"'
    OR coalesce(access.attributes_json, '') CONTAINS '"privilege_level":"admin"'
    OR coalesce(access.attributes_json, '') CONTAINS 'AdministratorAccess'
    OR coalesce(access.attributes_json, '') CONTAINS '"permission":"*"'
  )
WITH public, reach, exposed, account, principal, access, permission, proof_path
ORDER BY length(proof_path), principal.label, principal.urn, permission.label, permission.urn
WITH public, reach, exposed, account, principal, access, permission, head(collect(proof_path)) AS proof_path`, NormalizeDepth(depth), graphpaths.CloudExposurePrivilegeTraversalDirectionPredicate)
}

func CountsFromRow(row ports.CypherRow) Counts {
	return Counts{
		Paths:                cypherInt(row, "path_count"),
		ExposedResources:     cypherInt(row, "exposed_resource_count"),
		PrivilegedPrincipals: cypherInt(row, "privileged_principal_count"),
		CloudAccounts:        cypherInt(row, "cloud_account_count"),
	}
}

func PathsFromRows(rows []ports.CypherRow) []Path {
	result := make([]Path, 0, len(rows))
	for _, row := range rows {
		relationChain := cypherStringList(row.Values["relation_chain"])
		traversalEdges := EdgesFromRow(row)
		path := Path{
			PublicPrincipal: NodeRef{URN: cypherString(row, "public_urn"), EntityType: cypherString(row, "public_entity_type"), Label: cypherString(row, "public_label")},
			ExposedResource: NodeRef{URN: cypherString(row, "exposed_urn"), EntityType: cypherString(row, "exposed_entity_type"), Label: cypherString(row, "exposed_label")},
			CloudAccount:    NodeRef{URN: cypherString(row, "account_urn"), EntityType: cypherString(row, "account_entity_type"), Label: cypherString(row, "account_label")},
			Principal:       NodeRef{URN: cypherString(row, "principal_urn"), EntityType: cypherString(row, "principal_entity_type"), Label: cypherString(row, "principal_label")},
			Permission:      NodeRef{URN: cypherString(row, "permission_urn"), EntityType: cypherString(row, "permission_entity_type"), Label: cypherString(row, "permission_label")},
			ReachRelation:   cypherString(row, "reach_relation"),
			AccessRelation:  cypherString(row, "access_relation"),
			RelationChain:   relationChain,
			TraversalEdges:  traversalEdges,
		}
		if path.PublicPrincipal.URN == "" || path.ExposedResource.URN == "" || path.CloudAccount.URN == "" || path.Principal.URN == "" || path.Permission.URN == "" || !TraversalProofMatches(relationChain, traversalEdges) {
			continue
		}
		result = append(result, path)
	}
	return result
}

func TraversalProofMatches(relationChain []string, edges []Edge) bool {
	if len(relationChain) == 0 || len(edges) != len(relationChain) {
		return false
	}
	for idx, relation := range relationChain {
		relation = strings.TrimSpace(relation)
		edge := edges[idx]
		if relation == "" || relation != strings.TrimSpace(edge.Relation) {
			return false
		}
		if edge.From.URN == "" || edge.To.URN == "" || !graphpaths.CloudExposurePrivilegeTraversalAllowsStep(edge.Relation, edge.Direction) {
			return false
		}
	}
	return true
}

func EdgesFromRow(row ports.CypherRow) []Edge {
	items, ok := row.Values["traversal_edges"].([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	edges := make([]Edge, 0, len(items))
	for _, item := range items {
		edge := Edge{
			From: NodeRef{
				URN:        cypherMapString(item, "from_urn"),
				EntityType: cypherMapString(item, "from_entity_type"),
				Label:      cypherMapString(item, "from_label"),
			},
			Relation: cypherMapString(item, "relation"),
			To: NodeRef{
				URN:        cypherMapString(item, "to_urn"),
				EntityType: cypherMapString(item, "to_entity_type"),
				Label:      cypherMapString(item, "to_label"),
			},
			Direction: cypherMapString(item, "direction"),
		}
		if edge.From.URN == "" || edge.Relation == "" || edge.To.URN == "" {
			continue
		}
		edges = append(edges, edge)
	}
	return edges
}

func cypherString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	value, ok := row.Values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func cypherStringList(value any) []string {
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, cypherAnyString(item))
	}
	return result
}

func cypherAnyString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

func cypherMapString(item any, key string) string {
	values, ok := item.(map[string]any)
	if !ok {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func cypherInt(row ports.CypherRow, key string) int {
	if row.Values == nil {
		return 0
	}
	switch value := row.Values[key].(type) {
	case int:
		return value
	case int8:
		return int(value)
	case int16:
		return int(value)
	case int32:
		return int(value)
	case int64:
		return int64ToInt(value)
	case uint:
		return uint64ToInt(uint64(value))
	case uint8:
		return int(value)
	case uint16:
		return int(value)
	case uint32:
		return int(value)
	case uint64:
		return uint64ToInt(value)
	case float32:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func int64ToInt(value int64) int {
	if value > int64(math.MaxInt) {
		return math.MaxInt
	}
	if value < int64(math.MinInt) {
		return math.MinInt
	}
	return int(value)
}

func uint64ToInt(value uint64) int {
	if value > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}
