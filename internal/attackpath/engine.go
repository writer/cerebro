package attackpath

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

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
	store     ports.RawCypherQueryStore
	typed     ports.CloudAttackPathStore
	depth     int
	useLegacy bool
}

type Request struct {
	TenantID              string
	AccountID             string
	RuntimeID             string
	RequireAssertionProof bool
	Limit                 uint32
}

type Result struct {
	TenantID        string  `json:"tenant_id"`
	Filters         Filters `json:"filters"`
	Counts          Counts  `json:"counts"`
	Paths           []Path  `json:"paths"`
	NeighborhoodURN string  `json:"neighborhood_hint,omitempty"`
}

type Filters struct {
	AccountID             string `json:"account_id,omitempty"`
	RuntimeID             string `json:"runtime_id,omitempty"`
	RequireAssertionProof bool   `json:"require_assertion_proof,omitempty"`
	Limit                 int    `json:"limit"`
}

type Counts struct {
	Paths                int `json:"paths"`
	ExposedResources     int `json:"exposed_resources"`
	PrivilegedPrincipals int `json:"privileged_principals"`
	CloudAccounts        int `json:"cloud_accounts"`
}

type Path struct {
	PublicPrincipal       NodeRef     `json:"public_principal"`
	ExposedResource       NodeRef     `json:"exposed_resource"`
	CloudAccount          NodeRef     `json:"cloud_account"`
	Principal             NodeRef     `json:"principal"`
	Permission            NodeRef     `json:"permission"`
	Ownerships            []Ownership `json:"ownerships,omitempty"`
	ReachRelation         string      `json:"reach_relation"`
	AccessRelation        string      `json:"access_relation"`
	RelationChain         []string    `json:"relation_chain,omitempty"`
	ExposureEdge          Edge        `json:"exposure_edge"`
	ResourceAccountEdge   Edge        `json:"resource_account_edge"`
	TraversalEdges        []Edge      `json:"traversal_edges,omitempty"`
	PrivilegeEdge         Edge        `json:"privilege_edge"`
	PermissionAccountEdge Edge        `json:"permission_account_edge"`
}

// Ownership carries each observed owner assignment and the graph edge that
// established it. Multiple assignments remain explicit.
type Ownership struct {
	Owner NodeRef `json:"owner"`
	Edge  Edge    `json:"edge"`
}

type Edge struct {
	From                NodeRef   `json:"from"`
	Relation            string    `json:"relation"`
	To                  NodeRef   `json:"to"`
	Direction           string    `json:"direction,omitempty"`
	SourceID            string    `json:"source_id,omitempty"`
	SourceRuntimeID     string    `json:"source_runtime_id,omitempty"`
	AssertionRuntimeIDs []string  `json:"assertion_runtime_ids,omitempty"`
	SourceEventID       string    `json:"source_event_id,omitempty"`
	ObservedAt          time.Time `json:"observed_at,omitempty"`
}

type NodeRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

func New(store ports.RawCypherQueryStore) *Engine {
	return &Engine{store: store, typed: cloudAttackPathCapability(store), depth: DefaultDepth}
}

func NewWithCapabilities(rawCypher ports.RawCypherQueryStore, typed ports.CloudAttackPathStore) *Engine {
	return &Engine{store: rawCypher, typed: typed, depth: DefaultDepth}
}

func (e *Engine) Traverse(ctx context.Context, request Request) (*Result, error) {
	if e == nil || (e.typed == nil && e.store == nil) {
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
			AccountID:             strings.TrimSpace(request.AccountID),
			RuntimeID:             strings.TrimSpace(request.RuntimeID),
			RequireAssertionProof: request.RequireAssertionProof,
			Limit:                 limit,
		},
	}
	if e.typed != nil && !e.useLegacy {
		typed, err := e.typed.ListCloudAttackPaths(ctx, ports.CloudAttackPathRequest{
			TenantID:              tenantID,
			AccountID:             strings.TrimSpace(request.AccountID),
			RuntimeID:             strings.TrimSpace(request.RuntimeID),
			RequireAssertionProof: request.RequireAssertionProof,
			Limit:                 limit,
			Depth:                 NormalizeDepth(e.depth),
		})
		if err != nil {
			return nil, err
		}
		if err := applyTypedResult(result, typed, limit); err != nil {
			return nil, err
		}
		return result, nil
	}
	if e.store == nil {
		return nil, ErrRuntimeUnavailable
	}

	countsQuery := CountsQuery(e.depth)
	samplesQuery := SamplesQuery(e.depth)
	if request.RequireAssertionProof {
		countsQuery = AssertionCountsQuery(e.depth)
		samplesQuery = AssertionSamplesQuery(e.depth)
	}
	countRows, err := e.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: countsQuery, Params: params, RowLimit: 1})
	if err != nil {
		return nil, err
	}
	if len(countRows) > 0 {
		result.Counts = CountsFromRow(countRows[0])
	}

	pathRows, err := e.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: samplesQuery, Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.Paths = PathsFromRows(pathRows)
	if len(result.Paths) > 0 {
		result.NeighborhoodURN = result.Paths[0].ExposedResource.URN
	}
	return result, nil
}

func cloudAttackPathCapability(store any) ports.CloudAttackPathStore {
	if typed, ok := store.(ports.CloudAttackPathStore); ok {
		return typed
	}
	return nil
}

func applyTypedResult(result *Result, typed *ports.CloudAttackPathResult, limit int) error {
	if result == nil || typed == nil || typed.TenantID != result.TenantID {
		return fmt.Errorf("%w: typed attack path returned an invalid tenant", ErrRuntimeUnavailable)
	}
	if len(typed.Paths) > limit {
		return fmt.Errorf("%w: typed attack path returned too many paths", ErrRuntimeUnavailable)
	}
	result.Counts = Counts{
		Paths:                uint64ToInt(typed.Counts.Paths),
		ExposedResources:     uint64ToInt(typed.Counts.ExposedResources),
		PrivilegedPrincipals: uint64ToInt(typed.Counts.PrivilegedPrincipals),
		CloudAccounts:        uint64ToInt(typed.Counts.CloudAccounts),
	}
	for _, path := range typed.Paths {
		converted := pathFromTyped(path)
		if converted.PublicPrincipal.URN == "" || converted.ExposedResource.URN == "" || converted.CloudAccount.URN == "" || converted.Principal.URN == "" || converted.Permission.URN == "" || !BoundaryProofMatches(converted) || !AccountProofMatches(converted) || !TraversalProofMatches(converted.RelationChain, converted.TraversalEdges) {
			continue
		}
		result.Paths = append(result.Paths, converted)
		if len(result.Paths) == limit {
			break
		}
	}
	if len(result.Paths) > 0 {
		result.NeighborhoodURN = result.Paths[0].ExposedResource.URN
	}
	return nil
}

func pathFromTyped(path ports.CloudAttackPath) Path {
	ownerships := make([]Ownership, 0, len(path.Ownerships))
	for _, ownership := range path.Ownerships {
		ownerships = append(ownerships, Ownership{
			Owner: nodeFromTyped(ownership.Owner),
			Edge:  edgeFromTyped(ownership.Edge),
		})
	}
	traversalEdges := make([]Edge, 0, len(path.TraversalEdges))
	for _, edge := range path.TraversalEdges {
		traversalEdges = append(traversalEdges, edgeFromTyped(edge))
	}
	return Path{
		PublicPrincipal:       nodeFromTyped(path.PublicPrincipal),
		ExposedResource:       nodeFromTyped(path.ExposedResource),
		CloudAccount:          nodeFromTyped(path.CloudAccount),
		Principal:             nodeFromTyped(path.Principal),
		Permission:            nodeFromTyped(path.Permission),
		Ownerships:            ownerships,
		ReachRelation:         path.ReachRelation,
		AccessRelation:        path.AccessRelation,
		RelationChain:         append([]string(nil), path.RelationChain...),
		ExposureEdge:          edgeFromTyped(path.ExposureEdge),
		ResourceAccountEdge:   edgeFromTyped(path.ResourceAccountEdge),
		TraversalEdges:        traversalEdges,
		PrivilegeEdge:         edgeFromTyped(path.PrivilegeEdge),
		PermissionAccountEdge: edgeFromTyped(path.PermissionAccountEdge),
	}
}

func nodeFromTyped(node ports.CloudAttackPathNode) NodeRef {
	return NodeRef{URN: node.URN, EntityType: node.EntityType, Label: node.Label}
}

func edgeFromTyped(edge ports.CloudAttackPathEdge) Edge {
	attributes := cypherMapJSON(map[string]any{"attributes_json": edge.AttributesJSON}, "attributes_json")
	sourceRuntimeID := firstNonEmpty(edge.SourceRuntimeID, attributes["source_runtime_id"])
	return Edge{
		From:                nodeFromTyped(edge.From),
		Relation:            edge.Relation,
		To:                  nodeFromTyped(edge.To),
		Direction:           edge.Direction,
		SourceID:            firstNonEmpty(edge.SourceID, attributes["source_id"]),
		SourceRuntimeID:     sourceRuntimeID,
		AssertionRuntimeIDs: normalizedStringList(append(edge.AssertionRuntimeIDs, sourceRuntimeID)),
		SourceEventID:       firstNonEmpty(attributes["source_event_id"], attributes["event_id"]),
		ObservedAt:          parseObservedAt(firstNonEmpty(attributes["observed_at"], attributes["at"])),
	}
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
		"runtime_id":          strings.TrimSpace(request.RuntimeID),
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
	return countsQuery(NormalizeDepth(depth), "RELATION")
}

// AssertionCountsQuery requires every material edge to have a distinct
// source-runtime assertion.
func AssertionCountsQuery(depth int) string {
	return countsQuery(NormalizeDepth(depth), "RELATION_ASSERTION")
}

func countsQuery(depth int, relationType string) string {
	return pattern(depth, relationType) + `
RETURN count(*) AS path_count,
       count(DISTINCT exposed) AS exposed_resource_count,
       count(DISTINCT principal) AS privileged_principal_count,
       count(DISTINCT account) AS cloud_account_count`
}

func SamplesQuery(depth int) string {
	return samplesQuery(NormalizeDepth(depth), "RELATION")
}

// AssertionSamplesQuery returns proof from per-runtime assertion edges.
func AssertionSamplesQuery(depth int) string {
	return samplesQuery(NormalizeDepth(depth), "RELATION_ASSERTION")
}

func samplesQuery(depth int, relationType string) string {
	return pattern(depth, relationType) + `
CALL {
  WITH exposed
  OPTIONAL MATCH (exposed)-[ownership:` + relationType + ` {tenant_id: $tenant_id, relation: 'owned_by'}]->(candidate_owner:Entity {tenant_id: $tenant_id})
  WHERE $runtime_id = '' OR ownership.runtime_id = $runtime_id
  WITH exposed, candidate_owner, collect(ownership) AS ownership_assertions
  WITH exposed, candidate_owner, head(ownership_assertions) AS ownership,
       [assertion IN ownership_assertions | assertion.runtime_id] AS ownership_assertion_runtime_ids
  ORDER BY candidate_owner.urn, candidate_owner.entity_type, candidate_owner.label
  RETURN [item IN collect({
    owner_urn: candidate_owner.urn,
    owner_entity_type: candidate_owner.entity_type,
    owner_label: candidate_owner.label,
    from_urn: exposed.urn,
    from_entity_type: exposed.entity_type,
    from_label: exposed.label,
    relation: ownership.relation,
    to_urn: candidate_owner.urn,
    to_entity_type: candidate_owner.entity_type,
    to_label: candidate_owner.label,
    direction: 'forward',
    source_id: ownership.source_id,
    source_runtime_id: ownership.runtime_id,
    assertion_runtime_ids: ownership_assertion_runtime_ids,
    attributes_json: ownership.attributes_json
  }) WHERE item.owner_urn IS NOT NULL] AS ownerships
}
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
       ownerships,
       reach.relation AS reach_relation,
       access.relation AS access_relation,
       proof_relations AS relation_chain,
       {
         from_urn: public.urn,
         from_label: public.label,
         from_entity_type: public.entity_type,
         relation: reach.relation,
         to_urn: exposed.urn,
         to_label: exposed.label,
         to_entity_type: exposed.entity_type,
         direction: 'forward',
         source_id: reach.source_id,
         source_runtime_id: reach.runtime_id,
         assertion_runtime_ids: reach_assertion_runtime_ids,
         attributes_json: reach.attributes_json
       } AS exposure_edge,
       {
         from_urn: exposed.urn,
         from_label: exposed.label,
         from_entity_type: exposed.entity_type,
         relation: resource_account.relation,
         to_urn: account.urn,
         to_label: account.label,
         to_entity_type: account.entity_type,
         direction: 'forward',
         source_id: resource_account.source_id,
         source_runtime_id: resource_account.runtime_id,
         assertion_runtime_ids: resource_account_assertion_runtime_ids,
         attributes_json: resource_account.attributes_json
       } AS resource_account_edge,
       [idx IN range(0, length(proof_path) - 1) | {
         from_urn: nodes(proof_path)[idx].urn,
         from_label: nodes(proof_path)[idx].label,
         from_entity_type: nodes(proof_path)[idx].entity_type,
         relation: relationships(proof_path)[idx].relation,
         to_urn: nodes(proof_path)[idx + 1].urn,
         to_label: nodes(proof_path)[idx + 1].label,
         to_entity_type: nodes(proof_path)[idx + 1].entity_type,
         direction: CASE WHEN startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx] THEN 'forward' ELSE 'reverse' END,
         source_id: relationships(proof_path)[idx].source_id,
         source_runtime_id: relationships(proof_path)[idx].runtime_id,
         assertion_runtime_ids: traversal_assertion_runtime_ids[idx],
         attributes_json: relationships(proof_path)[idx].attributes_json
       }] AS traversal_edges,
       {
         from_urn: principal.urn,
         from_label: principal.label,
         from_entity_type: principal.entity_type,
         relation: access.relation,
         to_urn: permission.urn,
         to_label: permission.label,
         to_entity_type: permission.entity_type,
         direction: 'forward',
         source_id: access.source_id,
         source_runtime_id: access.runtime_id,
         assertion_runtime_ids: access_assertion_runtime_ids,
         attributes_json: access.attributes_json
       } AS privilege_edge,
       {
         from_urn: permission.urn,
         from_label: permission.label,
         from_entity_type: permission.entity_type,
         relation: permission_account.relation,
         to_urn: account.urn,
         to_label: account.label,
         to_entity_type: account.entity_type,
         direction: 'forward',
         source_id: permission_account.source_id,
         source_runtime_id: permission_account.runtime_id,
         assertion_runtime_ids: permission_account_assertion_runtime_ids,
         attributes_json: permission_account.attributes_json
       } AS permission_account_edge
ORDER BY account.label, exposed.label, principal.label, permission.label
LIMIT $sample_limit`
}

func pattern(depth int, relationType string) string {
	return fmt.Sprintf(`MATCH (public:Entity {tenant_id: $tenant_id})-[reach:%[2]s {relation: 'can_reach'}]->(exposed:Entity {tenant_id: $tenant_id})-[resource_account:%[2]s {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE public.entity_type ENDS WITH '.public_principal'
  AND ($account_id = '' OR account.label = $account_id OR account.urn CONTAINS $account_id)
MATCH proof_path = (exposed)-[:%[2]s*1..%[1]d]-(principal:Entity {tenant_id: $tenant_id})
WHERE all(node IN nodes(proof_path) WHERE node.tenant_id = $tenant_id)
  AND all(rel IN relationships(proof_path) WHERE rel.tenant_id = $tenant_id AND rel.relation IN $traversal_relations)
  AND %[3]s
MATCH (principal)-[access:%[2]s]->(permission:Entity {tenant_id: $tenant_id})-[permission_account:%[2]s {relation: 'belongs_to'}]->(account)
WHERE access.relation IN $access_relations
	  AND (
    access.relation <> 'can_perform'
    OR coalesce(access.attributes_json, '') CONTAINS '"is_admin":"true"'
    OR coalesce(access.attributes_json, '') CONTAINS '"privilege_level":"admin"'
    OR coalesce(access.attributes_json, '') CONTAINS 'AdministratorAccess'
	    OR coalesce(access.attributes_json, '') CONTAINS '"permission":"*"'
	  )
	  AND ($runtime_id = '' OR (
	    reach.runtime_id = $runtime_id
	    AND resource_account.runtime_id = $runtime_id
	    AND access.runtime_id = $runtime_id
	    AND permission_account.runtime_id = $runtime_id
	    AND all(rel IN relationships(proof_path) WHERE rel.runtime_id = $runtime_id)
	  ))
WITH public, reach, exposed, resource_account, account, principal, access, permission, permission_account, proof_path,
     reach.relation AS reach_relation, access.relation AS access_relation,
     [node IN nodes(proof_path) | node.urn] AS proof_node_urns,
     [rel IN relationships(proof_path) | rel.relation] AS proof_relations,
     [idx IN range(0, length(proof_path) - 1) |
       CASE WHEN startNode(relationships(proof_path)[idx]) = nodes(proof_path)[idx] THEN 'forward' ELSE 'reverse' END
     ] AS proof_directions
ORDER BY length(proof_path), principal.label, principal.urn, permission.label, permission.urn,
         reach.runtime_id, resource_account.runtime_id, access.runtime_id, permission_account.runtime_id
WITH public, exposed, account, principal, permission, reach_relation, access_relation,
     proof_node_urns, proof_relations, proof_directions,
     collect(reach) AS reach_assertions,
     collect(resource_account) AS resource_account_assertions,
     collect(access) AS access_assertions,
     collect(permission_account) AS permission_account_assertions,
     collect(proof_path) AS proof_paths
WITH public, exposed, account, principal, permission, reach_relation, access_relation, proof_relations,
     head(reach_assertions) AS reach,
     head(resource_account_assertions) AS resource_account,
     head(access_assertions) AS access,
     head(permission_account_assertions) AS permission_account,
     head(proof_paths) AS proof_path,
     [assertion IN reach_assertions | assertion.runtime_id] AS reach_assertion_runtime_ids,
     [assertion IN resource_account_assertions | assertion.runtime_id] AS resource_account_assertion_runtime_ids,
     [assertion IN access_assertions | assertion.runtime_id] AS access_assertion_runtime_ids,
     [assertion IN permission_account_assertions | assertion.runtime_id] AS permission_account_assertion_runtime_ids,
     [idx IN range(0, size(proof_relations) - 1) |
       [candidate_path IN proof_paths | relationships(candidate_path)[idx].runtime_id]
     ] AS traversal_assertion_runtime_ids`, NormalizeDepth(depth), relationType, graphpaths.CloudExposurePrivilegeTraversalDirectionPredicate)
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
			PublicPrincipal:       NodeRef{URN: cypherString(row, "public_urn"), EntityType: cypherString(row, "public_entity_type"), Label: cypherString(row, "public_label")},
			ExposedResource:       NodeRef{URN: cypherString(row, "exposed_urn"), EntityType: cypherString(row, "exposed_entity_type"), Label: cypherString(row, "exposed_label")},
			CloudAccount:          NodeRef{URN: cypherString(row, "account_urn"), EntityType: cypherString(row, "account_entity_type"), Label: cypherString(row, "account_label")},
			Principal:             NodeRef{URN: cypherString(row, "principal_urn"), EntityType: cypherString(row, "principal_entity_type"), Label: cypherString(row, "principal_label")},
			Permission:            NodeRef{URN: cypherString(row, "permission_urn"), EntityType: cypherString(row, "permission_entity_type"), Label: cypherString(row, "permission_label")},
			Ownerships:            ownershipsFromRow(row),
			ReachRelation:         cypherString(row, "reach_relation"),
			AccessRelation:        cypherString(row, "access_relation"),
			RelationChain:         relationChain,
			ExposureEdge:          edgeFromItem(row.Values["exposure_edge"]),
			ResourceAccountEdge:   edgeFromItem(row.Values["resource_account_edge"]),
			TraversalEdges:        traversalEdges,
			PrivilegeEdge:         edgeFromItem(row.Values["privilege_edge"]),
			PermissionAccountEdge: edgeFromItem(row.Values["permission_account_edge"]),
		}
		if path.PublicPrincipal.URN == "" || path.ExposedResource.URN == "" || path.CloudAccount.URN == "" || path.Principal.URN == "" || path.Permission.URN == "" || !BoundaryProofMatches(path) || !AccountProofMatches(path) || !TraversalProofMatches(relationChain, traversalEdges) {
			continue
		}
		result = append(result, path)
	}
	return result
}

// BoundaryProofMatches requires the attack path's public-exposure and
// principal-privilege edges to match the path endpoints exactly. Traversal
// proof is checked separately because its allowed directions vary by relation.
func BoundaryProofMatches(path Path) bool {
	exposure := path.ExposureEdge
	if strings.TrimSpace(path.ReachRelation) != "can_reach" ||
		strings.TrimSpace(exposure.Relation) != strings.TrimSpace(path.ReachRelation) ||
		strings.TrimSpace(exposure.Direction) != "forward" ||
		exposure.From.URN != path.PublicPrincipal.URN || exposure.To.URN != path.ExposedResource.URN {
		return false
	}
	privilege := path.PrivilegeEdge
	if strings.TrimSpace(privilege.Relation) != strings.TrimSpace(path.AccessRelation) ||
		strings.TrimSpace(privilege.Direction) != "forward" ||
		privilege.From.URN != path.Principal.URN || privilege.To.URN != path.Permission.URN ||
		!containsString(privilegedAccessRelations(), privilege.Relation) {
		return false
	}
	return true
}

// AccountProofMatches binds both resource and permission membership edges to
// the account used by the material path.
func AccountProofMatches(path Path) bool {
	resource := path.ResourceAccountEdge
	permission := path.PermissionAccountEdge
	return resource.Relation == "belongs_to" && resource.Direction == "forward" &&
		resource.From.URN == path.ExposedResource.URN && resource.To.URN == path.CloudAccount.URN &&
		permission.Relation == "belongs_to" && permission.Direction == "forward" &&
		permission.From.URN == path.Permission.URN && permission.To.URN == path.CloudAccount.URN
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
		edge := edgeFromItem(item)
		if edge.From.URN == "" || edge.Relation == "" || edge.To.URN == "" {
			continue
		}
		edges = append(edges, edge)
	}
	return edges
}

func edgeFromItem(item any) Edge {
	attributes := cypherMapJSON(item, "attributes_json")
	sourceRuntimeID := firstNonEmpty(cypherMapString(item, "source_runtime_id"), attributes["source_runtime_id"])
	return Edge{
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
		Direction:           cypherMapString(item, "direction"),
		SourceID:            firstNonEmpty(cypherMapString(item, "source_id"), attributes["source_id"]),
		SourceRuntimeID:     sourceRuntimeID,
		AssertionRuntimeIDs: normalizedStringList(append(cypherMapStringList(item, "assertion_runtime_ids"), sourceRuntimeID)),
		SourceEventID:       firstNonEmpty(attributes["source_event_id"], attributes["event_id"]),
		ObservedAt:          parseObservedAt(firstNonEmpty(attributes["observed_at"], attributes["at"])),
	}
}

func ownershipsFromRow(row ports.CypherRow) []Ownership {
	items, ok := row.Values["ownerships"].([]any)
	if !ok {
		return nil
	}
	result := make([]Ownership, 0, len(items))
	for _, item := range items {
		owner := NodeRef{
			URN:        cypherMapString(item, "owner_urn"),
			EntityType: cypherMapString(item, "owner_entity_type"),
			Label:      cypherMapString(item, "owner_label"),
		}
		edge := edgeFromItem(item)
		if owner.URN == "" || edge.Relation != "owned_by" || edge.To.URN != owner.URN {
			continue
		}
		result = append(result, Ownership{Owner: owner, Edge: edge})
	}
	return result
}

func cypherMapJSON(item any, key string) map[string]string {
	values, ok := item.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := values[key]
	if !ok || raw == nil {
		return nil
	}
	if typed, ok := raw.(map[string]any); ok {
		return stringMap(typed)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(cypherAnyString(raw)), &decoded); err != nil {
		return nil
	}
	return stringMap(decoded)
}

func stringMap(values map[string]any) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = strings.TrimSpace(cypherAnyString(value))
	}
	return result
}

func parseObservedAt(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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

func cypherMapStringList(item any, key string) []string {
	values, ok := item.(map[string]any)
	if !ok {
		return nil
	}
	switch typed := values[key].(type) {
	case []any:
		result := make([]string, 0, len(typed))
		for _, value := range typed {
			result = append(result, cypherAnyString(value))
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	default:
		return nil
	}
}

func normalizedStringList(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
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
