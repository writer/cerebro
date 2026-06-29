package graphquery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultEffectiveAccessPathLimit = 25
	maxEffectiveAccessPathLimit     = 100
)

type EffectiveAccessPathRequest struct {
	TenantID       string
	IdentityURN    string
	IdentityQuery  string
	ApplicationURN string
	Capability     string
	Limit          uint32
}

type EffectiveAccessPathResult struct {
	TenantID string                     `json:"tenant_id"`
	Filters  EffectiveAccessPathFilters `json:"filters"`
	Counts   EffectiveAccessPathCounts  `json:"counts"`
	Paths    []EffectiveAccessPath      `json:"paths"`
}

type EffectiveAccessPathFilters struct {
	IdentityURN    string `json:"identity_urn,omitempty"`
	IdentityQuery  string `json:"identity_query,omitempty"`
	ApplicationURN string `json:"application_urn,omitempty"`
	Capability     string `json:"capability,omitempty"`
	Limit          int    `json:"limit"`
}

type EffectiveAccessPathCounts struct {
	Paths                int `json:"paths"`
	DirectAssignments    int `json:"direct_assignments"`
	GroupMediatedPaths   int `json:"group_mediated_paths"`
	RolePaths            int `json:"role_paths"`
	AdminRolePaths       int `json:"admin_role_paths"`
	CapabilitiesReturned int `json:"capabilities_returned"`
}

type EffectiveAccessPath struct {
	Identity       GraphEntityRef            `json:"identity"`
	Principal      GraphEntityRef            `json:"principal"`
	Mediator       *GraphEntityRef           `json:"mediator,omitempty"`
	AccessTarget   GraphEntityRef            `json:"access_target"`
	Entitlement    GraphEntityRef            `json:"entitlement"`
	Capability     GraphEntityRef            `json:"capability"`
	AssignmentKind string                    `json:"assignment_kind"`
	RelationChain  []string                  `json:"relation_chain"`
	Edges          []EffectiveAccessPathEdge `json:"edges"`
}

type EffectiveAccessPathEdge struct {
	From       GraphEntityRef    `json:"from"`
	Relation   string            `json:"relation"`
	To         GraphEntityRef    `json:"to"`
	SourceID   string            `json:"source_id,omitempty"`
	RuntimeID  string            `json:"runtime_id,omitempty"`
	EventID    string            `json:"event_id,omitempty"`
	At         string            `json:"at,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func (p EffectiveAccessPath) IsPrivileged() bool {
	haystack := strings.ToLower(strings.Join([]string{
		p.AssignmentKind,
		p.AccessTarget.URN,
		p.AccessTarget.EntityType,
		p.AccessTarget.Label,
		p.Entitlement.URN,
		p.Entitlement.EntityType,
		p.Entitlement.Label,
		p.Capability.URN,
		p.Capability.EntityType,
		p.Capability.Label,
		strings.Join(p.RelationChain, " "),
	}, " "))
	if strings.Contains(haystack, "admin") || strings.Contains(haystack, "privileged") || strings.Contains(haystack, "owner") || strings.Contains(haystack, "root") {
		return true
	}
	for _, edge := range p.Edges {
		for key, value := range edge.Attributes {
			normalized := strings.ToLower(strings.TrimSpace(key + ":" + value))
			if normalized == "privileged:true" || strings.Contains(normalized, "privilege:admin") || strings.Contains(normalized, "role:admin") {
				return true
			}
		}
		if edge.Relation == "can_admin" {
			return true
		}
	}
	return false
}

func (p EffectiveAccessPath) IsSensitive() bool {
	haystack := strings.ToLower(strings.Join([]string{
		p.AccessTarget.URN,
		p.AccessTarget.EntityType,
		p.AccessTarget.Label,
		p.Entitlement.URN,
		p.Entitlement.EntityType,
		p.Entitlement.Label,
		p.Capability.URN,
		p.Capability.EntityType,
		p.Capability.Label,
	}, " "))
	if strings.Contains(haystack, "payroll") || strings.Contains(haystack, "finance") || strings.Contains(haystack, "sensitive") || strings.Contains(haystack, "confidential") {
		return true
	}
	for _, edge := range p.Edges {
		if strings.EqualFold(edge.Attributes["sensitive"], "true") || strings.EqualFold(edge.Attributes["data_classification"], "sensitive") {
			return true
		}
	}
	return false
}

func (p EffectiveAccessPath) AccessClassification() []string {
	classification := []string{}
	if p.IsPrivileged() {
		classification = append(classification, "privileged")
	}
	if p.IsSensitive() {
		classification = append(classification, "sensitive")
	}
	if p.Mediator != nil {
		classification = append(classification, "group_mediated")
	}
	if strings.Contains(p.AssignmentKind, "role") {
		classification = append(classification, "role_based")
	}
	return uniqueEffectiveAccessLabels(classification)
}

func (p EffectiveAccessPath) SupportsOperationProof(changedDuringPeriod bool) bool {
	return changedDuringPeriod && (p.IsPrivileged() || p.IsSensitive() || strings.Contains(p.AssignmentKind, "assignment"))
}

func EffectiveAccessPathRequestFromQuery(values url.Values) (EffectiveAccessPathRequest, error) {
	limit, err := uint32EffectiveAccessQueryParam(values.Get("limit"), "limit")
	if err != nil {
		return EffectiveAccessPathRequest{}, err
	}
	identityQuery := values.Get("identity_query")
	if identityQuery == "" {
		identityQuery = values.Get("q")
	}
	return EffectiveAccessPathRequest{
		TenantID:       values.Get("tenant_id"),
		IdentityURN:    values.Get("identity_urn"),
		IdentityQuery:  identityQuery,
		ApplicationURN: values.Get("application_urn"),
		Capability:     values.Get("capability"),
		Limit:          limit,
	}, nil
}

func (s *Service) GetEffectiveAccessPaths(ctx context.Context, request EffectiveAccessPathRequest) (*EffectiveAccessPathResult, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	identityURN := strings.TrimSpace(request.IdentityURN)
	identityQuery := strings.ToLower(strings.TrimSpace(request.IdentityQuery))
	if identityURN == "" && identityQuery == "" {
		return nil, fmt.Errorf("%w: identity_urn or identity_query is required", ErrInvalidRequest)
	}
	if err := validateOptionalTenantURN("identity_urn", tenantID, identityURN); err != nil {
		return nil, err
	}
	applicationURN := strings.TrimSpace(request.ApplicationURN)
	if err := validateOptionalTenantURN("application_urn", tenantID, applicationURN); err != nil {
		return nil, err
	}
	capability := strings.TrimSpace(request.Capability)
	capabilityURN := ""
	capabilityID := ""
	if strings.HasPrefix(capability, "urn:cerebro:") {
		if err := validateOptionalTenantURN("capability", tenantID, capability); err != nil {
			return nil, err
		}
		capabilityURN = capability
	} else {
		capabilityID = normalizeEffectiveCapabilityID(capability)
	}
	limit := normalizeEffectiveAccessPathLimit(request.Limit)
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: effectiveAccessPathQuery,
		Params: map[string]any{
			"application_urn": applicationURN,
			"capability_id":   capabilityID,
			"capability_urn":  capabilityURN,
			"identity_query":  identityQuery,
			"identity_urn":    identityURN,
			"sample_limit":    int64(limit),
			"tenant_id":       tenantID,
		},
		RowLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	paths := effectiveAccessPathsFromRows(rows)
	return &EffectiveAccessPathResult{
		TenantID: tenantID,
		Filters: EffectiveAccessPathFilters{
			IdentityURN:    identityURN,
			IdentityQuery:  identityQuery,
			ApplicationURN: applicationURN,
			Capability:     capability,
			Limit:          limit,
		},
		Counts: effectiveAccessPathCounts(paths),
		Paths:  paths,
	}, nil
}

func normalizeEffectiveAccessPathLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultEffectiveAccessPathLimit
	case limit > maxEffectiveAccessPathLimit:
		return maxEffectiveAccessPathLimit
	default:
		return int(limit)
	}
}

func uint32EffectiveAccessQueryParam(raw string, name string) (uint32, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid %s", ErrInvalidRequest, name)
	}
	if value == 0 {
		return 0, fmt.Errorf("%w: %s must be at least 1", ErrInvalidRequest, name)
	}
	return uint32(value), nil
}

func validateOptionalTenantURN(field string, tenantID string, urn string) error {
	if strings.TrimSpace(urn) == "" {
		return nil
	}
	if err := validateCerebroURN(urn); err != nil {
		return err
	}
	if urnTenant := tenantFromCerebroURN(urn); urnTenant != "" && urnTenant != tenantID {
		return fmt.Errorf("%w: %s tenant must match tenant_id", ErrInvalidRequest, field)
	}
	return nil
}

func normalizeEffectiveCapabilityID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, "-", "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}

const effectiveAccessPathQuery = `MATCH (subject:Entity {tenant_id: $tenant_id})
WHERE ($identity_urn = '' OR subject.urn = $identity_urn)
  AND ($identity_query = ''
       OR toLower(coalesce(subject.urn, '')) CONTAINS $identity_query
       OR toLower(coalesce(subject.label, '')) CONTAINS $identity_query
       OR toLower(coalesce(subject.attributes_json, '')) CONTAINS $identity_query)
WITH subject
ORDER BY subject.label, subject.urn
LIMIT $sample_limit
CALL {
  WITH subject
  RETURN subject AS principal
  UNION
  WITH subject
  MATCH (principal:Entity {tenant_id: $tenant_id})-[identity_link:RELATION]->(subject)
  WHERE identity_link.tenant_id = $tenant_id
    AND identity_link.relation IN ['represents_identity', 'same_actor']
  RETURN principal
  UNION
  WITH subject
  MATCH (subject)-[identity_link:RELATION]->(principal:Entity {tenant_id: $tenant_id})
  WHERE identity_link.tenant_id = $tenant_id
    AND identity_link.relation = 'same_actor'
  RETURN principal
  UNION
  WITH subject
  MATCH (subject)-[subject_link:RELATION {relation: 'represents_identity'}]->(identity:Entity {tenant_id: $tenant_id})<-[principal_link:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
  WHERE subject_link.tenant_id = $tenant_id
    AND principal_link.tenant_id = $tenant_id
  RETURN principal
  UNION
  WITH subject
  MATCH (subject)-[same_actor:RELATION {relation: 'same_actor'}]-(identity:Entity {tenant_id: $tenant_id})<-[principal_link:RELATION {relation: 'represents_identity'}]-(principal:Entity {tenant_id: $tenant_id})
  WHERE same_actor.tenant_id = $tenant_id
    AND principal_link.tenant_id = $tenant_id
  RETURN principal
}
WITH DISTINCT subject, principal
WHERE principal.tenant_id = $tenant_id
CALL {
  WITH subject, principal
  MATCH (principal)-[assignment:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE assignment.tenant_id = $tenant_id
    AND target.entity_type ENDS WITH '.application'
    AND ($application_urn = '' OR target.urn = $application_urn)
  MATCH (target)-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
  WHERE grant.tenant_id = $tenant_id
    AND confers.tenant_id = $tenant_id
    AND ($capability_urn = '' OR capability.urn = $capability_urn)
    AND ($capability_id = '' OR capability.urn ENDS WITH ':' + $capability_id)
  WITH subject, principal, target, entitlement, capability,
       null AS mediator,
       'direct_app_assignment' AS assignment_kind,
       [assignment, grant, confers] AS rels,
       [principal, target, entitlement, capability] AS path_nodes
  RETURN subject, principal, mediator, target, entitlement, capability, assignment_kind, rels, path_nodes
  UNION
  WITH subject, principal
  MATCH (principal)-[membership:RELATION {relation: 'member_of'}]->(mediator:Entity {tenant_id: $tenant_id})-[assignment:RELATION {relation: 'assigned_to'}]->(target:Entity {tenant_id: $tenant_id})
  WHERE membership.tenant_id = $tenant_id
    AND assignment.tenant_id = $tenant_id
    AND target.entity_type ENDS WITH '.application'
    AND ($application_urn = '' OR target.urn = $application_urn)
  MATCH (target)-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
  WHERE grant.tenant_id = $tenant_id
    AND confers.tenant_id = $tenant_id
    AND ($capability_urn = '' OR capability.urn = $capability_urn)
    AND ($capability_id = '' OR capability.urn ENDS WITH ':' + $capability_id)
  WITH subject, principal, mediator, target, entitlement, capability,
       'group_app_assignment' AS assignment_kind,
       [membership, assignment, grant, confers] AS rels,
       [principal, mediator, target, entitlement, capability] AS path_nodes
  RETURN subject, principal, mediator, target, entitlement, capability, assignment_kind, rels, path_nodes
  UNION
  WITH subject, principal
  MATCH (principal)-[role_assignment:RELATION]->(target:Entity {tenant_id: $tenant_id})-[grant:RELATION {relation: 'grants_entitlement'}]->(entitlement:Entity {tenant_id: $tenant_id})-[confers:RELATION {relation: 'confers_capability'}]->(capability:Entity {tenant_id: $tenant_id})
  WHERE $application_urn = ''
    AND role_assignment.tenant_id = $tenant_id
    AND role_assignment.relation IN ['assigned_to', 'can_admin']
    AND grant.tenant_id = $tenant_id
    AND confers.tenant_id = $tenant_id
    AND (target.entity_type ENDS WITH '.role' OR target.entity_type ENDS WITH '.admin_role')
    AND ($capability_urn = '' OR capability.urn = $capability_urn)
    AND ($capability_id = '' OR capability.urn ENDS WITH ':' + $capability_id)
  WITH subject, principal, target, entitlement, capability,
       null AS mediator,
       CASE WHEN role_assignment.relation = 'can_admin' THEN 'admin_role_assignment' ELSE 'role_assignment' END AS assignment_kind,
       [role_assignment, grant, confers] AS rels,
       [principal, target, entitlement, capability] AS path_nodes
  RETURN subject, principal, mediator, target, entitlement, capability, assignment_kind, rels, path_nodes
}
RETURN subject.urn AS identity_urn,
       subject.entity_type AS identity_entity_type,
       subject.label AS identity_label,
       principal.urn AS principal_urn,
       principal.entity_type AS principal_entity_type,
       principal.label AS principal_label,
       coalesce(mediator.urn, '') AS mediator_urn,
       coalesce(mediator.entity_type, '') AS mediator_entity_type,
       coalesce(mediator.label, '') AS mediator_label,
       target.urn AS target_urn,
       target.entity_type AS target_entity_type,
       target.label AS target_label,
       entitlement.urn AS entitlement_urn,
       entitlement.entity_type AS entitlement_entity_type,
       entitlement.label AS entitlement_label,
       capability.urn AS capability_urn,
       capability.entity_type AS capability_entity_type,
       capability.label AS capability_label,
       assignment_kind AS assignment_kind,
       [rel IN rels | rel.relation] AS relation_chain,
       [idx IN range(0, size(rels) - 1) | {
         from_urn: path_nodes[idx].urn,
         from_entity_type: path_nodes[idx].entity_type,
         from_label: path_nodes[idx].label,
         relation: rels[idx].relation,
         to_urn: path_nodes[idx + 1].urn,
         to_entity_type: path_nodes[idx + 1].entity_type,
         to_label: path_nodes[idx + 1].label,
         source_id: coalesce(rels[idx].source_id, ''),
         runtime_id: coalesce(rels[idx].runtime_id, ''),
         attributes_json: coalesce(rels[idx].attributes_json, '{}')
       }] AS edges
ORDER BY identity_label, principal_label, assignment_kind, target_label, entitlement_label, capability_label
LIMIT $sample_limit`

func effectiveAccessPathsFromRows(rows []ports.CypherRow) []EffectiveAccessPath {
	paths := make([]EffectiveAccessPath, 0, len(rows))
	for _, row := range rows {
		path := EffectiveAccessPath{
			Identity: GraphEntityRef{
				URN:        cypherString(row, "identity_urn"),
				EntityType: cypherString(row, "identity_entity_type"),
				Label:      cypherString(row, "identity_label"),
			},
			Principal: GraphEntityRef{
				URN:        cypherString(row, "principal_urn"),
				EntityType: cypherString(row, "principal_entity_type"),
				Label:      cypherString(row, "principal_label"),
			},
			AccessTarget: GraphEntityRef{
				URN:        cypherString(row, "target_urn"),
				EntityType: cypherString(row, "target_entity_type"),
				Label:      cypherString(row, "target_label"),
			},
			Entitlement: GraphEntityRef{
				URN:        cypherString(row, "entitlement_urn"),
				EntityType: cypherString(row, "entitlement_entity_type"),
				Label:      cypherString(row, "entitlement_label"),
			},
			Capability: GraphEntityRef{
				URN:        cypherString(row, "capability_urn"),
				EntityType: cypherString(row, "capability_entity_type"),
				Label:      cypherString(row, "capability_label"),
			},
			AssignmentKind: strings.TrimSpace(cypherString(row, "assignment_kind")),
			RelationChain:  cypherStringList(row.Values["relation_chain"]),
			Edges:          effectiveAccessPathEdgesFromRow(row),
		}
		if mediator := prefixedGraphRef(row, "mediator"); mediator.URN != "" {
			path.Mediator = &mediator
		}
		if path.Identity.URN == "" || path.Principal.URN == "" || path.AccessTarget.URN == "" || path.Entitlement.URN == "" || path.Capability.URN == "" || len(path.RelationChain) == 0 || !effectiveAccessPathEdgesMatch(path.RelationChain, path.Edges) {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func effectiveAccessPathEdgesFromRow(row ports.CypherRow) []EffectiveAccessPathEdge {
	items, ok := row.Values["edges"].([]any)
	if !ok || len(items) == 0 {
		return nil
	}
	edges := make([]EffectiveAccessPathEdge, 0, len(items))
	for _, item := range items {
		attributes := effectiveAccessEdgeAttributes(item)
		edge := EffectiveAccessPathEdge{
			From: GraphEntityRef{
				URN:        cypherMapString(item, "from_urn"),
				EntityType: cypherMapString(item, "from_entity_type"),
				Label:      cypherMapString(item, "from_label"),
			},
			Relation:   strings.TrimSpace(cypherMapString(item, "relation")),
			To:         GraphEntityRef{URN: cypherMapString(item, "to_urn"), EntityType: cypherMapString(item, "to_entity_type"), Label: cypherMapString(item, "to_label")},
			SourceID:   strings.TrimSpace(cypherMapString(item, "source_id")),
			RuntimeID:  strings.TrimSpace(cypherMapString(item, "runtime_id")),
			EventID:    strings.TrimSpace(attributes["event_id"]),
			At:         strings.TrimSpace(attributes["at"]),
			Attributes: attributes,
		}
		delete(edge.Attributes, "event_id")
		delete(edge.Attributes, "at")
		if len(edge.Attributes) == 0 {
			edge.Attributes = nil
		}
		if edge.From.URN == "" || edge.Relation == "" || edge.To.URN == "" {
			continue
		}
		edges = append(edges, edge)
	}
	return edges
}

func effectiveAccessEdgeAttributes(item any) map[string]string {
	raw := cypherMapString(item, "attributes_json")
	if raw == "" {
		return map[string]string{}
	}
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &attributes); err == nil {
		return attributes
	}
	anyAttributes := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &anyAttributes); err != nil {
		return map[string]string{}
	}
	for key, value := range anyAttributes {
		if text := strings.TrimSpace(cypherAnyString(value)); text != "" {
			attributes[key] = text
		}
	}
	return attributes
}

func effectiveAccessPathEdgesMatch(relationChain []string, edges []EffectiveAccessPathEdge) bool {
	if len(relationChain) == 0 || len(edges) != len(relationChain) {
		return false
	}
	for idx, relation := range relationChain {
		if strings.TrimSpace(relation) == "" || strings.TrimSpace(relation) != edges[idx].Relation {
			return false
		}
	}
	return true
}

func effectiveAccessPathCounts(paths []EffectiveAccessPath) EffectiveAccessPathCounts {
	counts := EffectiveAccessPathCounts{Paths: len(paths)}
	capabilities := map[string]struct{}{}
	for _, path := range paths {
		switch path.AssignmentKind {
		case "direct_app_assignment":
			counts.DirectAssignments++
		case "group_app_assignment":
			counts.GroupMediatedPaths++
		case "role_assignment":
			counts.RolePaths++
		case "admin_role_assignment":
			counts.AdminRolePaths++
		}
		if path.Capability.URN != "" {
			capabilities[path.Capability.URN] = struct{}{}
		}
	}
	counts.CapabilitiesReturned = len(capabilities)
	return counts
}

func uniqueEffectiveAccessLabels(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
