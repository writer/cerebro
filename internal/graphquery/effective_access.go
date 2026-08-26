package graphquery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

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
	Paths                  int `json:"paths"`
	LineageQualifiedPaths  int `json:"lineage_qualified_paths"`
	LineageIncompletePaths int `json:"lineage_incomplete_paths"`
	DirectAssignments      int `json:"direct_assignments"`
	GroupMediatedPaths     int `json:"group_mediated_paths"`
	RolePaths              int `json:"role_paths"`
	AdminRolePaths         int `json:"admin_role_paths"`
	CapabilitiesReturned   int `json:"capabilities_returned"`
}

type EffectiveAccessPath struct {
	Identity              GraphEntityRef                      `json:"identity"`
	Principal             GraphEntityRef                      `json:"principal"`
	Mediator              *GraphEntityRef                     `json:"mediator,omitempty"`
	AccessTarget          GraphEntityRef                      `json:"access_target"`
	Entitlement           GraphEntityRef                      `json:"entitlement"`
	Capability            GraphEntityRef                      `json:"capability"`
	AssignmentKind        string                              `json:"assignment_kind"`
	IdentityRelationChain []string                            `json:"identity_relation_chain,omitempty"`
	IdentityEdges         []EffectiveAccessPathEdge           `json:"identity_edges,omitempty"`
	RelationChain         []string                            `json:"relation_chain"`
	Edges                 []EffectiveAccessPathEdge           `json:"edges"`
	Lineage               EffectiveAccessLineageQualification `json:"lineage"`
}

type EffectiveAccessLineageGap struct {
	Segment   string   `json:"segment"`
	EdgeIndex int      `json:"edge_index"`
	Fields    []string `json:"fields"`
}

// EffectiveAccessLineageQualification describes whether every relation in an
// access path can be traced to a source observation. An incomplete path remains
// visible to callers, but it cannot be presented as qualified proof.
type EffectiveAccessLineageQualification struct {
	Qualified         bool                        `json:"qualified"`
	EdgeCount         int                         `json:"edge_count"`
	CompleteEdgeCount int                         `json:"complete_edge_count"`
	SourceIDs         []string                    `json:"source_ids"`
	RuntimeIDs        []string                    `json:"runtime_ids"`
	EventIDs          []string                    `json:"event_ids"`
	Gaps              []EffectiveAccessLineageGap `json:"gaps,omitempty"`
	ProofDigest       string                      `json:"proof_digest,omitempty"`
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
	return changedDuringPeriod && (p.IsPrivileged() || p.IsSensitive())
}

// QualifyLineage fails closed unless the graph path is structurally complete
// and every edge carries source, runtime, event, and observation-time lineage.
func (p EffectiveAccessPath) QualifyLineage() EffectiveAccessLineageQualification {
	qualification := EffectiveAccessLineageQualification{EdgeCount: len(p.IdentityEdges) + len(p.Edges)}
	sources, runtimes, events := []string{}, []string{}, []string{}
	for _, segment := range []struct {
		name  string
		edges []EffectiveAccessPathEdge
	}{
		{name: "identity", edges: p.IdentityEdges},
		{name: "access", edges: p.Edges},
	} {
		for index, edge := range segment.edges {
			missing := []string{}
			for field, value := range map[string]string{
				"from_urn":    edge.From.URN,
				"relation":    edge.Relation,
				"to_urn":      edge.To.URN,
				"source_id":   edge.SourceID,
				"runtime_id":  edge.RuntimeID,
				"event_id":    edge.EventID,
				"observed_at": edge.At,
			} {
				if strings.TrimSpace(value) == "" {
					missing = append(missing, field)
				}
			}
			if edge.At != "" {
				if _, err := time.Parse(time.RFC3339, edge.At); err != nil {
					missing = append(missing, "observed_at")
				}
			}
			if index > 0 && segment.edges[index-1].To.URN != edge.From.URN {
				missing = append(missing, "edge_continuity")
			}
			missing = uniqueEffectiveAccessLabels(missing)
			if len(missing) != 0 {
				qualification.Gaps = append(qualification.Gaps, EffectiveAccessLineageGap{Segment: segment.name, EdgeIndex: index, Fields: missing})
				continue
			}
			qualification.CompleteEdgeCount++
			sources = append(sources, edge.SourceID)
			runtimes = append(runtimes, edge.RuntimeID)
			events = append(events, edge.EventID)
		}
	}
	qualification.SourceIDs = uniqueEffectiveAccessLabels(sources)
	qualification.RuntimeIDs = uniqueEffectiveAccessLabels(runtimes)
	qualification.EventIDs = uniqueEffectiveAccessLabels(events)
	identityGaps := []string{}
	if p.Identity.URN != p.Principal.URN && len(p.IdentityEdges) == 0 {
		identityGaps = append(identityGaps, "identity_path")
	}
	if len(p.IdentityEdges) != 0 {
		if p.IdentityEdges[0].From.URN != p.Identity.URN {
			identityGaps = append(identityGaps, "identity")
		}
		if p.IdentityEdges[len(p.IdentityEdges)-1].To.URN != p.Principal.URN {
			identityGaps = append(identityGaps, "principal")
		}
		if !effectiveAccessPathEdgesMatch(p.IdentityRelationChain, p.IdentityEdges) {
			identityGaps = append(identityGaps, "relation_chain")
		}
	}
	if identityGaps = uniqueEffectiveAccessLabels(identityGaps); len(identityGaps) != 0 {
		qualification.Gaps = append(qualification.Gaps, EffectiveAccessLineageGap{Segment: "identity", EdgeIndex: -1, Fields: identityGaps})
	}
	accessGaps := []string{}
	if len(p.Edges) == 0 {
		accessGaps = append(accessGaps, "edges")
	} else {
		if p.Edges[0].From.URN != p.Principal.URN {
			accessGaps = append(accessGaps, "principal")
		}
		if p.Edges[len(p.Edges)-1].To.URN != p.Capability.URN {
			accessGaps = append(accessGaps, "capability")
		}
	}
	if !effectiveAccessPathEdgesMatch(p.RelationChain, p.Edges) {
		accessGaps = append(accessGaps, "relation_chain")
	}
	if !accessPathContainsURN(p.Edges, p.AccessTarget.URN) {
		accessGaps = append(accessGaps, "access_target")
	}
	if !accessPathContainsURN(p.Edges, p.Entitlement.URN) {
		accessGaps = append(accessGaps, "entitlement")
	}
	if accessGaps = uniqueEffectiveAccessLabels(accessGaps); len(accessGaps) != 0 {
		qualification.Gaps = append(qualification.Gaps, EffectiveAccessLineageGap{Segment: "access", EdgeIndex: -1, Fields: accessGaps})
	}
	qualification.Qualified = len(qualification.Gaps) == 0
	if qualification.Qualified {
		payload, err := json.Marshal(struct {
			Identity              GraphEntityRef            `json:"identity"`
			Principal             GraphEntityRef            `json:"principal"`
			Mediator              *GraphEntityRef           `json:"mediator,omitempty"`
			AccessTarget          GraphEntityRef            `json:"access_target"`
			Entitlement           GraphEntityRef            `json:"entitlement"`
			Capability            GraphEntityRef            `json:"capability"`
			AssignmentKind        string                    `json:"assignment_kind"`
			IdentityRelationChain []string                  `json:"identity_relation_chain,omitempty"`
			IdentityEdges         []EffectiveAccessPathEdge `json:"identity_edges,omitempty"`
			RelationChain         []string                  `json:"relation_chain"`
			Edges                 []EffectiveAccessPathEdge `json:"edges"`
		}{p.Identity, p.Principal, p.Mediator, p.AccessTarget, p.Entitlement, p.Capability, p.AssignmentKind, p.IdentityRelationChain, p.IdentityEdges, p.RelationChain, p.Edges})
		if err == nil {
			digest := sha256.Sum256(payload)
			qualification.ProofDigest = "sha256:" + hex.EncodeToString(digest[:])
		}
	}
	return qualification
}

func accessPathContainsURN(edges []EffectiveAccessPathEdge, urn string) bool {
	if strings.TrimSpace(urn) == "" {
		return false
	}
	for _, edge := range edges {
		if edge.From.URN == urn || edge.To.URN == urn {
			return true
		}
	}
	return false
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
	if s == nil || s.rawCypher == nil {
		return nil, ErrRuntimeUnavailable
	}
	typedStore, ok := s.rawCypher.(ports.EffectiveAccessPathStore)
	if !ok || typedStore == nil {
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
	typed, err := typedStore.ListEffectiveAccessPaths(ctx, ports.EffectiveAccessPathRequest{
		TenantID:       tenantID,
		IdentityURN:    identityURN,
		IdentityQuery:  identityQuery,
		ApplicationURN: applicationURN,
		CapabilityURN:  capabilityURN,
		CapabilityID:   capabilityID,
		Limit:          limit,
	})
	if err != nil {
		return nil, err
	}
	if typed == nil || typed.TenantID != tenantID || len(typed.Paths) > limit {
		return nil, fmt.Errorf("%w: typed effective access returned an invalid tenant or bound", ErrRuntimeUnavailable)
	}
	paths := make([]EffectiveAccessPath, 0, len(typed.Paths))
	for _, path := range typed.Paths {
		converted, err := effectiveAccessPathFromTyped(path)
		if err != nil {
			return nil, err
		}
		paths = append(paths, converted)
	}
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

func effectiveAccessPathFromTyped(path ports.EffectiveAccessPath) (EffectiveAccessPath, error) {
	converted := EffectiveAccessPath{
		Identity:              catalogGraphRef(path.Identity),
		Principal:             catalogGraphRef(path.Principal),
		AccessTarget:          catalogGraphRef(path.AccessTarget),
		Entitlement:           catalogGraphRef(path.Entitlement),
		Capability:            catalogGraphRef(path.Capability),
		AssignmentKind:        strings.TrimSpace(path.AssignmentKind),
		IdentityRelationChain: append([]string(nil), path.IdentityRelationChain...),
		RelationChain:         append([]string(nil), path.RelationChain...),
	}
	if path.Mediator != nil {
		mediator := catalogGraphRef(*path.Mediator)
		converted.Mediator = &mediator
	}
	for _, edge := range path.IdentityEdges {
		converted.IdentityEdges = append(converted.IdentityEdges, effectiveAccessEdgeFromTyped(edge))
	}
	for _, edge := range path.Edges {
		converted.Edges = append(converted.Edges, effectiveAccessEdgeFromTyped(edge))
	}
	if converted.Identity.URN == "" || converted.Principal.URN == "" || converted.AccessTarget.URN == "" || converted.Entitlement.URN == "" || converted.Capability.URN == "" || !effectiveAccessPathEdgesMatch(converted.RelationChain, converted.Edges) || len(converted.IdentityRelationChain) != len(converted.IdentityEdges) {
		return EffectiveAccessPath{}, fmt.Errorf("%w: typed effective access returned an invalid path", ErrRuntimeUnavailable)
	}
	converted.Lineage = converted.QualifyLineage()
	return converted, nil
}

func effectiveAccessEdgeFromTyped(edge ports.EffectiveAccessPathEdge) EffectiveAccessPathEdge {
	attributes := effectiveAccessAttributesJSON(edge.AttributesJSON)
	converted := EffectiveAccessPathEdge{
		From:       catalogGraphRef(edge.From),
		Relation:   strings.TrimSpace(edge.Relation),
		To:         catalogGraphRef(edge.To),
		SourceID:   strings.TrimSpace(edge.SourceID),
		RuntimeID:  strings.TrimSpace(edge.RuntimeID),
		EventID:    strings.TrimSpace(attributes["event_id"]),
		At:         strings.TrimSpace(attributes["at"]),
		Attributes: attributes,
	}
	delete(converted.Attributes, "event_id")
	delete(converted.Attributes, "at")
	if len(converted.Attributes) == 0 {
		converted.Attributes = nil
	}
	return converted
}

func effectiveAccessAttributesJSON(raw string) map[string]string {
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
		lineage := path.Lineage
		if lineage.EdgeCount == 0 {
			lineage = path.QualifyLineage()
		}
		if lineage.Qualified {
			counts.LineageQualifiedPaths++
		} else {
			counts.LineageIncompletePaths++
		}
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
