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
	store ports.CloudAttackPathStore
	depth int
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

func New(store ports.CloudAttackPathStore) *Engine {
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
	result := &Result{
		TenantID: tenantID,
		Filters: Filters{
			AccountID:             strings.TrimSpace(request.AccountID),
			RuntimeID:             strings.TrimSpace(request.RuntimeID),
			RequireAssertionProof: request.RequireAssertionProof,
			Limit:                 limit,
		},
	}
	typed, err := e.store.ListCloudAttackPaths(ctx, ports.CloudAttackPathRequest{
		TenantID:              tenantID,
		AccountID:             result.Filters.AccountID,
		RuntimeID:             result.Filters.RuntimeID,
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

func applyTypedResult(result *Result, typed *ports.CloudAttackPathResult, limit int) error {
	if result == nil || typed == nil || typed.TenantID != result.TenantID {
		return fmt.Errorf("%w: typed attack path returned an invalid tenant", ErrRuntimeUnavailable)
	}
	if len(typed.Paths) > limit || (typed.Truncated && len(typed.Paths) != limit) {
		return fmt.Errorf("%w: typed attack path returned an invalid bound", ErrRuntimeUnavailable)
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
	attributes := decodeAttributes(edge.AttributesJSON)
	sourceRuntimeID := firstNonEmpty(edge.SourceRuntimeID, attributes["source_runtime_id"])
	assertionRuntimeIDs := append([]string(nil), edge.AssertionRuntimeIDs...)
	assertionRuntimeIDs = append(assertionRuntimeIDs, sourceRuntimeID)
	return Edge{
		From:                nodeFromTyped(edge.From),
		Relation:            edge.Relation,
		To:                  nodeFromTyped(edge.To),
		Direction:           edge.Direction,
		SourceID:            firstNonEmpty(edge.SourceID, attributes["source_id"]),
		SourceRuntimeID:     sourceRuntimeID,
		AssertionRuntimeIDs: normalizedStringList(assertionRuntimeIDs),
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

func privilegedAccessRelations() []string {
	return []string{"can_admin", "can_perform", "can_assume", "can_impersonate"}
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

func decodeAttributes(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil
	}
	result := make(map[string]string, len(decoded))
	for key, value := range decoded {
		result[key] = strings.TrimSpace(attributeString(value))
	}
	return result
}

func attributeString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
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

func uint64ToInt(value uint64) int {
	if value > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}
