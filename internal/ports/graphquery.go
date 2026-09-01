package ports

import (
	"context"
	"errors"
	"reflect"
)

// ErrGraphEntityNotFound indicates that the requested graph root entity does not exist.
var ErrGraphEntityNotFound = errors.New("graph entity not found")

// ErrGraphRuntimeUnavailable indicates that the configured graph read authority
// could not serve the request.
var ErrGraphRuntimeUnavailable = errors.New("graph runtime unavailable")

// ErrGraphTypedOperationRequired indicates that a caller still depends on raw
// Cypher and must move to a bounded Rust graph operation before strict
// replacement mode can serve it.
var ErrGraphTypedOperationRequired = errors.New("typed Rust graph operation required")

// NeighborhoodNode is the normalized graph node shape returned by bounded neighborhood queries.
type NeighborhoodNode struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

// NeighborhoodRelation is the normalized graph edge shape returned by bounded neighborhood queries.
type NeighborhoodRelation struct {
	FromURN    string            `json:"from_urn"`
	Relation   string            `json:"relation"`
	ToURN      string            `json:"to_urn"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// EntityNeighborhood is one bounded graph neighborhood centered on a root entity.
type EntityNeighborhood struct {
	Root      *NeighborhoodNode       `json:"root,omitempty"`
	Neighbors []*NeighborhoodNode     `json:"neighbors"`
	Relations []*NeighborhoodRelation `json:"relations"`
}

// CypherRow is one row returned by a read-only Cypher query.
type CypherRow struct {
	Values map[string]any
}

// CypherQueryRequest scopes one read-only graph query call.
type CypherQueryRequest struct {
	Query    string
	Params   map[string]any
	RowLimit int
}

// CypherPlan is a normalized read query execution plan returned by EXPLAIN.
type CypherPlan struct {
	Root *CypherPlanNode
}

// CypherPlanNode is one operator in a normalized Cypher execution plan tree.
type CypherPlanNode struct {
	Operator  string
	Arguments map[string]any
	Children  []CypherPlanNode
}

// MaxCypherQueryRows caps the number of rows the graph store will return for one read query.
const MaxCypherQueryRows = 3000

// GraphNeighborhoodStore exposes bounded product graph reads.
type GraphNeighborhoodStore interface {
	GraphStore
	GetEntityNeighborhood(context.Context, string, int) (*EntityNeighborhood, error)
}

// RawCypherQueryStore is the retained compatibility surface for callers that
// have not migrated to bounded typed Rust operations.
type RawCypherQueryStore interface {
	GraphStore
	ExecuteReadCypher(context.Context, CypherQueryRequest) ([]CypherRow, error)
}

// FindingGraphRuleRequest selects one closed Rust-owned graph rule. Params may
// contain only the non-tenant parameters declared by that rule's catalog entry.
type FindingGraphRuleRequest struct {
	TenantID  string
	RuntimeID string
	RuleID    string
	Params    map[string]any
	RowLimit  int
}

// FindingGraphRuleResult contains the bounded rows returned by one rule.
type FindingGraphRuleResult struct {
	Rows      []CypherRow
	Truncated bool
}

// FindingGraphRuleStore exposes closed finding rule reads without accepting
// caller-supplied Cypher.
type FindingGraphRuleStore interface {
	GraphStore
	RunFindingGraphRule(context.Context, FindingGraphRuleRequest) (*FindingGraphRuleResult, error)
}

type GraphReadCapabilities struct {
	Neighborhoods     GraphNeighborhoodStore
	RawCypher         RawCypherQueryStore
	Catalog           EntityCatalogStore
	Exposure          ExposureCoverageStore
	EntityKindCounts  EntityKindCountStore
	RelationCounts    RelationCountStore
	PersonAccess      PersonAccessPathStore
	EffectiveAccess   EffectiveAccessPathStore
	CloudAttackPaths  CloudAttackPathStore
	CrownJewelPaths   CrownJewelPathStore
	FindingGraphRules FindingGraphRuleStore
	VendorRegister    VendorRegisterStore
	VendorDiscoveries VendorDiscoveryRegisterStore
	ComplianceImpact  ComplianceImpactGraph
}

func NewGraphReadCapabilities(store GraphStore) GraphReadCapabilities {
	if isNilGraphReadCapability(store) {
		return GraphReadCapabilities{}
	}
	var capabilities GraphReadCapabilities
	if neighborhoods, ok := store.(GraphNeighborhoodStore); ok && !isNilGraphReadCapability(neighborhoods) {
		capabilities.Neighborhoods = neighborhoods
	}
	if rawCypher, ok := store.(RawCypherQueryStore); ok && !isNilGraphReadCapability(rawCypher) {
		capabilities.RawCypher = rawCypher
	}
	if catalog, ok := store.(EntityCatalogStore); ok && !isNilGraphReadCapability(catalog) {
		capabilities.Catalog = catalog
	}
	if exposure, ok := store.(ExposureCoverageStore); ok && !isNilGraphReadCapability(exposure) {
		capabilities.Exposure = exposure
	}
	if entityKindCounts, ok := store.(EntityKindCountStore); ok && !isNilGraphReadCapability(entityKindCounts) {
		capabilities.EntityKindCounts = entityKindCounts
	}
	if relationCounts, ok := store.(RelationCountStore); ok && !isNilGraphReadCapability(relationCounts) {
		capabilities.RelationCounts = relationCounts
	}
	if personAccess, ok := store.(PersonAccessPathStore); ok && !isNilGraphReadCapability(personAccess) {
		capabilities.PersonAccess = personAccess
	}
	if effectiveAccess, ok := store.(EffectiveAccessPathStore); ok && !isNilGraphReadCapability(effectiveAccess) {
		capabilities.EffectiveAccess = effectiveAccess
	}
	if cloudAttackPaths, ok := store.(CloudAttackPathStore); ok && !isNilGraphReadCapability(cloudAttackPaths) {
		capabilities.CloudAttackPaths = cloudAttackPaths
	}
	if crownJewelPaths, ok := store.(CrownJewelPathStore); ok && !isNilGraphReadCapability(crownJewelPaths) {
		capabilities.CrownJewelPaths = crownJewelPaths
	}
	if findingGraphRules, ok := store.(FindingGraphRuleStore); ok && !isNilGraphReadCapability(findingGraphRules) {
		capabilities.FindingGraphRules = findingGraphRules
	}
	if vendorRegister, ok := store.(VendorRegisterStore); ok && !isNilGraphReadCapability(vendorRegister) {
		capabilities.VendorRegister = vendorRegister
	}
	if vendorDiscoveries, ok := store.(VendorDiscoveryRegisterStore); ok && !isNilGraphReadCapability(vendorDiscoveries) {
		capabilities.VendorDiscoveries = vendorDiscoveries
	}
	if complianceImpact, ok := store.(ComplianceImpactGraph); ok && !isNilGraphReadCapability(complianceImpact) {
		capabilities.ComplianceImpact = complianceImpact
	}
	return capabilities
}

func (c GraphReadCapabilities) ReadinessStore() GraphStore {
	if !isNilGraphReadCapability(c.Neighborhoods) {
		return c.Neighborhoods
	}
	if !isNilGraphReadCapability(c.RawCypher) {
		return c.RawCypher
	}
	return nil
}

func isNilGraphReadCapability(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// GraphNeighborhoodBatchStore exposes batched bounded graph neighborhood reads.
type GraphNeighborhoodBatchStore interface {
	GetEntityNeighborhoods(context.Context, []string, int) (map[string]*EntityNeighborhood, error)
}
