package ports

import (
	"context"
	"errors"
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

// GraphReadStore is the top-level graph read handle wired by bootstrap: Rust
// authority typed reads (neighborhoods, batched neighborhoods, entity catalog,
// exposure coverage) plus the retained raw-Cypher compatibility surface.
// Consumers narrow it to the capability interfaces they need.
type GraphReadStore interface {
	GraphNeighborhoodStore
	GraphNeighborhoodBatchStore
	EntityCatalogStore
	ExposureCoverageStore
	RawCypherQueryStore
}

// GraphNeighborhoodBatchStore exposes batched bounded graph neighborhood reads.
type GraphNeighborhoodBatchStore interface {
	GetEntityNeighborhoods(context.Context, []string, int) (map[string]*EntityNeighborhood, error)
}
