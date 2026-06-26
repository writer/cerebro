package ports

import (
	"context"
	"errors"
)

// ErrGraphEntityNotFound indicates that the requested graph root entity does not exist.
var ErrGraphEntityNotFound = errors.New("graph entity not found")

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

// GraphQueryStore exposes bounded graph neighborhood reads and read-only Cypher.
type GraphQueryStore interface {
	GraphStore
	GetEntityNeighborhood(context.Context, string, int) (*EntityNeighborhood, error)
	ExecuteReadCypher(context.Context, CypherQueryRequest) ([]CypherRow, error)
}

// GraphNeighborhoodBatchStore exposes batched bounded graph neighborhood reads.
type GraphNeighborhoodBatchStore interface {
	GetEntityNeighborhoods(context.Context, []string, int) (map[string]*EntityNeighborhood, error)
}
