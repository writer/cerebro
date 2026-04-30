package ports

import (
	"context"
	"errors"
)

// ErrGraphEntityNotFound indicates that the requested graph root entity does not exist.
var ErrGraphEntityNotFound = errors.New("graph entity not found")

// NeighborhoodNode is the normalized graph node shape returned by bounded neighborhood queries.
type NeighborhoodNode struct {
	URN        string
	EntityType string
	Label      string
}

// NeighborhoodRelation is the normalized graph edge shape returned by bounded neighborhood queries.
type NeighborhoodRelation struct {
	FromURN  string
	Relation string
	ToURN    string
}

// EntityNeighborhood is one bounded graph neighborhood centered on a root entity.
type EntityNeighborhood struct {
	Root      *NeighborhoodNode
	Neighbors []*NeighborhoodNode
	Relations []*NeighborhoodRelation
}

// GraphQueryStore exposes bounded graph neighborhood reads.
type GraphQueryStore interface {
	GraphStore
	GetEntityNeighborhood(context.Context, string, int) (*EntityNeighborhood, error)
}
