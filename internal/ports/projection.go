package ports

import (
	"context"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// ProjectedEntity is the normalized current-state and graph entity shape.
type ProjectedEntity struct {
	URN        string
	TenantID   string
	SourceID   string
	EntityType string
	Label      string
	Attributes map[string]string
}

// ProjectedLink is the normalized graph edge shape.
type ProjectedLink struct {
	TenantID   string
	SourceID   string
	FromURN    string
	ToURN      string
	Relation   string
	Attributes map[string]string
}

// ProjectionResult reports how many entities and links were materialized.
type ProjectionResult struct {
	EntitiesProjected uint32
	LinksProjected    uint32
}

// ProjectionStateStore persists normalized current-state entities and links.
type ProjectionStateStore interface {
	StateStore
	UpsertProjectedEntity(context.Context, *ProjectedEntity) error
	UpsertProjectedLink(context.Context, *ProjectedLink) error
}

// ProjectionGraphStore persists normalized entities and links into the graph.
type ProjectionGraphStore interface {
	GraphStore
	UpsertProjectedEntity(context.Context, *ProjectedEntity) error
	UpsertProjectedLink(context.Context, *ProjectedLink) error
}

// ProjectionLinkDeleter removes normalized links from projection stores that support deletion.
type ProjectionLinkDeleter interface {
	DeleteProjectedLink(context.Context, *ProjectedLink) error
}

// SourceProjector materializes source events into current-state and graph stores.
type SourceProjector interface {
	Project(context.Context, *cerebrov1.EventEnvelope) (ProjectionResult, error)
}
