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
	RuntimeID  string
	EntityType string
	Label      string
	Attributes map[string]string
}

// ProjectedLink is the normalized graph edge shape.
type ProjectedLink struct {
	TenantID   string
	SourceID   string
	RuntimeID  string
	FromURN    string
	ToURN      string
	Relation   string
	Attributes map[string]string
}

// ProjectionResult reports how many entities and links were materialized.
type ProjectionResult struct {
	EntitiesProjected uint32
	LinksProjected    uint32
	EntitiesDeleted   uint32
	LinksDeleted      uint32
}

// ProjectionCleanupRequest scopes opportunistic graph cleanup to one tenant/source/runtime boundary.
type ProjectionCleanupRequest struct {
	TenantID     string
	SourceID     string
	RuntimeID    string
	FindingID    string
	EntityTypes  []string
	URNPrefixes  []string
	OnlyIsolated bool
	Limit        uint32
	DryRun       bool
}

// ProjectionCleanupResult reports graph objects removed by one cleanup pass.
type ProjectionCleanupResult struct {
	EntitiesMatched uint32
	LinksMatched    uint32
	EntitiesDeleted uint32
	LinksDeleted    uint32
}

// ProjectionLinkCleanupRequest scopes a destructive projection-link cleanup pass.
type ProjectionLinkCleanupRequest struct {
	TenantID  string
	SourceID  string
	RuntimeID string
	Limit     uint32
	DryRun    bool
}

// ProjectionLinkCleanupResult reports links found/deleted by one cleanup pass.
type ProjectionLinkCleanupResult struct {
	LinksMatched uint32
	LinksDeleted uint32
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

// ProjectionEntityDeleter removes normalized entities from projection stores that support deletion.
type ProjectionEntityDeleter interface {
	DeleteProjectedEntity(context.Context, string) error
}

// ProjectionCleaner removes stale or orphaned projection artifacts in scoped batches.
type ProjectionCleaner interface {
	CleanupProjectedEntities(context.Context, ProjectionCleanupRequest) (ProjectionCleanupResult, error)
}

// EndpointOwnerIDLinkCleaner removes stale endpoint owner_id/user_id canonical identity links.
type EndpointOwnerIDLinkCleaner interface {
	CleanupEndpointOwnerIDLinks(context.Context, ProjectionLinkCleanupRequest) (ProjectionLinkCleanupResult, error)
}

// SourceProjector materializes source events into current-state and graph stores.
type SourceProjector interface {
	Project(context.Context, *cerebrov1.EventEnvelope) (ProjectionResult, error)
}
