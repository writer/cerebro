package ports

import (
	"context"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	cerebrourn "github.com/writer/cerebro/internal/urn"
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

// ValidateProjectedTenantScopes rejects Cerebro-owned projection URNs that do
// not belong to the projection tenant. Provider-native identifiers remain valid.
func ValidateProjectedTenantScopes(entities []*ProjectedEntity, links []*ProjectedLink) error {
	for _, entity := range entities {
		if err := ValidateProjectedEntityTenantScope(entity); err != nil {
			return err
		}
	}
	for _, link := range links {
		if err := ValidateProjectedLinkTenantScope(link); err != nil {
			return err
		}
	}
	return nil
}

// ValidateProjectedEntityTenantScope enforces that a Cerebro-owned entity URN
// cannot be projected under a different tenant_id.
func ValidateProjectedEntityTenantScope(entity *ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	return validateProjectedCerebroURNScope("projected entity urn", entity.URN, entity.TenantID)
}

// ValidateProjectedLinkTenantScope enforces that Cerebro-owned link endpoints
// cannot be projected under a different tenant_id.
func ValidateProjectedLinkTenantScope(link *ProjectedLink) error {
	if link == nil {
		return nil
	}
	if err := validateProjectedCerebroURNScope("projected link from urn", link.FromURN, link.TenantID); err != nil {
		return err
	}
	return validateProjectedCerebroURNScope("projected link to urn", link.ToURN, link.TenantID)
}

func validateProjectedCerebroURNScope(field string, rawURN string, rawTenantID string) error {
	urn := strings.TrimSpace(rawURN)
	tenantID := strings.TrimSpace(rawTenantID)
	if urn == "" || tenantID == "" || !strings.HasPrefix(urn, cerebrourn.Prefix) {
		return nil
	}
	parsed, err := cerebrourn.Parse(urn)
	if err != nil {
		return fmt.Errorf("%s %q is invalid: %w", field, urn, err)
	}
	if parsed.TenantID != tenantID {
		return fmt.Errorf("%s %q is scoped to tenant %q, not projection tenant %q", field, urn, parsed.TenantID, tenantID)
	}
	return nil
}

// ProjectionResult reports how many workflow events, entities, and links were materialized or pruned.
type ProjectionResult struct {
	EventsProjected   uint32
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

// ProjectionEntityReader reads normalized current-state entities when a projector
// needs to compare immutable identity fields before applying an update.
type ProjectionEntityReader interface {
	GetProjectedEntity(context.Context, string) (*ProjectedEntity, error)
}

// ProjectionRuntimeEvidenceReader reads runtime evidence by its stable source
// event identity before projection assigns or updates evidence-specific URNs.
type ProjectionRuntimeEvidenceReader interface {
	GetProjectedRuntimeEvidenceBySourceEvent(context.Context, string, string, string) (*ProjectedEntity, error)
}

// ProjectionGraphStore persists normalized entities and links into the graph.
type ProjectionGraphStore interface {
	GraphStore
	UpsertProjectedEntity(context.Context, *ProjectedEntity) error
	UpsertProjectedLink(context.Context, *ProjectedLink) error
}

// ProjectionGraphBatchStore upserts coalesced entities and links in batches,
// collapsing the per-element merge/load and version-checked update round-trips
// of ProjectionGraphStore into a handful of UNWIND transactions. Graph stores
// that implement it are preferred by the projection writer; callers fall back
// to the per-element ProjectionGraphStore methods when it is not implemented.
// Batch methods preserve the exact per-element semantics: tenant-scope
// validation, attribute deep-merge, typed-property derivation, monotonic
// attributes_version, and links materialized only when both endpoints exist.
type ProjectionGraphBatchStore interface {
	UpsertProjectedEntities(context.Context, []*ProjectedEntity) error
	UpsertProjectedLinks(context.Context, []*ProjectedLink) error
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
