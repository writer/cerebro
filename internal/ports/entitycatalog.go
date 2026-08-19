package ports

import "context"

type EntityCatalogFilter struct {
	TenantID            string
	SourceID            string
	RuntimeIDs          []string
	ExactAgentKey       string
	IncludeKinds        []string
	IncludeKindPrefixes []string
	ExcludeKinds        []string
	ExcludeKindPrefixes []string
	Query               string
	QueryAttributes     bool
	ExpectedRevision    uint64
	RelationCounts      *EntityRelationCountFilter
}

type EntityRelationCountFilter struct {
	Directions    []EntityRelationDirection
	Relations     []string
	NeighborKinds []string
}

type CatalogEntity struct {
	URN        string
	TenantID   string
	EntityType string
	Label      string
	SourceID   string
	RuntimeID  string
	Attributes map[string]string
}

type EntityCatalogPageRequest struct {
	Filter        EntityCatalogFilter
	Limit         int
	AfterAgentKey string
}

type EntityCatalogPage struct {
	TenantID          string
	GraphRevision     uint64
	Entities          []CatalogEntity
	Truncated         bool
	NextAfterAgentKey string
	RelationCounts    []EntityRelationCount
}

type EntityRelationCount struct {
	AgentKey     string
	Direction    EntityRelationDirection
	Relation     string
	NeighborKind string
	Count        uint64
}

type EntityKindCount struct {
	EntityKind string
	Count      uint64
}

type EntityKindCountRequest struct {
	Filter          EntityCatalogFilter
	Limit           int
	AfterEntityKind string
}

type EntityKindCountPage struct {
	TenantID            string
	GraphRevision       uint64
	Counts              []EntityKindCount
	Truncated           bool
	NextAfterEntityKind string
}

type EntityKindCountStore interface {
	CountEntityKinds(context.Context, EntityKindCountRequest) (*EntityKindCountPage, error)
}

type RelationCount struct {
	Relation string
	Count    uint64
}

type RelationCountRequest struct {
	TenantID         string
	Limit            int
	AfterRelation    string
	ExpectedRevision uint64
}

type RelationCountPage struct {
	TenantID          string
	GraphRevision     uint64
	Counts            []RelationCount
	Truncated         bool
	NextAfterRelation string
}

type RelationCountStore interface {
	CountRelations(context.Context, RelationCountRequest) (*RelationCountPage, error)
}

type EntityRelationDirection string

const (
	EntityRelationIncoming EntityRelationDirection = "incoming"
	EntityRelationOutgoing EntityRelationDirection = "outgoing"
)

type EntityCatalogRelation struct {
	Direction EntityRelationDirection
	Relation  string
	Entity    CatalogEntity
}

type EntityRelationPageRequest struct {
	TenantID         string
	AgentKey         string
	Directions       []EntityRelationDirection
	Relations        []string
	NeighborKinds    []string
	Limit            int
	AfterAgentKey    string
	AfterRelation    string
	AfterDirection   EntityRelationDirection
	ExpectedRevision uint64
}

type EntityRelationPage struct {
	TenantID           string
	GraphRevision      uint64
	Relations          []EntityCatalogRelation
	Truncated          bool
	NextAfterAgentKey  string
	NextAfterRelation  string
	NextAfterDirection EntityRelationDirection
}

type EntityCatalogStore interface {
	ListEntities(context.Context, EntityCatalogPageRequest) (*EntityCatalogPage, error)
	CountEntityKinds(context.Context, EntityKindCountRequest) (*EntityKindCountPage, error)
	ListEntityRelations(context.Context, EntityRelationPageRequest) (*EntityRelationPage, error)
}
