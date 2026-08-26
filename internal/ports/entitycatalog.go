package ports

import "context"

type EntityCatalogFilter struct {
	TenantID               string
	ApplicationWorkspaceID string
	SourceID               string
	RuntimeIDs             []string
	ExactAgentKey          string
	IncludeKinds           []string
	IncludeKindPrefixes    []string
	ExcludeKinds           []string
	ExcludeKindPrefixes    []string
	Query                  string
	QueryAttributes        bool
	ExpectedRevision       uint64
	RelationCounts         *EntityRelationCountFilter
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

type PersonAccessPathRequest struct {
	TenantID         string
	PersonURN        string
	PersonQuery      string
	Limit            int
	Depth            int
	ExpectedRevision uint64
}

type PersonAccessPath struct {
	Person        CatalogEntity
	Identity      CatalogEntity
	Principal     CatalogEntity
	AccessTarget  CatalogEntity
	RelationChain []string
}

type PersonAccessPathResult struct {
	TenantID      string
	GraphRevision uint64
	Paths         []PersonAccessPath
	Truncated     bool
}

type PersonAccessPathStore interface {
	ListPersonAccessPaths(context.Context, PersonAccessPathRequest) (*PersonAccessPathResult, error)
}

type EffectiveAccessPathRequest struct {
	TenantID         string
	IdentityURN      string
	IdentityQuery    string
	ApplicationURN   string
	CapabilityURN    string
	CapabilityID     string
	Limit            int
	ExpectedRevision uint64
}

type EffectiveAccessPathEdge struct {
	From           CatalogEntity
	Relation       string
	To             CatalogEntity
	SourceID       string
	RuntimeID      string
	AttributesJSON string
}

type EffectiveAccessPath struct {
	Identity              CatalogEntity
	Principal             CatalogEntity
	Mediator              *CatalogEntity
	AccessTarget          CatalogEntity
	Entitlement           CatalogEntity
	Capability            CatalogEntity
	AssignmentKind        string
	IdentityRelationChain []string
	IdentityEdges         []EffectiveAccessPathEdge
	RelationChain         []string
	Edges                 []EffectiveAccessPathEdge
}

type EffectiveAccessPathResult struct {
	TenantID      string
	GraphRevision uint64
	Paths         []EffectiveAccessPath
	Truncated     bool
}

type EffectiveAccessPathStore interface {
	ListEffectiveAccessPaths(context.Context, EffectiveAccessPathRequest) (*EffectiveAccessPathResult, error)
}

type CloudAttackPathNode struct {
	URN        string
	EntityType string
	Label      string
}

type CloudAttackPathEdge struct {
	From                CloudAttackPathNode
	Relation            string
	To                  CloudAttackPathNode
	Direction           string
	SourceID            string
	SourceRuntimeID     string
	AssertionRuntimeIDs []string
	AttributesJSON      string
}

type CloudAttackPathOwnership struct {
	Owner CloudAttackPathNode
	Edge  CloudAttackPathEdge
}

type CloudAttackPath struct {
	PublicPrincipal       CloudAttackPathNode
	ExposedResource       CloudAttackPathNode
	CloudAccount          CloudAttackPathNode
	Principal             CloudAttackPathNode
	Permission            CloudAttackPathNode
	Ownerships            []CloudAttackPathOwnership
	ReachRelation         string
	AccessRelation        string
	RelationChain         []string
	ExposureEdge          CloudAttackPathEdge
	ResourceAccountEdge   CloudAttackPathEdge
	TraversalEdges        []CloudAttackPathEdge
	PrivilegeEdge         CloudAttackPathEdge
	PermissionAccountEdge CloudAttackPathEdge
}

type CloudAttackPathCounts struct {
	Paths                uint64
	ExposedResources     uint64
	PrivilegedPrincipals uint64
	CloudAccounts        uint64
}

type CloudAttackPathRequest struct {
	TenantID              string
	AccountID             string
	RuntimeID             string
	RequireAssertionProof bool
	Limit                 int
	Depth                 int
	ExpectedRevision      uint64
}

type CloudAttackPathResult struct {
	TenantID      string
	GraphRevision uint64
	Counts        CloudAttackPathCounts
	Paths         []CloudAttackPath
	Truncated     bool
}

type CloudAttackPathStore interface {
	ListCloudAttackPaths(context.Context, CloudAttackPathRequest) (*CloudAttackPathResult, error)
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
