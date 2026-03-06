package graph

// EdgeKind represents the type of relationship between nodes
type EdgeKind string

const (
	// Identity -> Identity
	EdgeKindCanAssume EdgeKind = "can_assume"
	EdgeKindMemberOf  EdgeKind = "member_of"

	// Identity -> Resource (permissions)
	EdgeKindCanRead   EdgeKind = "can_read"
	EdgeKindCanWrite  EdgeKind = "can_write"
	EdgeKindCanDelete EdgeKind = "can_delete"
	EdgeKindCanAdmin  EdgeKind = "can_admin"

	// Resource -> Resource
	EdgeKindConnectsTo EdgeKind = "connects_to"

	// Internet -> Resource
	EdgeKindExposedTo EdgeKind = "exposed_to"

	// Asset -> Code
	EdgeKindDeployedFrom EdgeKind = "deployed_from"

	// Business relationships
	EdgeKindOwns         EdgeKind = "owns"
	EdgeKindSubscribedTo EdgeKind = "subscribed_to"
	EdgeKindBilledBy     EdgeKind = "billed_by"
	EdgeKindWorksAt      EdgeKind = "works_at"
	EdgeKindManagedBy    EdgeKind = "managed_by"
	EdgeKindAssignedTo   EdgeKind = "assigned_to"
	EdgeKindRenews       EdgeKind = "renews"
	EdgeKindEscalatedTo  EdgeKind = "escalated_to"
	EdgeKindRefers       EdgeKind = "refers"
)

// EdgeEffect represents whether an edge allows or denies access
type EdgeEffect string

const (
	EdgeEffectAllow EdgeEffect = "allow"
	EdgeEffectDeny  EdgeEffect = "deny"
)

// Edge represents a relationship between nodes
type Edge struct {
	ID         string         `json:"id"`
	Source     string         `json:"source"`
	Target     string         `json:"target"`
	Kind       EdgeKind       `json:"kind"`
	Effect     EdgeEffect     `json:"effect"`
	Priority   int            `json:"priority"` // deny=100, allow=50
	Properties map[string]any `json:"properties,omitempty"`
	Risk       RiskLevel      `json:"risk"`
}

// IsDeny returns true if this edge denies access
func (e *Edge) IsDeny() bool {
	return e.Effect == EdgeEffectDeny
}

// IsCrossAccount returns true if this edge crosses AWS accounts
func (e *Edge) IsCrossAccount() bool {
	if ca, ok := e.Properties["cross_account"].(bool); ok {
		return ca
	}
	return false
}

// IsCrossSystem returns true when an edge links entities from different systems.
func (e *Edge) IsCrossSystem() bool {
	if cs, ok := e.Properties["cross_system"].(bool); ok {
		return cs
	}
	return false
}
