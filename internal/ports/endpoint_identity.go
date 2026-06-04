package ports

import (
	"context"
	"time"
)

// EndpointIdentityAlias is one observed identifier for a canonical endpoint.
// Implementations should treat hostname aliases as weaker evidence than device
// IDs, hardware UUIDs, serial numbers, and provider-native IDs.
type EndpointIdentityAlias struct {
	TenantID          string
	CanonicalDeviceID string
	AliasType         string
	AliasValue        string
	SourceID          string
	Confidence        float64
	ObservedAt        time.Time
	Attributes        map[string]string
}

// EndpointIdentityResolveRequest asks for the canonical endpoint associated
// with any of the supplied aliases.
type EndpointIdentityResolveRequest struct {
	TenantID string
	Aliases  []EndpointIdentityAlias
	Limit    uint32
}

// EndpointIdentityResolution returns all candidate canonical endpoint IDs
// matched by the supplied aliases, ordered by confidence and recency.
type EndpointIdentityResolution struct {
	TenantID           string
	CanonicalDeviceID  string
	MatchedAliases     []EndpointIdentityAlias
	CandidateDeviceIDs []string
	Ambiguous          bool
}

// EndpointIdentityStore persists and resolves endpoint identity aliases.
type EndpointIdentityStore interface {
	UpsertEndpointIdentityAliases(context.Context, []EndpointIdentityAlias) error
	ResolveEndpointIdentity(context.Context, EndpointIdentityResolveRequest) (EndpointIdentityResolution, error)
}
