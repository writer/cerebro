package applicationworkspace

import (
	"maps"
	"net/url"

	"github.com/writer/cerebro/internal/config"
)

// CanonicalCacheQuery removes the normalized workspace selector from a query
// before it is combined with the selector's canonical value in a cache key.
func CanonicalCacheQuery(values url.Values) string {
	query := maps.Clone(values)
	query.Del("workspace_id")
	return query.Encode()
}

// CanonicalGrants returns stable tenant-qualified authority material for cache
// keys. Authenticated principals have already passed grant validation.
func CanonicalGrants(grants []config.ApplicationWorkspaceGrant) []config.ApplicationWorkspaceGrant {
	normalized, _ := NormalizeGrants(grants)
	return normalized
}
