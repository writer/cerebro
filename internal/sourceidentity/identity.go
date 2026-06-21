package sourceidentity

import "github.com/writer/cerebro/internal/sourcecdk"

// HashedExternalIDKey returns a stable graph/event-safe key for provider IDs
// whose native values may contain URI or event-id delimiters.
func HashedExternalIDKey(value string, emptyFallback string) string {
	return sourcecdk.StableExternalID(value, emptyFallback)
}
