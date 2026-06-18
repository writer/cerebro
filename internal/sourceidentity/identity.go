package sourceidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// HashedExternalIDKey returns a stable graph/event-safe key for provider IDs
// whose native values may contain URI or event-id delimiters.
func HashedExternalIDKey(value string, emptyFallback string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return emptyFallback
	}
	sum := sha256.Sum256([]byte(normalized))
	return "id-" + hex.EncodeToString(sum[:16])
}
