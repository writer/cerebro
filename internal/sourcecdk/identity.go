package sourcecdk

import (
	"fmt"
	"strings"

	cerebrourn "github.com/writer/cerebro/internal/urn"
)

// StableExternalID returns a deterministic, delimiter-safe key for provider IDs.
func StableExternalID(value string, emptyFallback string) string {
	return cerebrourn.StableExternalID(value, emptyFallback)
}

// URNFor builds and validates a tenant-scoped source entity URN.
func URNFor(tenant, kind, providerID string) (URN, error) {
	tenant = strings.TrimSpace(tenant)
	kind = strings.TrimSpace(kind)
	providerID = strings.TrimSpace(providerID)
	if tenant == "" {
		return "", fmt.Errorf("tenant is required")
	}
	if kind == "" {
		return "", fmt.Errorf("urn kind is required")
	}
	if providerID == "" {
		return "", fmt.Errorf("provider id is required")
	}
	raw, err := cerebrourn.Mint(tenant, kind, providerID)
	if err != nil {
		return "", err
	}
	return URN(raw), nil
}

// URNForEscaped builds a URN after hashing provider-controlled parts that may
// contain delimiters, display names, slashes, or other collision-prone text.
func URNForEscaped(tenant, kind string, parts ...string) (URN, error) {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		normalized = append(normalized, part)
	}
	if len(normalized) == 0 {
		return "", fmt.Errorf("provider id parts are required")
	}
	return URNFor(tenant, kind, StableExternalID(strings.Join(normalized, "\x00"), "missing"))
}

// EventID returns a deterministic event ID key from stable source/provider parts.
func EventID(parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		normalized = append(normalized, part)
	}
	return StableExternalID(strings.Join(normalized, "\x00"), "id-missing")
}
