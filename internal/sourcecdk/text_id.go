package sourcecdk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// StableID joins non-empty, trimmed parts with ":" into a stable composite
// identifier, skipping blank parts rather than embedding empty segments.
func StableID(parts ...string) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ":")
}

// NormalizeID replaces characters that are unsafe inside a URN or
// dash-joined identifier segment (whitespace, "/", ":") with "-", and
// returns "unknown" for a blank value so an identifier segment is never
// empty.
func NormalizeID(value string) string {
	if normalized := strings.TrimSpace(value); normalized != "" {
		return strings.NewReplacer(" ", "-", "/", "-", ":", "-", "\n", "-", "\t", "-").Replace(normalized)
	}
	return "unknown"
}

// FirstNonEmpty returns the first trimmed, non-empty value among values.
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// TrimEmptyAttributes deletes blank-valued entries from attrs and trims the
// remaining values in place, so an event attribute map never carries
// whitespace-only or empty strings.
func TrimEmptyAttributes(attrs map[string]string) {
	for key, value := range attrs {
		if strings.TrimSpace(value) == "" {
			delete(attrs, key)
			continue
		}
		attrs[key] = strings.TrimSpace(value)
	}
}

// ScopeHash returns a short (12 hex character) stable digest of parts
// joined with a NUL separator, suitable for scoping an identifier to a
// specific provider configuration (e.g. base URL, client ID, auth scope)
// without embedding the raw values in the identifier.
func ScopeHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:12]
}

// WrapFamilyErr wraps a non-nil family error with "<source> <family>: %w"
// context, passing nil through unchanged.
func WrapFamilyErr(source string, family string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s: %w", source, family, err)
}
