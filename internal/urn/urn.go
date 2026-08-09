package urn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// Prefix identifies URNs owned by Cerebro's canonical namespace.
const Prefix = "urn:cerebro:"

// URN is the parsed representation of a canonical Cerebro resource name.
// Parts excludes the fixed urn:cerebro prefix, tenant, and kind segments.
type URN struct {
	Raw      string
	TenantID string
	Kind     string
	Parts    []string
}

// String returns the validated URN without decoding or reformatting segments.
func (u URN) String() string {
	return u.Raw
}

// Parse validates raw as a Cerebro URN and separates its authority fields.
// It preserves encoded path segments exactly; callers decode provider values
// only when their domain contract explicitly requires it.
func Parse(raw string) (URN, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return URN{}, fmt.Errorf("urn is required")
	}
	if !strings.HasPrefix(value, Prefix) {
		return URN{}, fmt.Errorf("invalid cerebro urn %q", value)
	}
	parts := strings.Split(value, ":")
	if len(parts) > 3 && parts[3] == "runtime" && (len(parts) < 7 || parts[5] == "") {
		return URN{}, fmt.Errorf("invalid cerebro urn %q", value)
	}
	if len(parts) < 4 || parts[0] != "urn" || parts[1] != "cerebro" {
		return URN{}, fmt.Errorf("invalid cerebro urn %q", value)
	}
	if parts[len(parts)-1] == "" {
		return URN{}, fmt.Errorf("invalid cerebro urn %q", value)
	}
	for i, part := range parts[2:] {
		if strings.TrimSpace(part) != part || (i < 3 && part == "") {
			return URN{}, fmt.Errorf("invalid cerebro urn %q", value)
		}
	}
	parsed := URN{
		Raw:      value,
		TenantID: parts[2],
		Kind:     parts[3],
		Parts:    append([]string(nil), parts[4:]...),
	}
	return parsed, nil
}

// Mint builds and validates a tenant-scoped Cerebro URN. Empty optional parts
// are omitted. Callers must EncodeSegment for provider-controlled values before
// passing them to Mint so delimiters cannot change the URN structure.
func Mint(tenantID string, kind string, parts ...string) (string, error) {
	tenant := strings.TrimSpace(tenantID)
	entityKind := strings.TrimSpace(kind)
	if tenant == "" {
		return "", fmt.Errorf("tenant is required")
	}
	if entityKind == "" {
		return "", fmt.Errorf("urn kind is required")
	}
	values := []string{"urn", "cerebro", tenant, entityKind}
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	raw := strings.Join(values, ":")
	if _, err := Parse(raw); err != nil {
		return "", err
	}
	return raw, nil
}

// TenantID returns the tenant authority in raw, or an empty string when raw is
// not a valid Cerebro URN.
func TenantID(raw string) string {
	parsed, err := Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.TenantID
}

// SameTenant reports whether raw is valid and belongs to the non-empty tenant.
func SameTenant(raw string, tenantID string) bool {
	tenant := strings.TrimSpace(tenantID)
	return tenant != "" && TenantID(raw) == tenant
}

// EncodeSegment escapes provider-controlled identifiers for Cerebro's colon-delimited URN parts.
func EncodeSegment(value string) string {
	escaped := url.PathEscape(strings.TrimSpace(value))
	return strings.ReplaceAll(escaped, ":", "%3A")
}

// StableExternalID returns a deterministic, opaque identifier derived from a
// provider value. Only the first 128 digest bits are exposed. If value is empty,
// emptyFallback is returned unchanged so the caller controls missing-ID policy.
func StableExternalID(value string, emptyFallback string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return emptyFallback
	}
	sum := sha256.Sum256([]byte(normalized))
	return "id-" + hex.EncodeToString(sum[:16])
}
