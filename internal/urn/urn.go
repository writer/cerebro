package urn

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const Prefix = "urn:cerebro:"

type URN struct {
	Raw      string
	TenantID string
	Kind     string
	Parts    []string
}

func (u URN) String() string {
	return u.Raw
}

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

func TenantID(raw string) string {
	parsed, err := Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.TenantID
}

func SameTenant(raw string, tenantID string) bool {
	tenant := strings.TrimSpace(tenantID)
	return tenant != "" && TenantID(raw) == tenant
}

// EncodeSegment escapes provider-controlled identifiers for Cerebro's colon-delimited URN parts.
func EncodeSegment(value string) string {
	escaped := url.PathEscape(strings.TrimSpace(value))
	return strings.ReplaceAll(escaped, ":", "%3A")
}

func StableExternalID(value string, emptyFallback string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return emptyFallback
	}
	sum := sha256.Sum256([]byte(normalized))
	return "id-" + hex.EncodeToString(sum[:16])
}
