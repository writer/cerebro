package oktaasset

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// CanonicalThreatInsightMaterial returns the payload and immutable event ID
// for the complete durable material of one threat configuration observation.
func CanonicalThreatInsightMaterial(
	domain string,
	action string,
	zones []string,
	occurredAt time.Time,
) ([]byte, string, error) {
	canonicalZones := append([]string{}, zones...)
	sort.Strings(canonicalZones)
	payload, err := json.Marshal(map[string]any{
		"domain":        domain,
		"action":        action,
		"exclude_zones": canonicalZones,
	})
	if err != nil {
		return nil, "", err
	}
	material, err := json.Marshal(struct {
		TenantID            string          `json:"tenant_id"`
		SourceID            string          `json:"source_id"`
		Kind                string          `json:"kind"`
		OccurredAtUnixMilli int64           `json:"occurred_at_unix_ms"`
		SchemaRef           string          `json:"schema_ref"`
		Payload             json.RawMessage `json:"payload"`
		Action              string          `json:"attribute_action"`
		Domain              string          `json:"attribute_domain"`
		ExcludeZoneCount    int             `json:"attribute_exclude_zone_count"`
		Family              string          `json:"attribute_family"`
		ResourceID          string          `json:"attribute_resource_id"`
		ResourceType        string          `json:"attribute_resource_type"`
	}{
		TenantID:            domain,
		SourceID:            "okta",
		Kind:                "okta.threat_insight",
		OccurredAtUnixMilli: occurredAt.UnixMilli(),
		SchemaRef:           "okta/threat_insight/v1",
		Payload:             payload,
		Action:              action,
		Domain:              domain,
		ExcludeZoneCount:    len(canonicalZones),
		Family:              "threat_insight",
		ResourceID:          "threat_insight_config",
		ResourceType:        "ThreatInsightConfiguration",
	})
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(material)
	return payload, fmt.Sprintf("okta-threat-insight-sha256-%x", digest), nil
}
