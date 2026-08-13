package oktaasset

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/primitives"
)

// ThreatInsightOccurredAt returns the first positive provider timestamp,
// normalized to the append log's millisecond precision.
func ThreatInsightOccurredAt(lastUpdated string, created string) (time.Time, error) {
	for _, value := range []*time.Time{ParseTime(lastUpdated), ParseTime(created)} {
		if value != nil && !value.IsZero() {
			normalized := time.UnixMilli(value.UnixMilli()).UTC()
			if normalized.UnixMilli() > 0 {
				return normalized, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("okta threat insight requires a positive created or lastUpdated timestamp")
}

// ThreatInsightEvent builds one immutable threat configuration observation.
func ThreatInsightEvent(domain string, action string, zones []string, lastUpdated string, created string) (*primitives.Event, error) {
	occurredAt, err := ThreatInsightOccurredAt(lastUpdated, created)
	if err != nil {
		return nil, err
	}
	payload, eventID, err := CanonicalThreatInsightMaterial(domain, action, zones, occurredAt)
	if err != nil {
		return nil, fmt.Errorf("marshal okta threat insight material: %w", err)
	}
	return &primitives.Event{
		Id:         eventID,
		TenantId:   domain,
		SourceId:   "okta",
		Kind:       "okta.threat_insight",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "okta/threat_insight/v1",
		Payload:    payload,
		Attributes: map[string]string{
			"action":             action,
			"domain":             domain,
			"exclude_zone_count": fmt.Sprintf("%d", len(zones)),
			"family":             "threat_insight",
			"resource_id":        "threat_insight_config",
			"resource_type":      "ThreatInsightConfiguration",
		},
	}, nil
}

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
