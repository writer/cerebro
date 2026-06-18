package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	cloudflareZoneProtectionPausedRuleID    = "cloudflare-zone-protection-paused"
	cloudflareZoneProtectionPausedTitle     = "Cloudflare Zone Edge Protection Paused"
	cloudflareZoneProtectionPausedSeverity  = "HIGH"
	cloudflareZoneProtectionPausedStatus    = "open"
	cloudflareZoneProtectionPausedCheckID   = "cloudflare-zone-protection-paused-current"
	cloudflareZoneProtectionPausedCheckName = "Cloudflare Zone Edge Protection Paused (current state)"
)

var cloudflareZoneProtectionPausedControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.6"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.20"},
}

type cloudflareZoneProtectionPausedRule struct {
	Rule
	definition RuleDefinition
}

var cloudflareZoneProtectionPausedDefinition = RuleDefinition{
	ID:                 cloudflareZoneProtectionPausedRuleID,
	Name:               cloudflareZoneProtectionPausedTitle,
	Description:        "Detect Cloudflare zones whose edge protection is currently paused, bypassing WAF, DDoS, and TLS controls.",
	SourceID:           "cloudflare",
	EventKinds:         []string{"cloudflare.zone"},
	OutputKind:         "finding.cloudflare_zone_protection_paused",
	Severity:           cloudflareZoneProtectionPausedSeverity,
	Status:             cloudflareZoneProtectionPausedStatus,
	Maturity:           "test",
	Tags:               []string{"cloudflare", "edge", "zone", "waf", "defense-evasion"},
	References:         []string{"https://developers.cloudflare.com/fundamentals/setup/manage-domains/pause-cloudflare/"},
	FalsePositives:     []string{"Temporary, approved zone pause during a maintenance or migration change window."},
	Runbook:            "Confirm whether the zone pause is an approved change; if not, unpause the zone to restore edge security controls and review who paused it.",
	RequiredAttributes: []string{"zone_id"},
	FingerprintFields:  []string{"cloudflare_zone_urn"},
	ControlRefs:        cloudflareZoneProtectionPausedControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
}

var cloudflareZoneProtectionPausedKindMatcher = eventKindMatcher(cloudflareZoneProtectionPausedDefinition.EventKinds...)

func newCloudflareZoneProtectionPausedRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: cloudflareZoneProtectionPausedDefinition,
		match:      matchesCloudflareZoneProtectionPaused,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return cloudflareZoneProtectionPausedFinding(event, runtime.GetId())
		},
	})
	return &cloudflareZoneProtectionPausedRule{
		Rule:       rule,
		definition: cloudflareZoneProtectionPausedDefinition,
	}
}

func (r *cloudflareZoneProtectionPausedRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *cloudflareZoneProtectionPausedRule) OpenAnchor(attributes map[string]string) string {
	return cloudflareZoneProtectionPausedAnchor(attributes)
}

func (r *cloudflareZoneProtectionPausedRule) CloseOnEvent(event Event) (string, bool) {
	if !cloudflareZoneProtectionPausedKindMatcher(event) || !hasRequiredAttributes(event, cloudflareZoneProtectionPausedDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !cloudflareZoneProtectionRestored(attributes) {
		return "", false
	}
	zoneURN := cloudflareZoneProtectionPausedURN(event.GetTenantId(), attributes["zone_id"])
	anchor := cloudflareZoneProtectionPausedAnchor(map[string]string{"cloudflare_zone_urn": zoneURN})
	return anchor, anchor != ""
}

func matchesCloudflareZoneProtectionPaused(event *cerebrov1.EventEnvelope) bool {
	if !cloudflareZoneProtectionPausedKindMatcher(event) || !hasRequiredAttributes(event, cloudflareZoneProtectionPausedDefinition.RequiredAttributes...) {
		return false
	}
	return cloudflareZoneProtectionIsPaused(eventAttributes(event))
}

func cloudflareZoneProtectionPausedFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	zoneID := strings.TrimSpace(attrs["zone_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	zoneURN := cloudflareZoneProtectionPausedURN(tenantID, zoneID)
	if zoneURN == "" {
		return nil, nil
	}
	zoneName := firstNonEmpty(attrs["name"], attrs["zone_name"], zoneID)
	attributes := map[string]string{
		"cloudflare_zone_urn":  zoneURN,
		"zone_id":              zoneID,
		"zone_name":            zoneName,
		"account_id":           strings.TrimSpace(attrs["account_id"]),
		"zone_status":          strings.TrimSpace(attrs["status"]),
		"paused":               strings.TrimSpace(attrs["paused"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": zoneURN,
	}
	for key, value := range cloudflareZoneProtectionPausedDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(cloudflareZoneProtectionPausedRuleID, zoneURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          cloudflareZoneProtectionPausedRuleID,
		Title:           cloudflareZoneProtectionPausedTitle,
		Severity:        cloudflareZoneProtectionPausedSeverity,
		Status:          cloudflareZoneProtectionPausedStatus,
		Summary:         cloudflareZoneProtectionPausedSummary(zoneName),
		ResourceURNs:    []string{zoneURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         cloudflareZoneProtectionPausedCheckID,
		CheckName:       cloudflareZoneProtectionPausedCheckName,
		ControlRefs:     cloneFindingControlRefs(cloudflareZoneProtectionPausedDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func cloudflareZoneProtectionIsPaused(attributes map[string]string) bool {
	paused, ok := parseOptionalBoolAttribute(attributes, "paused")
	return ok && paused
}

func cloudflareZoneProtectionRestored(attributes map[string]string) bool {
	paused, ok := parseOptionalBoolAttribute(attributes, "paused")
	return ok && !paused
}

func cloudflareZoneProtectionPausedURN(tenantID string, zoneID string) string {
	tenantID = strings.TrimSpace(tenantID)
	zoneID = strings.TrimSpace(zoneID)
	if tenantID == "" || zoneID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:cloudflare_zone:%s", tenantID, zoneID)
}

func cloudflareZoneProtectionPausedAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"cloudflare_zone_urn": strings.TrimSpace(attributes["cloudflare_zone_urn"]),
	}, "cloudflare_zone_urn")
}

func cloudflareZoneProtectionPausedSummary(zoneName string) string {
	return fmt.Sprintf("Cloudflare zone %s has edge protection paused", firstNonEmpty(zoneName, "unknown zone"))
}
