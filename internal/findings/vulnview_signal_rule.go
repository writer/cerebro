package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const vulnViewActionableExternalFindingRuleID = "vulnview-actionable-external-finding"

func newVulnViewActionableExternalFindingRule() Rule {
	definition := RuleDefinition{
		ID:                 vulnViewActionableExternalFindingRuleID,
		Name:               "VulnView Actionable External Finding",
		Description:        "Detect VulnView external attack-surface findings that require AppSec triage.",
		SourceID:           "vulnview",
		EventKinds:         []string{"vulnview.vulnerability", "vulnview.dns_alert"},
		OutputKind:         "finding.vulnview_actionable_external_finding",
		Severity:           "dynamic",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"vulnview", "appsec", "attack-surface"},
		RequiredAttributes: []string{"severity"},
		FingerprintFields:  []string{"template_id", "alert", "target_id", "matched_at"},
	}
	return newEventRule(eventRuleConfig{definition: definition, sourceID: "vulnview", match: matchesVulnViewActionableExternalFinding, build: buildVulnViewActionableExternalFinding})
}

func matchesVulnViewActionableExternalFinding(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher("vulnview.vulnerability")(event) && !eventKindMatcher("vulnview.dns_alert")(event) {
		return false
	}
	severity := strings.ToLower(strings.TrimSpace(event.GetAttributes()["severity"]))
	return severity == "critical" || severity == "high" || severity == "medium"
}

func buildVulnViewActionableExternalFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attrs := eventAttributes(event)
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   []string{"has_evidence", "observed_on", "affected_by"},
		PrimaryEntityType:  "external.asset",
		CollectAllEntities: true,
		ResourceFallbacks:  []string{attrs["target_name"], attrs["target_id"], attrs["host"], attrs["matched_at"], attrs["asset_id"]},
	})
	if err != nil {
		return nil, err
	}
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	action := firstNonEmpty(attrs["name"], attrs["alert"], attrs["template_id"], attrs["external_id"], "VulnView finding")
	target := firstNonEmpty(projectedContext.ResourceLabel, attrs["target_name"], attrs["target_id"], attrs["host"], attrs["matched_at"], "unknown target")
	findingAttributes := map[string]string{
		"action":               action,
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"target":               target,
	}
	for key, value := range attrs {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	definition := RuleDefinition{ID: vulnViewActionableExternalFindingRuleID, Name: "VulnView Actionable External Finding", SourceID: "vulnview", OutputKind: "finding.vulnview_actionable_external_finding", Severity: "dynamic", Status: findingStatusOpen}
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	fingerprint := hashFindingFingerprint(
		vulnViewActionableExternalFindingRuleID,
		strings.TrimSpace(event.GetTenantId()),
		firstNonEmpty(attrs["template_id"], attrs["alert"], attrs["external_id"]),
		firstNonEmpty(attrs["target_id"], attrs["host"], attrs["asset_id"], projectedContext.PrimaryResourceURN),
		attrs["matched_at"],
	)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        strings.TrimSpace(event.GetTenantId()),
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          vulnViewActionableExternalFindingRuleID,
		Title:           "VulnView Actionable External Finding",
		Severity:        normalizeFindingSeverity(attrs["severity"]),
		Status:          findingStatusOpen,
		Summary:         fmt.Sprintf("VulnView reported %s on %s", action, target),
		ResourceURNs:    projectedContext.ResourceURNs,
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		PolicyID:        firstNonEmpty(attrs["template_id"], attrs["alert"], attrs["external_id"]),
		PolicyName:      action,
		CheckID:         vulnViewActionableExternalFindingRuleID,
		CheckName:       "VulnView Actionable External Finding",
		Attributes:      findingAttributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}
