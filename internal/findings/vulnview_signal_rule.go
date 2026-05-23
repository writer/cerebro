package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

const vulnViewActionableExternalFindingRuleID = "vulnview-actionable-external-finding"

type vulnViewActionableExternalFindingRule struct {
	Rule
	definition RuleDefinition
}

func newVulnViewActionableExternalFindingRule() Rule {
	definition := vulnViewActionableExternalFindingDefinition()
	return &vulnViewActionableExternalFindingRule{
		Rule:       newEventRule(eventRuleConfig{definition: definition, sourceID: "vulnview", match: matchesVulnViewActionableExternalFinding, build: buildVulnViewActionableExternalFinding}),
		definition: definition,
	}
}

func vulnViewActionableExternalFindingDefinition() RuleDefinition {
	return RuleDefinition{
		ID:                 vulnViewActionableExternalFindingRuleID,
		Name:               "VulnView Actionable External Finding",
		Description:        "Detect open VulnView external attack-surface findings that require AppSec triage.",
		SourceID:           "vulnview",
		EventKinds:         []string{"vulnview.vulnerability", "vulnview.dns_alert"},
		OutputKind:         "finding.vulnview_actionable_external_finding",
		Severity:           "dynamic",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"vulnview", "appsec", "attack-surface"},
		References:         []string{"https://owasp.org/www-project-web-security-testing-guide/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
		FalsePositives:     []string{"Finding is a duplicate, asset is intentionally exposed with compensating controls, or scanner severity was manually downgraded after validation."},
		Runbook:            "Validate exploitability and asset ownership, link duplicate external findings, patch or mitigate the exposed service, and document accepted risk.",
		RequiredAttributes: []string{"severity", "vulnview_finding_state"},
		FingerprintFields:  []string{"asset_urn", "template_id"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC7.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.8.8"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
	}
}

var vulnViewActionableExternalFindingKindMatcher = eventKindMatcher("vulnview.vulnerability", "vulnview.dns_alert")

func (r *vulnViewActionableExternalFindingRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *vulnViewActionableExternalFindingRule) OpenAnchor(attributes map[string]string) string {
	return vulnViewActionableExternalFindingAnchor(
		vulnViewActionableExternalFindingAssetURNFromAttributes(attributes),
		vulnViewActionableExternalFindingTemplateID(attributes),
	)
}

func (r *vulnViewActionableExternalFindingRule) CloseOnEvent(event Event) (string, bool) {
	if !vulnViewActionableExternalFindingKindMatcher(event) {
		return "", false
	}
	attrs := eventAttributes(event)
	anchor := vulnViewActionableExternalFindingAnchorForEvent(event)
	if anchor == "" {
		return "", false
	}
	if !vulnViewActionableExternalFindingSourceOpen(attrs) {
		return anchor, true
	}
	if severity := strings.TrimSpace(attrs["severity"]); severity != "" && !vulnViewActionableExternalFindingSeverityActionable(severity) {
		return anchor, true
	}
	return "", false
}

func matchesVulnViewActionableExternalFinding(event *cerebrov1.EventEnvelope) bool {
	if !vulnViewActionableExternalFindingKindMatcher(event) {
		return false
	}
	attrs := eventAttributes(event)
	if !vulnViewActionableExternalFindingSourceOpen(attrs) {
		return false
	}
	return vulnViewActionableExternalFindingSeverityActionable(attrs["severity"])
}

func vulnViewActionableExternalFindingSeverityActionable(severity string) bool {
	severity = strings.ToLower(strings.TrimSpace(severity))
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
	templateID := vulnViewActionableExternalFindingTemplateID(attrs)
	assetURN := firstNonEmpty(
		vulnViewActionableExternalFindingAssetURNFromAttributes(attrs),
		vulnViewActionableExternalFindingAssetURNFromProjection(projectedContext),
	)
	if templateID == "" || assetURN == "" {
		return nil, nil
	}
	action := firstNonEmpty(attrs["name"], attrs["alert"], templateID, attrs["external_id"], "VulnView finding")
	target := firstNonEmpty(projectedContext.ResourceLabel, attrs["target_name"], attrs["target_id"], attrs["host"], attrs["matched_at"], "unknown target")
	findingAttributes := map[string]string{
		"asset_urn":            assetURN,
		"action":               action,
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"primary_resource_urn": assetURN,
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"target":               target,
		"template_id":          templateID,
	}
	for key, value := range attrs {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	definition := vulnViewActionableExternalFindingDefinition()
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	fingerprint := hashFindingFingerprint(
		vulnViewActionableExternalFindingRuleID,
		assetURN,
		templateID,
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
		PolicyID:        templateID,
		PolicyName:      action,
		CheckID:         vulnViewActionableExternalFindingRuleID,
		CheckName:       "VulnView Actionable External Finding",
		ControlRefs:     cloneFindingControlRefs(definition.ControlRefs),
		Attributes:      findingAttributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func vulnViewActionableExternalFindingTemplateID(attributes map[string]string) string {
	return firstNonEmpty(attributes["template_id"], attributes["vulnerability_id"], attributes["alert"], attributes["external_id"])
}

func vulnViewActionableExternalFindingAnchor(assetURN string, templateID string) string {
	assetURN = strings.TrimSpace(assetURN)
	templateID = strings.TrimSpace(templateID)
	if assetURN == "" || templateID == "" {
		return ""
	}
	return assetURN + "|" + templateID
}

func vulnViewActionableExternalFindingAnchorForEvent(event Event) string {
	attrs := eventAttributes(event)
	templateID := vulnViewActionableExternalFindingTemplateID(attrs)
	if templateID == "" {
		return ""
	}
	return vulnViewActionableExternalFindingAnchor(vulnViewActionableExternalFindingAssetURNForEvent(event), templateID)
}

func vulnViewActionableExternalFindingAssetURNForEvent(event Event) string {
	attrs := eventAttributes(event)
	if assetURN := vulnViewActionableExternalFindingAssetURNFromAttributes(attrs); assetURN != "" {
		return assetURN
	}
	entities, _, err := sourceprojection.ProjectEvent(event)
	if err != nil {
		return ""
	}
	for _, entity := range entities {
		if entity == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(entity.EntityType), "external.asset") {
			return strings.TrimSpace(entity.URN)
		}
	}
	return ""
}

func vulnViewActionableExternalFindingAssetURNFromAttributes(attributes map[string]string) string {
	if assetURN := strings.TrimSpace(attributes["asset_urn"]); assetURN != "" {
		return assetURN
	}
	if primaryURN := strings.TrimSpace(attributes["primary_resource_urn"]); strings.Contains(primaryURN, ":external_asset:") {
		return primaryURN
	}
	return ""
}

func vulnViewActionableExternalFindingAssetURNFromProjection(projectedContext findingProjectionContext) string {
	for _, entity := range projectedContext.Entities {
		if entity == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(entity.EntityType), "external.asset") {
			return strings.TrimSpace(entity.URN)
		}
	}
	if primaryURN := strings.TrimSpace(projectedContext.PrimaryResourceURN); strings.Contains(primaryURN, ":external_asset:") {
		return primaryURN
	}
	return ""
}

func vulnViewActionableExternalFindingSourceOpen(attributes map[string]string) bool {
	state := strings.ToLower(strings.TrimSpace(vulnViewActionableExternalFindingSourceState(attributes)))
	state = strings.ReplaceAll(state, "-", "_")
	state = strings.ReplaceAll(state, " ", "_")
	switch state {
	case "open", "opened", "active", "detected", "new", "unresolved", "reopened":
		return true
	case "":
		return false
	case "closed", "resolved", "fixed", "remediated", "false_positive", "accepted_risk", "ignored", "suppressed":
		return false
	default:
		return true
	}
}

func vulnViewActionableExternalFindingSourceState(attributes map[string]string) string {
	return firstNonEmpty(
		attributes["vulnview_finding_state"],
		attributes["vulnview_status"],
		attributes["vulnview_state"],
		attributes["vulnview_finding_status"],
		attributes["vulnview_remediation_state"],
		attributes["vulnview_lifecycle_state"],
	)
}
