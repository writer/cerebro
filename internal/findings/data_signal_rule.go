package findings

import (
	"context"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const dataSensitiveAssetRiskRuleID = "data-sensitive-asset-risk"

func newDataSensitiveAssetRiskRule() Rule {
	definition := dataSensitiveAssetRiskDefinition()
	return newEventRule(eventRuleConfig{definition: definition, sourceID: "asset", match: eventKindMatcher("asset.data_sensitivity", "asset.crown_jewel"), build: buildDataSensitiveAssetFinding})
}

func dataSensitiveAssetRiskDefinition() RuleDefinition {
	return RuleDefinition{
		ID:                 dataSensitiveAssetRiskRuleID,
		Name:               "Data Sensitive Asset Risk",
		Description:        "Detect sensitive or crown-jewel data assets with public exposure or privileged access risk.",
		SourceID:           "asset",
		EventKinds:         []string{"asset.data_sensitivity", "asset.crown_jewel"},
		OutputKind:         "finding.data_sensitive_asset_risk",
		Severity:           "HIGH",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"data", "crown-jewel", "exposure"},
		References:         []string{"https://www.cisecurity.org/controls/data-protection", "https://owasp.org/www-project-top-ten/"},
		FalsePositives:     []string{"Data classification is stale, test data is intentionally labeled sensitive, or public exposure is already approved by documented compensating controls."},
		Runbook:            "Validate the data classification, exposure signal, owner, and compensating controls.",
		RequiredAttributes: []string{"resource_id"},
		FingerprintFields:  []string{"asset_urn"},
		ControlRefs: []ports.FindingControlRef{
			{FrameworkName: "SOC 2", ControlID: "CC6.1"},
			{FrameworkName: "ISO 27001:2022", ControlID: "A.5.12"},
		},
		Lifecycle: Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored},
	}
}

func buildDataSensitiveAssetFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attributes := eventAttributes(event)
	if !matchesDataSensitiveAssetRisk(attributes) {
		return nil, nil
	}
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   []string{"has_classification", "tagged_as", "owned_by"},
		CollectAllLinkURNs: true,
		ResourceFallbacks:  []string{attributes["resource_name"], attributes["resource_id"], attributes["resource_urn"]},
	})
	if err != nil {
		return nil, err
	}
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	findingAttributes := map[string]string{
		"action":               "sensitive_asset_risk",
		"asset_criticality":    firstNonEmpty(attributes["asset_criticality"], attributes["business_criticality"], attributes["tier"]),
		"crown_jewel":          strings.TrimSpace(attributes["crown_jewel"]),
		"data_classification":  firstNonEmpty(attributes["data_classification"], attributes["data_sensitivity"], attributes["sensitivity"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"internet_exposed":     strings.TrimSpace(attributes["internet_exposed"]),
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"resource_id":          firstNonEmpty(attributes["resource_id"], attributes["resource_urn"]),
		"resource_label":       projectedContext.ResourceLabel,
		"resource_type":        strings.TrimSpace(attributes["resource_type"]),
		"source_family":        strings.TrimSpace(runtime.GetSourceId()),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
	}
	for key, value := range attributes {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	definition := dataSensitiveAssetRiskDefinition()
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	assetURN := dataAssetURN(projectedContext)
	if strings.TrimSpace(assetURN) == "" {
		trimEmptyAttributes(findingAttributes)
		return nil, nil
	}
	findingAttributes["asset_urn"] = assetURN
	trimEmptyAttributes(findingAttributes)
	fingerprint := hashFindingFingerprint(dataSensitiveAssetRiskRuleID, assetURN)
	return &ports.FindingRecord{ID: fingerprint, Fingerprint: fingerprint, TenantID: strings.TrimSpace(event.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()), RuleID: dataSensitiveAssetRiskRuleID, Title: "Data Sensitive Asset Risk", Severity: "HIGH", Status: findingStatusOpen, Summary: "Sensitive data asset has exposure or privileged access risk", ResourceURNs: projectedContext.ResourceURNs, EventIDs: []string{event.GetId()}, PolicyID: findingAttributes["resource_id"], CheckID: dataSensitiveAssetRiskRuleID, CheckName: "Data Sensitive Asset Risk", ControlRefs: cloneFindingControlRefs(definition.ControlRefs), Attributes: findingAttributes, FirstObservedAt: observedAt, LastObservedAt: observedAt}, nil
}

func dataAssetURN(projection findingProjectionContext) string {
	if urn := strings.TrimSpace(projection.PrimaryActorURN); urn != "" {
		return urn
	}
	for _, entity := range projection.Entities {
		if entity == nil {
			continue
		}
		entityType := strings.TrimSpace(entity.EntityType)
		switch entityType {
		case "data.classification", "asset.tag", "owner":
			continue
		}
		if urn := strings.TrimSpace(entity.URN); urn != "" {
			return urn
		}
	}
	return strings.TrimSpace(projection.PrimaryResourceURN)
}

func matchesDataSensitiveAssetRisk(attributes map[string]string) bool {
	sensitive := findingAttributeBool(attributes, "crown_jewel", "contains_secrets", "contains_pii", "contains_phi") || dataClassificationSensitive(firstNonEmpty(attributes["data_classification"], attributes["data_sensitivity"], attributes["sensitivity"]))
	if !sensitive {
		return false
	}
	return findingAttributeBool(attributes, "public", "internet_exposed", "external_exposure", "privileged_access", "is_admin")
}

func dataClassificationSensitive(value string) bool {
	tokens := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(value)), dataClassificationSeparator)
	switch strings.Join(tokens, "_") {
	case "", "public", "unrestricted", "not_sensitive", "non_sensitive", "no_sensitive_data":
		return false
	}
	for _, token := range tokens {
		switch token {
		case "secret", "secrets", "sensitive", "confidential", "restricted":
			return true
		}
	}
	return false
}

func dataClassificationSeparator(r rune) bool {
	return (r < 'a' || r > 'z') && (r < '0' || r > '9')
}
