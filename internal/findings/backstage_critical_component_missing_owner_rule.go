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
	backstageCriticalComponentMissingOwnerRuleID    = "backstage-critical-component-missing-owner"
	backstageCriticalComponentMissingOwnerTitle     = "Backstage Critical Component Missing Accountable Owner"
	backstageCriticalComponentMissingOwnerSeverity  = "HIGH"
	backstageCriticalComponentMissingOwnerCheckID   = "backstage-critical-component-missing-owner-current"
	backstageCriticalComponentMissingOwnerCheckName = "Backstage Critical Component Missing Accountable Owner (current state)"
)

var backstageCriticalComponentMissingOwnerControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC1.4"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.2"},
}

var backstageCriticalComponentTiers = map[string]struct{}{
	"critical":    {},
	"crown_jewel": {},
	"crown-jewel": {},
	"tier0":       {},
	"tier-0":      {},
	"tier_0":      {},
	"p0":          {},
	"high":        {},
	"highest":     {},
	"gold":        {},
}

var backstageUnaccountableOwners = map[string]struct{}{
	"unknown":    {},
	"unowned":    {},
	"none":       {},
	"n/a":        {},
	"na":         {},
	"tbd":        {},
	"unassigned": {},
	"nobody":     {},
}

var backstageDecommissionedLifecycles = map[string]struct{}{
	"deprecated":     {},
	"decommissioned": {},
	"retired":        {},
	"archived":       {},
	"deleted":        {},
	"removed":        {},
	"end-of-life":    {},
	"eol":            {},
}

type backstageCriticalComponentMissingOwnerRule struct {
	Rule
	definition RuleDefinition
}

var backstageCriticalComponentMissingOwnerDefinition = RuleDefinition{
	ID:                 backstageCriticalComponentMissingOwnerRuleID,
	Name:               backstageCriticalComponentMissingOwnerTitle,
	Description:        "Detect business-critical Backstage components that have no accountable owner, leaving a high-importance service without a responsible team to govern its security posture, on-call response, or remediation.",
	SourceID:           "backstage",
	EventKinds:         []string{"backstage.component"},
	OutputKind:         "finding.backstage_critical_component_missing_owner",
	Severity:           backstageCriticalComponentMissingOwnerSeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"backstage", "ownership", "accountability", "service-catalog", "crown-jewel"},
	References:         []string{"https://backstage.io/docs/features/software-catalog/system-model"},
	FalsePositives:     []string{"Critical components intentionally owned by a shared platform group that is tracked outside the Backstage ownership model."},
	Runbook:            "Identify the unowned critical Backstage component and assign an accountable owning team in the catalog, or downgrade its criticality if it is no longer business-critical.",
	RequiredAttributes: []string{"name"},
	FingerprintFields:  []string{"backstage_component_urn"},
	ControlRefs:        backstageCriticalComponentMissingOwnerControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var backstageCriticalComponentMissingOwnerKindMatcher = eventKindMatcher(backstageCriticalComponentMissingOwnerDefinition.EventKinds...)

func newBackstageCriticalComponentMissingOwnerRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: backstageCriticalComponentMissingOwnerDefinition,
		match:      matchesBackstageCriticalComponentMissingOwner,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return backstageCriticalComponentMissingOwnerFinding(event, runtime.GetId())
		},
	})
	return &backstageCriticalComponentMissingOwnerRule{
		Rule:       rule,
		definition: backstageCriticalComponentMissingOwnerDefinition,
	}
}

func (r *backstageCriticalComponentMissingOwnerRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *backstageCriticalComponentMissingOwnerRule) OpenAnchor(attributes map[string]string) string {
	return backstageCriticalComponentMissingOwnerAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later snapshot of the same
// component shows an accountable owner (remediation), is no longer critical
// (downgraded), or is decommissioned (no longer an active service), so resolved
// components do not leave stale open findings.
func (r *backstageCriticalComponentMissingOwnerRule) CloseOnEvent(event Event) (string, bool) {
	if !backstageCriticalComponentMissingOwnerKindMatcher(event) || !hasRequiredAttributes(event, backstageCriticalComponentMissingOwnerDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if backstageComponentIsCritical(attributes["criticality"]) &&
		!backstageComponentHasAccountableOwner(attributes) &&
		!backstageComponentDecommissioned(attributes) {
		return "", false
	}
	componentURN := backstageComponentResourceURN(event.GetTenantId(), attributes)
	anchor := backstageCriticalComponentMissingOwnerAnchor(map[string]string{"backstage_component_urn": componentURN})
	return anchor, anchor != ""
}

func matchesBackstageCriticalComponentMissingOwner(event *cerebrov1.EventEnvelope) bool {
	if !backstageCriticalComponentMissingOwnerKindMatcher(event) || !hasRequiredAttributes(event, backstageCriticalComponentMissingOwnerDefinition.RequiredAttributes...) {
		return false
	}
	attributes := eventAttributes(event)
	if backstageComponentDecommissioned(attributes) {
		return false
	}
	if !backstageComponentIsCritical(attributes["criticality"]) {
		return false
	}
	return !backstageComponentHasAccountableOwner(attributes)
}

func backstageCriticalComponentMissingOwnerFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	tenantID := strings.TrimSpace(event.GetTenantId())
	componentURN := backstageComponentResourceURN(tenantID, attrs)
	if componentURN == "" {
		return nil, nil
	}
	name := strings.TrimSpace(attrs["name"])
	label := firstNonEmpty(strings.TrimSpace(attrs["entity_ref"]), name)
	attributes := map[string]string{
		"backstage_component_urn": componentURN,
		"name":                    name,
		"namespace":               strings.TrimSpace(attrs["namespace"]),
		"component_kind":          strings.TrimSpace(attrs["kind"]),
		"type":                    strings.TrimSpace(attrs["type"]),
		"lifecycle":               strings.TrimSpace(attrs["lifecycle"]),
		"criticality":             strings.TrimSpace(attrs["criticality"]),
		"system":                  strings.TrimSpace(attrs["system"]),
		"entity_ref":              strings.TrimSpace(attrs["entity_ref"]),
		"event_id":                strings.TrimSpace(event.GetId()),
		"source_runtime_id":       strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":    componentURN,
	}
	for key, value := range backstageCriticalComponentMissingOwnerDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(backstageCriticalComponentMissingOwnerRuleID, componentURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          backstageCriticalComponentMissingOwnerRuleID,
		Title:           backstageCriticalComponentMissingOwnerTitle,
		Severity:        backstageCriticalComponentMissingOwnerSeverity,
		Status:          findingStatusOpen,
		Summary:         backstageCriticalComponentMissingOwnerSummary(label),
		ResourceURNs:    []string{componentURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         backstageCriticalComponentMissingOwnerCheckID,
		CheckName:       backstageCriticalComponentMissingOwnerCheckName,
		ControlRefs:     cloneFindingControlRefs(backstageCriticalComponentMissingOwnerDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func backstageComponentIsCritical(value string) bool {
	for _, token := range strings.Split(value, ",") {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		if _, ok := backstageCriticalComponentTiers[token]; ok {
			return true
		}
	}
	return false
}

func backstageComponentHasAccountableOwner(attributes map[string]string) bool {
	owner := strings.TrimSpace(attributes["owner"])
	if owner == "" {
		return false
	}
	normalized := normalizeBackstageOwnerValue(owner)
	if normalized == "" {
		return false
	}
	_, placeholder := backstageUnaccountableOwners[normalized]
	return !placeholder
}

func backstageComponentDecommissioned(attributes map[string]string) bool {
	lifecycle := strings.ToLower(strings.TrimSpace(attributes["lifecycle"]))
	_, ok := backstageDecommissionedLifecycles[lifecycle]
	return ok
}

func normalizeBackstageOwnerValue(owner string) string {
	owner = strings.ToLower(strings.TrimSpace(owner))
	owner = strings.TrimPrefix(owner, "group:")
	owner = strings.TrimPrefix(owner, "user:")
	if slash := strings.LastIndex(owner, "/"); slash >= 0 {
		owner = owner[slash+1:]
	}
	return strings.TrimSpace(owner)
}

func backstageComponentResourceURN(tenantID string, attributes map[string]string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ""
	}
	entityRef := strings.TrimSpace(attributes["entity_ref"])
	if entityRef == "" {
		name := strings.TrimSpace(attributes["name"])
		if name == "" {
			return ""
		}
		kind := firstNonEmpty(strings.TrimSpace(attributes["kind"]), "Component")
		namespace := firstNonEmpty(strings.TrimSpace(attributes["namespace"]), "default")
		entityRef = kind + "/" + namespace + "/" + name
	}
	return fmt.Sprintf("urn:cerebro:%s:service:%s", tenantID, canonicalBackstageComponentEntityRef(
		entityRef,
		firstNonEmpty(strings.TrimSpace(attributes["kind"]), "Component"),
		firstNonEmpty(strings.TrimSpace(attributes["namespace"]), "default"),
		strings.TrimSpace(attributes["name"]),
	))
}

func canonicalBackstageComponentEntityRef(entityRef string, kind string, namespace string, name string) string {
	value := strings.ToLower(strings.TrimSpace(entityRef))
	if value == "" {
		return strings.ToLower(firstNonEmpty(kind, "Component")) + "/" + strings.ToLower(firstNonEmpty(namespace, "default")) + "/" + strings.ToLower(strings.TrimSpace(name))
	}
	if colon := strings.Index(value, ":"); colon > 0 {
		refKind := strings.TrimSpace(value[:colon])
		remainder := strings.TrimSpace(value[colon+1:])
		if slash := strings.Index(remainder, "/"); slash > 0 {
			return refKind + "/" + strings.TrimSpace(remainder[:slash]) + "/" + strings.TrimSpace(remainder[slash+1:])
		}
		return refKind + "/default/" + remainder
	}
	parts := strings.Split(value, "/")
	if len(parts) == 3 {
		return strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1]) + "/" + strings.TrimSpace(parts[2])
	}
	if len(parts) == 2 {
		return strings.ToLower(firstNonEmpty(kind, "Component")) + "/" + strings.TrimSpace(parts[0]) + "/" + strings.TrimSpace(parts[1])
	}
	return value
}

func backstageCriticalComponentMissingOwnerAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"backstage_component_urn": strings.TrimSpace(attributes["backstage_component_urn"]),
	}, "backstage_component_urn")
}

func backstageCriticalComponentMissingOwnerSummary(label string) string {
	return fmt.Sprintf("Backstage critical component %s has no accountable owner", firstNonEmpty(label, "unknown component"))
}
