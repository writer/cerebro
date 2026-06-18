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
	evidenceCASUnresolvedLinkageRuleID    = "evidence-cas-unresolved-linkage"
	evidenceCASUnresolvedLinkageTitle     = "Evidence CAS Object With Unresolved Linkage"
	evidenceCASUnresolvedLinkageSeverity  = "MEDIUM"
	evidenceCASUnresolvedLinkageCheckID   = "evidence-cas-unresolved-linkage-current"
	evidenceCASUnresolvedLinkageCheckName = "Evidence CAS Object With Unresolved Linkage (current state)"
	evidenceCASObjectEventKind            = "evidence_cas.object"
)

var evidenceCASUnresolvedLinkageControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.2"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.5.28"},
}

type evidenceCASUnresolvedLinkageRule struct {
	Rule
	definition RuleDefinition
}

var evidenceCASUnresolvedLinkageDefinition = RuleDefinition{
	ID:                 evidenceCASUnresolvedLinkageRuleID,
	Name:               evidenceCASUnresolvedLinkageTitle,
	Description:        "Detect Evidence CAS objects whose latest reference cannot resolve the case or resource it claims to document, leaving stored evidence detached from the asset, identity, or case it is meant to support and breaking its chain of custody until the linkage is repaired.",
	SourceID:           "evidence_cas",
	EventKinds:         []string{evidenceCASObjectEventKind},
	OutputKind:         "finding.evidence_cas_unresolved_linkage",
	Severity:           evidenceCASUnresolvedLinkageSeverity,
	Status:             findingStatusOpen,
	Maturity:           "test",
	Tags:               []string{"evidence-cas", "evidence", "chain-of-custody", "data-integrity", "correlation"},
	References:         []string{"https://github.com/writer/cerebro/blob/main/docs/ARCHITECTURE.md"},
	FalsePositives:     []string{"Evidence captured slightly ahead of the case or resource it references, where the linkage resolves on the next sync once the referenced context is ingested."},
	Runbook:            "Confirm whether the referenced case or resource exists, repair the evidence reference or ingest the missing context, and verify the next Evidence CAS sync resolves the linkage.",
	RequiredAttributes: []string{"evidence_id"},
	FingerprintFields:  []string{"evidence_cas_evidence_urn"},
	ControlRefs:        evidenceCASUnresolvedLinkageControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var evidenceCASObjectKindMatcher = eventKindMatcher(evidenceCASUnresolvedLinkageDefinition.EventKinds...)

func newEvidenceCASUnresolvedLinkageRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: evidenceCASUnresolvedLinkageDefinition,
		match:      matchesEvidenceCASUnresolvedLinkage,
		build: func(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return evidenceCASUnresolvedLinkageFinding(event, runtime.GetId())
		},
	})
	return &evidenceCASUnresolvedLinkageRule{
		Rule:       rule,
		definition: evidenceCASUnresolvedLinkageDefinition,
	}
}

func (r *evidenceCASUnresolvedLinkageRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *evidenceCASUnresolvedLinkageRule) OpenAnchor(attributes map[string]string) string {
	return evidenceCASUnresolvedLinkageAnchor(attributes)
}

// CloseOnEvent resolves an open finding only when a later reference for the
// same evidence object supplies case or resource context that explicitly
// resolves, so evidence whose context has since been ingested or repaired does
// not leave a stale open finding. A context-less follow-up event that omits
// case and resource linkage entirely must not close the finding: the absence
// of unresolved markers is not evidence that the linkage was repaired.
func (r *evidenceCASUnresolvedLinkageRule) CloseOnEvent(event Event) (string, bool) {
	if !evidenceCASObjectKindMatcher(event) || !hasRequiredAttributes(event, evidenceCASUnresolvedLinkageDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !evidenceCASLinkageResolved(attributes) {
		return "", false
	}
	evidenceURN := evidenceCASEvidenceURN(event.GetTenantId(), attributes["evidence_id"])
	anchor := evidenceCASUnresolvedLinkageAnchor(map[string]string{"evidence_cas_evidence_urn": evidenceURN})
	return anchor, anchor != ""
}

func matchesEvidenceCASUnresolvedLinkage(event *cerebrov1.EventEnvelope) bool {
	if !evidenceCASObjectKindMatcher(event) || !hasRequiredAttributes(event, evidenceCASUnresolvedLinkageDefinition.RequiredAttributes...) {
		return false
	}
	return evidenceCASLinkageUnresolved(eventAttributes(event))
}

func evidenceCASUnresolvedLinkageFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	evidenceID := strings.TrimSpace(attrs["evidence_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	evidenceURN := evidenceCASEvidenceURN(tenantID, evidenceID)
	if evidenceURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["resource_name"]), evidenceID)
	attributes := map[string]string{
		"evidence_cas_evidence_urn": evidenceURN,
		"evidence_id":               evidenceID,
		"evidence_type":             strings.TrimSpace(attrs["evidence_type"]),
		"source_system":             strings.TrimSpace(attrs["source_system"]),
		"unresolved_linkage":        evidenceCASUnresolvedLinkageScope(attrs),
		"case_id":                   strings.TrimSpace(attrs["case_id"]),
		"case_urn":                  strings.TrimSpace(attrs["case_urn"]),
		"case_link_status":          strings.TrimSpace(attrs["case_link_status"]),
		"resource_urn":              strings.TrimSpace(attrs["resource_urn"]),
		"resource_link_status":      strings.TrimSpace(attrs["resource_link_status"]),
		"evidence_cas_uri":          strings.TrimSpace(attrs["evidence_cas_uri"]),
		"evidence_cas_digest":       strings.TrimSpace(attrs["evidence_cas_digest"]),
		"event_id":                  strings.TrimSpace(event.GetId()),
		"source_runtime_id":         firstNonEmpty(strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]), strings.TrimSpace(runtimeID)),
		"primary_resource_urn":      evidenceURN,
	}
	for key, value := range evidenceCASUnresolvedLinkageDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(evidenceCASUnresolvedLinkageRuleID, evidenceURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          evidenceCASUnresolvedLinkageRuleID,
		Title:           evidenceCASUnresolvedLinkageTitle,
		Severity:        evidenceCASUnresolvedLinkageSeverity,
		Status:          findingStatusOpen,
		Summary:         evidenceCASUnresolvedLinkageSummary(label),
		ResourceURNs:    []string{evidenceURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		PolicyID:        evidenceID,
		CheckID:         evidenceCASUnresolvedLinkageCheckID,
		CheckName:       evidenceCASUnresolvedLinkageCheckName,
		ControlRefs:     cloneFindingControlRefs(evidenceCASUnresolvedLinkageDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

// evidenceCASLinkageUnresolved reports whether an Evidence CAS object that
// supplied a case or resource context could not resolve that context. Evidence
// with no declared context, or whose declared context resolves, is not a
// linkage risk so ordinary inventory does not surface as a finding.
func evidenceCASLinkageUnresolved(attributes map[string]string) bool {
	return evidenceCASResourceLinkUnresolved(attributes) || evidenceCASCaseLinkUnresolved(attributes)
}

// evidenceCASLinkageResolved reports whether an Evidence CAS object explicitly
// supplies case or resource context that resolves. It requires positive
// evidence of a repaired linkage: at least one declared context must be present
// and none of the declared contexts may be unresolved. Evidence that declares
// no case or resource context carries no resolved-linkage signal and therefore
// does not resolve an open finding.
func evidenceCASLinkageResolved(attributes map[string]string) bool {
	if !evidenceCASResourceContextSupplied(attributes) && !evidenceCASCaseContextSupplied(attributes) {
		return false
	}
	return !evidenceCASLinkageUnresolved(attributes)
}

func evidenceCASResourceLinkUnresolved(attributes map[string]string) bool {
	if !evidenceCASResourceContextSupplied(attributes) {
		return false
	}
	if parseBoolAttribute(attributes, "unresolved_resource_context") {
		return true
	}
	return !strings.EqualFold(strings.TrimSpace(attributes["resource_link_status"]), "linked")
}

func evidenceCASCaseLinkUnresolved(attributes map[string]string) bool {
	if !evidenceCASCaseContextSupplied(attributes) {
		return false
	}
	if parseBoolAttribute(attributes, "unresolved_case_context") {
		return true
	}
	return !strings.EqualFold(strings.TrimSpace(attributes["case_link_status"]), "linked")
}

func evidenceCASResourceContextSupplied(attributes map[string]string) bool {
	return firstNonEmpty(attributes["resource_urn"], attributes["resource_id"]) != "" ||
		parseBoolAttribute(attributes, "unresolved_resource_context")
}

func evidenceCASCaseContextSupplied(attributes map[string]string) bool {
	return firstNonEmpty(attributes["case_id"], attributes["case_urn"]) != "" ||
		parseBoolAttribute(attributes, "unresolved_case_context")
}

func evidenceCASUnresolvedLinkageScope(attributes map[string]string) string {
	resource := evidenceCASResourceLinkUnresolved(attributes)
	caseLink := evidenceCASCaseLinkUnresolved(attributes)
	switch {
	case resource && caseLink:
		return "resource_and_case"
	case resource:
		return "resource"
	case caseLink:
		return "case"
	default:
		return ""
	}
}

func evidenceCASEvidenceURN(tenantID string, evidenceID string) string {
	tenantID = strings.TrimSpace(tenantID)
	evidenceID = strings.TrimSpace(evidenceID)
	if tenantID == "" || evidenceID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:runtime_evidence:%s", tenantID, evidenceID)
}

func evidenceCASUnresolvedLinkageAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"evidence_cas_evidence_urn": strings.TrimSpace(attributes["evidence_cas_evidence_urn"]),
	}, "evidence_cas_evidence_urn")
}

func evidenceCASUnresolvedLinkageSummary(label string) string {
	return fmt.Sprintf("Evidence CAS object %s cannot resolve its case or resource linkage", firstNonEmpty(label, "unknown evidence"))
}
