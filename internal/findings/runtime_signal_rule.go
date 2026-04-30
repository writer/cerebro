package findings

import (
	"context"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const runtimeActiveThreatEvidenceRuleID = "runtime-active-threat-evidence"

func newRuntimeActiveThreatEvidenceRule() Rule {
	definition := RuleDefinition{
		ID:                 runtimeActiveThreatEvidenceRuleID,
		Name:               "Runtime Active Threat Evidence",
		Description:        "Detect confirmed runtime evidence of active exploitation, credential access, or suspicious execution.",
		SourceID:           "runtime",
		EventKinds:         []string{"runtime.evidence"},
		OutputKind:         "finding.runtime_active_threat_evidence",
		Severity:           "HIGH",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"runtime", "threat", "evidence", "attack.t1059"},
		Runbook:            "Review the workload, process, credential access, linked finding, and runtime evidence before containment.",
		RequiredAttributes: []string{"evidence_type"},
		FingerprintFields:  []string{"event_id"},
	}
	return newEventRule(eventRuleConfig{definition: definition, sourceID: "runtime", match: eventKindMatcher("runtime.evidence"), build: buildRuntimeActiveThreatFinding})
}

func buildRuntimeActiveThreatFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
	attributes := eventAttributes(event)
	if !matchesRuntimeActiveThreat(attributes) {
		return nil, nil
	}
	projectedContext, err := buildFindingProjectionContext(ctx, event, findingProjectionContextOptions{
		PrimaryRelations:   []string{"has_evidence", "observed_on", "supports"},
		CollectAllLinkURNs: true,
		ResourceFallbacks:  []string{attributes["resource_name"], attributes["resource_id"], attributes["resource_urn"], attributes["workload_urn"]},
	})
	if err != nil {
		return nil, err
	}
	observedAt := time.Time{}
	if event.GetOccurredAt() != nil {
		observedAt = event.GetOccurredAt().AsTime().UTC()
	}
	findingAttributes := map[string]string{
		"action":               firstNonEmpty(attributes["evidence_type"], attributes["verdict"]),
		"confidence":           strings.TrimSpace(attributes["confidence"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"evidence_type":        strings.TrimSpace(attributes["evidence_type"]),
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"resource_id":          firstNonEmpty(attributes["resource_id"], attributes["resource_urn"], attributes["workload_urn"]),
		"resource_label":       projectedContext.ResourceLabel,
		"resource_type":        strings.TrimSpace(attributes["resource_type"]),
		"source_family":        strings.TrimSpace(runtime.GetSourceId()),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
		"verdict":              strings.TrimSpace(attributes["verdict"]),
	}
	for key, value := range attributes {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	definition := RuleDefinition{ID: runtimeActiveThreatEvidenceRuleID, Name: "Runtime Active Threat Evidence", SourceID: "runtime", OutputKind: "finding.runtime_active_threat_evidence", Severity: "HIGH", Status: findingStatusOpen}
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	fingerprint := hashFindingFingerprint(runtimeActiveThreatEvidenceRuleID, event.GetId(), projectedContext.PrimaryResourceURN, compoundRiskAction(&ports.FindingRecord{Attributes: findingAttributes}))
	return &ports.FindingRecord{ID: fingerprint, Fingerprint: fingerprint, TenantID: strings.TrimSpace(event.GetTenantId()), RuntimeID: strings.TrimSpace(runtime.GetId()), RuleID: runtimeActiveThreatEvidenceRuleID, Title: "Runtime Active Threat Evidence", Severity: "HIGH", Status: findingStatusOpen, Summary: "Runtime evidence indicates active threat activity", ResourceURNs: projectedContext.ResourceURNs, EventIDs: []string{event.GetId()}, PolicyID: firstNonEmpty(findingAttributes["resource_id"], findingAttributes["evidence_id"]), CheckID: runtimeActiveThreatEvidenceRuleID, CheckName: "Runtime Active Threat Evidence", Attributes: findingAttributes, FirstObservedAt: observedAt, LastObservedAt: observedAt}, nil
}

func matchesRuntimeActiveThreat(attributes map[string]string) bool {
	verdict := strings.ToLower(strings.TrimSpace(attributes["verdict"]))
	if containsAny(verdict, "malicious", "exploited", "confirmed", "active") {
		return true
	}
	evidenceType := strings.ToLower(strings.TrimSpace(attributes["evidence_type"]))
	if !containsAny(evidenceType, "exploit", "secret_access", "credential_use", "token_exchange", "suspicious_process") {
		return false
	}
	confidence, err := strconv.ParseFloat(strings.TrimSpace(attributes["confidence"]), 64)
	return err == nil && confidence >= 0.7
}
