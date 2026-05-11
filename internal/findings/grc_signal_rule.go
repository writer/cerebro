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
	grcControlTestNeedsAttentionRuleID = "grc-control-test-needs-attention"
	grcVulnerabilitySLAOverdueRuleID   = "grc-vulnerability-sla-overdue"
	grcVendorReviewOverdueRuleID       = "grc-vendor-review-overdue"
)

func newGRCControlTestNeedsAttentionRule() Rule {
	definition := RuleDefinition{
		ID:                 grcControlTestNeedsAttentionRuleID,
		Name:               "GRC Control Test Needs Attention",
		Description:        "Detect provider-neutral GRC control tests that are failing or need attention.",
		SourceID:           "grc",
		EventKinds:         []string{"grc.control_test"},
		OutputKind:         "finding.grc_control_test_needs_attention",
		Severity:           "MEDIUM",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"grc", "compliance", "control-test"},
		RequiredAttributes: []string{"test_id", "status"},
		FingerprintFields:  []string{"provider", "test_id"},
	}
	return newEventRule(eventRuleConfig{definition: definition, match: matchesGRCControlTestNeedsAttention, build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
		return buildGRCFinding(ctx, runtime, event, definition, "GRC control test needs attention", grcControlTestSummary(event.GetAttributes()), "test_id", "MEDIUM")
	}})
}

func newGRCVulnerabilitySLAOverdueRule() Rule {
	definition := RuleDefinition{
		ID:                 grcVulnerabilitySLAOverdueRuleID,
		Name:               "GRC Vulnerability SLA Overdue",
		Description:        "Detect provider-neutral GRC vulnerabilities that are past remediation deadline.",
		SourceID:           "grc",
		EventKinds:         []string{"grc.vulnerability"},
		OutputKind:         "finding.grc_vulnerability_sla_overdue",
		Severity:           "dynamic",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"grc", "vulnerability", "sla"},
		RequiredAttributes: []string{"name", "remediate_by_date"},
		FingerprintFields:  []string{"provider", "name", "package", "target_id"},
	}
	return newEventRule(eventRuleConfig{definition: definition, match: matchesGRCVulnerabilitySLAOverdue, build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
		attrs := event.GetAttributes()
		return buildGRCFinding(ctx, runtime, event, definition, "GRC vulnerability SLA overdue", grcVulnerabilitySummary(attrs), "name", normalizeFindingSeverity(attrs["severity"]))
	}})
}

func newGRCVendorReviewOverdueRule() Rule {
	definition := RuleDefinition{
		ID:                 grcVendorReviewOverdueRuleID,
		Name:               "GRC Vendor Review Overdue",
		Description:        "Detect provider-neutral GRC vendors with overdue security reviews or missing owners.",
		SourceID:           "grc",
		EventKinds:         []string{"grc.vendor"},
		OutputKind:         "finding.grc_vendor_review_overdue",
		Severity:           "MEDIUM",
		Status:             findingStatusOpen,
		Maturity:           "test",
		Tags:               []string{"grc", "vendor-risk"},
		RequiredAttributes: []string{"vendor_id"},
		FingerprintFields:  []string{"provider", "vendor_id"},
	}
	return newEventRule(eventRuleConfig{definition: definition, match: matchesGRCVendorReviewOverdue, build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
		attrs := event.GetAttributes()
		return buildGRCFinding(ctx, runtime, event, definition, "GRC vendor review overdue", grcVendorSummary(attrs), "vendor_id", "MEDIUM")
	}})
}

func matchesGRCControlTestNeedsAttention(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher("grc.control_test")(event) || !hasRequiredAttributes(event, "test_id", "status") {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(event.GetAttributes()["status"]))
	return containsAny(status, "needs_attention", "fail", "failing", "error")
}

func matchesGRCVulnerabilitySLAOverdue(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher("grc.vulnerability")(event) || !hasRequiredAttributes(event, "name", "remediate_by_date") {
		return false
	}
	attrs := event.GetAttributes()
	if value := strings.ToLower(strings.TrimSpace(attrs["is_fixable"])); value != "" && value != "true" && value != "1" && value != "yes" {
		return false
	}
	deadline, ok := parseGRCTime(attrs["remediate_by_date"])
	return ok && deadline.Before(time.Now().UTC())
}

func matchesGRCVendorReviewOverdue(event *cerebrov1.EventEnvelope) bool {
	if !eventKindMatcher("grc.vendor")(event) || !hasRequiredAttributes(event, "vendor_id") {
		return false
	}
	attrs := event.GetAttributes()
	if strings.TrimSpace(attrs["security_owner_user_id"]) == "" {
		return true
	}
	due, ok := parseGRCTime(attrs["next_security_review_due_date"])
	return ok && due.Before(time.Now().UTC())
}

func buildGRCFinding(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope, definition RuleDefinition, title string, summary string, policyKey string, severity string) (*ports.FindingRecord, error) {
	projectedContext, err := buildFindingProjectionContext(ctx, event, grcFindingProjectionOptions(event))
	if err != nil {
		return nil, err
	}
	attrs := event.GetAttributes()
	findingAttributes := map[string]string{
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_kind":           strings.TrimSpace(event.GetKind()),
		"primary_resource_urn": projectedContext.PrimaryResourceURN,
		"provider":             strings.TrimSpace(attrs["provider"]),
		"source_runtime_id":    strings.TrimSpace(runtime.GetId()),
	}
	for key, value := range attrs {
		if _, exists := findingAttributes[key]; !exists {
			findingAttributes[key] = strings.TrimSpace(value)
		}
	}
	for key, value := range definition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	policyID := firstNonEmpty(strings.TrimSpace(attrs[policyKey]), projectedContext.PrimaryResourceURN)
	fingerprint := hashFindingFingerprint(grcFingerprintParts(definition, attrs, policyID)...)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        strings.TrimSpace(event.GetTenantId()),
		RuntimeID:       strings.TrimSpace(runtime.GetId()),
		RuleID:          definition.ID,
		Title:           title,
		Severity:        normalizeFindingSeverity(severity),
		Status:          findingStatusOpen,
		Summary:         summary,
		ResourceURNs:    projectedContext.ResourceURNs,
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		PolicyID:        policyID,
		PolicyName:      firstNonEmpty(projectedContext.ResourceLabel, attrs["name"], attrs["title"], attrs["description"]),
		CheckID:         definition.ID,
		CheckName:       definition.Name,
		Attributes:      findingAttributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func grcFindingProjectionOptions(event *cerebrov1.EventEnvelope) findingProjectionContextOptions {
	options := findingProjectionContextOptions{CollectAllEntities: true}
	switch strings.TrimSpace(event.GetKind()) {
	case "grc.control_test":
		options.PrimaryEntityType = "evidence"
		options.ResourceFallbacks = []string{event.GetAttributes()["name"], event.GetAttributes()["test_id"]}
	case "grc.vulnerability":
		options.PrimaryEntityType = "vulnerability"
		options.ResourceFallbacks = []string{event.GetAttributes()["name"], event.GetAttributes()["vulnerability_id"]}
	case "grc.vendor":
		options.PrimaryEntityType = "vendor"
		options.ResourceFallbacks = []string{event.GetAttributes()["name"], event.GetAttributes()["vendor_id"]}
	}
	return options
}

func grcFingerprintParts(definition RuleDefinition, attrs map[string]string, fallbackPolicyID string) []string {
	parts := []string{definition.ID}
	if len(definition.FingerprintFields) == 0 {
		return append(parts, attrs["provider"], fallbackPolicyID)
	}
	for _, field := range definition.FingerprintFields {
		parts = append(parts, attrs[strings.TrimSpace(field)])
	}
	return parts
}

func grcControlTestSummary(attrs map[string]string) string {
	return fmt.Sprintf("GRC control test %s has status %s", firstNonEmpty(attrs["name"], attrs["test_id"], "unknown test"), firstNonEmpty(attrs["status"], "needs attention"))
}

func grcVulnerabilitySummary(attrs map[string]string) string {
	return fmt.Sprintf("GRC vulnerability %s is past remediation deadline %s", firstNonEmpty(attrs["name"], attrs["vulnerability_id"], "unknown vulnerability"), firstNonEmpty(attrs["remediate_by_date"], "unknown"))
}

func grcVendorSummary(attrs map[string]string) string {
	if strings.TrimSpace(attrs["security_owner_user_id"]) == "" {
		return fmt.Sprintf("GRC vendor %s is missing a security owner", firstNonEmpty(attrs["name"], attrs["vendor_id"], "unknown vendor"))
	}
	return fmt.Sprintf("GRC vendor %s has overdue security review due %s", firstNonEmpty(attrs["name"], attrs["vendor_id"], "unknown vendor"), firstNonEmpty(attrs["next_security_review_due_date"], "unknown"))
}

func parseGRCTime(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}
