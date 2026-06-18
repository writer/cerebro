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
	kolideHostFailingComplianceChecksRuleID    = "kolide-host-failing-compliance-checks"
	kolideHostFailingComplianceChecksTitle     = "Kolide Host Failing Compliance Checks"
	kolideHostFailingComplianceChecksSeverity  = "MEDIUM"
	kolideHostFailingComplianceChecksStatus    = "open"
	kolideHostFailingComplianceChecksCheckID   = "kolide-host-failing-compliance-checks-current"
	kolideHostFailingComplianceChecksCheckName = "Kolide Host Failing Compliance Checks (current state)"
	kolideDeviceEventKind                      = "kolide.device"
	kolideIssueEventKind                       = "kolide.issue"
)

var kolideHostFailingComplianceChecksControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC7.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.9"},
}

var kolideHostDeprovisionedStatuses = map[string]struct{}{
	"deleted":     {},
	"removed":     {},
	"offboarded":  {},
	"unenrolled":  {},
	"deactivated": {},
	"inactive":    {},
	"retired":     {},
}

type kolideHostFailingComplianceChecksRule struct {
	Rule
	definition RuleDefinition
}

var kolideHostFailingComplianceChecksDefinition = RuleDefinition{
	ID:                 kolideHostFailingComplianceChecksRuleID,
	Name:               kolideHostFailingComplianceChecksTitle,
	Description:        "Detect Kolide-managed hosts that currently fail one or more device compliance checks, indicating a sustained non-compliant endpoint posture that leaves the host out of policy.",
	SourceID:           "kolide",
	EventKinds:         []string{kolideIssueEventKind, kolideDeviceEventKind},
	OutputKind:         "finding.kolide_host_failing_compliance_checks",
	Severity:           kolideHostFailingComplianceChecksSeverity,
	Status:             kolideHostFailingComplianceChecksStatus,
	Maturity:           "test",
	Tags:               []string{"kolide", "endpoint", "device-posture", "compliance", "osquery"},
	References:         []string{"https://www.kolide.com/features/checks"},
	FalsePositives:     []string{"Hosts with failing checks that are covered by a documented, risk-accepted exception or are pending a scheduled maintenance window."},
	Runbook:            "Review the host's failing Kolide checks, remediate the underlying configuration gaps (or apply auto-remediation), and confirm the host returns to a passing compliance state.",
	RequiredAttributes: []string{"device_id"},
	RequiredAttributesByKind: map[string][]string{
		kolideDeviceEventKind: {"device_id"},
		kolideIssueEventKind:  {"device_id", "issue_id"},
	},
	FingerprintFields: []string{"kolide_issue_urn", "kolide_device_urn"},
	ControlRefs:       kolideHostFailingComplianceChecksControlRefs,
	Lifecycle:         Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var kolideHostFailingComplianceChecksKindMatcher = eventKindMatcher(kolideHostFailingComplianceChecksDefinition.EventKinds...)

func newKolideHostFailingComplianceChecksRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: kolideHostFailingComplianceChecksDefinition,
		match:      matchesKolideHostFailingComplianceChecks,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return kolideHostFailingComplianceChecksFinding(event, runtime.GetId())
		},
	})
	return &kolideHostFailingComplianceChecksRule{
		Rule:       rule,
		definition: kolideHostFailingComplianceChecksDefinition,
	}
}

func (r *kolideHostFailingComplianceChecksRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *kolideHostFailingComplianceChecksRule) OpenAnchor(attributes map[string]string) string {
	return kolideHostFailingComplianceChecksAnchor(attributes)
}

// CloseOnEvent resolves an open issue finding when Kolide later marks that
// issue resolved/exempted. Legacy device aggregate findings still close when a
// later host snapshot reports zero failing checks or a deprovisioned host.
func (r *kolideHostFailingComplianceChecksRule) CloseOnEvent(event Event) (string, bool) {
	if !kolideHostFailingComplianceChecksKindMatcher(event) {
		return "", false
	}
	attributes := eventAttributes(event)
	switch strings.TrimSpace(event.GetKind()) {
	case kolideIssueEventKind:
		if !kolideIssueResolved(attributes) {
			return "", false
		}
		issueURN := kolideIssueURN(event.GetTenantId(), attributes["issue_id"])
		anchor := kolideHostFailingComplianceChecksAnchor(map[string]string{"kolide_issue_urn": issueURN})
		return anchor, anchor != ""
	case kolideDeviceEventKind:
		if !hasRequiredAttributes(event, kolideHostFailingComplianceChecksDefinition.RequiredAttributes...) {
			return "", false
		}
		if !kolideHostChecksRemediated(attributes) && !kolideHostDeprovisioned(attributes) {
			return "", false
		}
		deviceURN := kolideHostURN(event.GetTenantId(), attributes["device_id"])
		anchor := kolideHostFailingComplianceChecksAnchor(map[string]string{"kolide_device_urn": deviceURN})
		return anchor, anchor != ""
	default:
		return "", false
	}
}

func matchesKolideHostFailingComplianceChecks(event *cerebrov1.EventEnvelope) bool {
	if !kolideHostFailingComplianceChecksKindMatcher(event) {
		return false
	}
	attributes := eventAttributes(event)
	switch strings.TrimSpace(event.GetKind()) {
	case kolideIssueEventKind:
		return kolideIssueOpen(attributes)
	case kolideDeviceEventKind:
		if !hasRequiredAttributes(event, kolideHostFailingComplianceChecksDefinition.RequiredAttributes...) {
			return false
		}
		return kolideHostChecksFailing(attributes)
	default:
		return false
	}
}

func kolideHostFailingComplianceChecksFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	deviceID := strings.TrimSpace(attrs["device_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	deviceURN := kolideHostURN(tenantID, deviceID)
	if deviceURN == "" {
		return nil, nil
	}
	if strings.TrimSpace(event.GetKind()) == kolideIssueEventKind {
		return kolideIssueFinding(event, runtimeID, deviceURN)
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["device_name"]), strings.TrimSpace(attrs["hostname"]), strings.TrimSpace(attrs["serial_number"]), deviceID)
	attributes := map[string]string{
		"kolide_device_urn":    deviceURN,
		"device_id":            deviceID,
		"device_name":          strings.TrimSpace(attrs["device_name"]),
		"hostname":             strings.TrimSpace(attrs["hostname"]),
		"serial_number":        strings.TrimSpace(attrs["serial_number"]),
		"platform":             strings.TrimSpace(attrs["platform"]),
		"owner_email":          firstNonEmpty(strings.TrimSpace(attrs["owner_email"]), strings.TrimSpace(attrs["user_email"])),
		"failure_count":        strings.TrimSpace(attrs["failure_count"]),
		"registered":           strings.TrimSpace(attrs["registered"]),
		"compliance_status":    strings.TrimSpace(attrs["compliance_status"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": deviceURN,
	}
	for key, value := range kolideHostFailingComplianceChecksDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(kolideHostFailingComplianceChecksRuleID, deviceURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          kolideHostFailingComplianceChecksRuleID,
		Title:           kolideHostFailingComplianceChecksTitle,
		Severity:        kolideHostFailingComplianceChecksSeverity,
		Status:          kolideHostFailingComplianceChecksStatus,
		Summary:         kolideHostFailingComplianceChecksSummary(label),
		ResourceURNs:    []string{deviceURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         kolideHostFailingComplianceChecksCheckID,
		CheckName:       kolideHostFailingComplianceChecksCheckName,
		ControlRefs:     cloneFindingControlRefs(kolideHostFailingComplianceChecksDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func kolideIssueFinding(event *cerebrov1.EventEnvelope, runtimeID string, deviceURN string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	tenantID := strings.TrimSpace(event.GetTenantId())
	deviceID := strings.TrimSpace(attrs["device_id"])
	issueID := strings.TrimSpace(attrs["issue_id"])
	issueURN := kolideIssueURN(tenantID, issueID)
	if issueURN == "" {
		return nil, nil
	}
	checkID := strings.TrimSpace(attrs["check_id"])
	checkURN := kolideCheckURN(tenantID, checkID)
	checkName := firstNonEmpty(strings.TrimSpace(attrs["title"]), checkID, kolideHostFailingComplianceChecksCheckName)
	label := firstNonEmpty(strings.TrimSpace(attrs["device_name"]), strings.TrimSpace(attrs["hostname"]), strings.TrimSpace(attrs["serial_number"]), deviceID)
	attributes := map[string]string{
		"kolide_issue_urn":     issueURN,
		"kolide_device_urn":    deviceURN,
		"kolide_check_urn":     checkURN,
		"issue_id":             issueID,
		"issue_key":            strings.TrimSpace(attrs["issue_key"]),
		"issue_value":          strings.TrimSpace(attrs["issue_value"]),
		"check_id":             checkID,
		"check_name":           checkName,
		"check_url":            strings.TrimSpace(attrs["check_url"]),
		"device_id":            deviceID,
		"device_url":           strings.TrimSpace(attrs["device_url"]),
		"device_name":          strings.TrimSpace(attrs["device_name"]),
		"hostname":             strings.TrimSpace(attrs["hostname"]),
		"serial_number":        strings.TrimSpace(attrs["serial_number"]),
		"exempted":             strings.TrimSpace(attrs["exempted"]),
		"detected_at":          strings.TrimSpace(attrs["detected_at"]),
		"last_rechecked_at":    strings.TrimSpace(attrs["last_rechecked_at"]),
		"blocks_device_at":     strings.TrimSpace(attrs["blocks_device_at"]),
		"check_result_value":   strings.TrimSpace(attrs["check_result_value"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": deviceURN,
	}
	for key, value := range kolideHostFailingComplianceChecksDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	resourceURNs := []string{deviceURN, issueURN}
	if checkURN != "" {
		resourceURNs = append(resourceURNs, checkURN)
	}
	fingerprint := hashFindingFingerprint(kolideHostFailingComplianceChecksRuleID, issueURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          kolideHostFailingComplianceChecksRuleID,
		Title:           kolideHostFailingComplianceChecksTitle,
		Severity:        kolideHostFailingComplianceChecksSeverity,
		Status:          kolideHostFailingComplianceChecksStatus,
		Summary:         kolideIssueSummary(label, checkName),
		ResourceURNs:    resourceURNs,
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		PolicyID:        issueID,
		CheckID:         firstNonEmpty(checkID, kolideHostFailingComplianceChecksCheckID),
		CheckName:       checkName,
		ControlRefs:     cloneFindingControlRefs(kolideHostFailingComplianceChecksDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func kolideHostChecksFailing(attributes map[string]string) bool {
	if kolideHostDeprovisioned(attributes) {
		return false
	}
	count, ok := findingAttributeInt(attributes, "failure_count")
	return ok && count > 0
}

func kolideHostChecksRemediated(attributes map[string]string) bool {
	count, ok := findingAttributeInt(attributes, "failure_count")
	return ok && count == 0
}

func kolideIssueOpen(attributes map[string]string) bool {
	if strings.TrimSpace(attributes["issue_id"]) == "" || strings.TrimSpace(attributes["device_id"]) == "" {
		return false
	}
	return !kolideIssueResolved(attributes)
}

func kolideIssueResolved(attributes map[string]string) bool {
	if strings.TrimSpace(attributes["resolved_at"]) != "" {
		return true
	}
	if exempted, ok := parseOptionalBoolAttribute(attributes, "exempted"); ok && exempted {
		return true
	}
	return false
}

func kolideHostDeprovisioned(attributes map[string]string) bool {
	if registered, ok := parseOptionalBoolAttribute(attributes, "registered"); ok && !registered {
		return true
	}
	if managed, ok := parseOptionalBoolAttribute(attributes, "mdm_enabled"); ok && !managed {
		return true
	}
	status := strings.ToLower(strings.TrimSpace(attributes["status"]))
	_, deprovisioned := kolideHostDeprovisionedStatuses[status]
	return deprovisioned
}

func kolideIssueURN(tenantID string, issueID string) string {
	tenantID = strings.TrimSpace(tenantID)
	issueID = strings.TrimSpace(issueID)
	if tenantID == "" || issueID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:kolide_issue:%s", tenantID, issueID)
}

func kolideCheckURN(tenantID string, checkID string) string {
	tenantID = strings.TrimSpace(tenantID)
	checkID = strings.TrimSpace(checkID)
	if tenantID == "" || checkID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:kolide_check:%s", tenantID, checkID)
}

func kolideHostURN(tenantID string, deviceID string) string {
	tenantID = strings.TrimSpace(tenantID)
	deviceID = strings.TrimSpace(deviceID)
	if tenantID == "" || deviceID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:kolide_device:%s", tenantID, deviceID)
}

func kolideHostFailingComplianceChecksAnchor(attributes map[string]string) string {
	if issueURN := strings.TrimSpace(attributes["kolide_issue_urn"]); issueURN != "" {
		return identityCounterEventAnchor(map[string]string{
			"kolide_issue_urn": issueURN,
		}, "kolide_issue_urn")
	}
	return identityCounterEventAnchor(map[string]string{
		"kolide_device_urn": strings.TrimSpace(attributes["kolide_device_urn"]),
	}, "kolide_device_urn")
}

func kolideIssueSummary(label string, checkName string) string {
	return fmt.Sprintf("Kolide host %s is failing check %s", firstNonEmpty(label, "unknown host"), firstNonEmpty(checkName, "unknown check"))
}

func kolideHostFailingComplianceChecksSummary(label string) string {
	return fmt.Sprintf("Kolide host %s is failing one or more device compliance checks", firstNonEmpty(label, "unknown host"))
}
