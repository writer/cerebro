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
	kandjiEndpointDiskEncryptionDisabledRuleID    = "kandji-endpoint-disk-encryption-disabled"
	kandjiEndpointDiskEncryptionDisabledTitle     = "Kandji Endpoint Disk Encryption Disabled"
	kandjiEndpointDiskEncryptionDisabledSeverity  = "HIGH"
	kandjiEndpointDiskEncryptionDisabledStatus    = "open"
	kandjiEndpointDiskEncryptionDisabledCheckID   = "kandji-endpoint-disk-encryption-disabled-current"
	kandjiEndpointDiskEncryptionDisabledCheckName = "Kandji Endpoint Disk Encryption Disabled (current state)"
)

var kandjiEndpointDiskEncryptionDisabledControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.24"},
}

var kandjiEndpointDeprovisionedStatuses = map[string]struct{}{
	"deleted":     {},
	"removed":     {},
	"offboarded":  {},
	"unenrolled":  {},
	"deactivated": {},
	"inactive":    {},
	"retired":     {},
}

type kandjiEndpointDiskEncryptionDisabledRule struct {
	Rule
	definition RuleDefinition
}

var kandjiEndpointDiskEncryptionDisabledDefinition = RuleDefinition{
	ID:                 kandjiEndpointDiskEncryptionDisabledRuleID,
	Name:               kandjiEndpointDiskEncryptionDisabledTitle,
	Description:        "Detect Kandji-managed Apple endpoints whose FileVault disk encryption is currently disabled, leaving data at rest unprotected on a managed device.",
	SourceID:           "kandji",
	EventKinds:         []string{"kandji.device"},
	OutputKind:         "finding.kandji_endpoint_disk_encryption_disabled",
	Severity:           kandjiEndpointDiskEncryptionDisabledSeverity,
	Status:             kandjiEndpointDiskEncryptionDisabledStatus,
	Maturity:           "test",
	Tags:               []string{"kandji", "endpoint", "disk-encryption", "filevault", "device-posture"},
	References:         []string{"https://support.kandji.io/kb/filevault-overview"},
	FalsePositives:     []string{"Endpoints that are intentionally exempt from FileVault enforcement under a documented, risk-accepted blueprint."},
	Runbook:            "Confirm the device should enforce FileVault; if so, apply the FileVault Library Item to the device's blueprint and escalate disk encryption so data at rest is protected.",
	RequiredAttributes: []string{"device_id"},
	FingerprintFields:  []string{"kandji_device_urn"},
	ControlRefs:        kandjiEndpointDiskEncryptionDisabledControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var kandjiEndpointDiskEncryptionDisabledKindMatcher = eventKindMatcher(kandjiEndpointDiskEncryptionDisabledDefinition.EventKinds...)

func newKandjiEndpointDiskEncryptionDisabledRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: kandjiEndpointDiskEncryptionDisabledDefinition,
		match:      matchesKandjiEndpointDiskEncryptionDisabled,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return kandjiEndpointDiskEncryptionDisabledFinding(event, runtime.GetId())
		},
	})
	return &kandjiEndpointDiskEncryptionDisabledRule{
		Rule:       rule,
		definition: kandjiEndpointDiskEncryptionDisabledDefinition,
	}
}

func (r *kandjiEndpointDiskEncryptionDisabledRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *kandjiEndpointDiskEncryptionDisabledRule) OpenAnchor(attributes map[string]string) string {
	return kandjiEndpointDiskEncryptionDisabledAnchor(attributes)
}

// CloseOnEvent resolves an open finding when a later device snapshot shows
// FileVault has been re-enabled (remediation) or when the device is no longer
// managed by Kandji (deprovisioned/offboarded), so removed endpoints do not
// leave stale open findings.
func (r *kandjiEndpointDiskEncryptionDisabledRule) CloseOnEvent(event Event) (string, bool) {
	if !kandjiEndpointDiskEncryptionDisabledKindMatcher(event) || !hasRequiredAttributes(event, kandjiEndpointDiskEncryptionDisabledDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !kandjiEndpointDiskEncryptionRestored(attributes) && !kandjiEndpointDeprovisioned(attributes) {
		return "", false
	}
	deviceURN := kandjiEndpointURN(event.GetTenantId(), attributes["device_id"])
	anchor := kandjiEndpointDiskEncryptionDisabledAnchor(map[string]string{"kandji_device_urn": deviceURN})
	return anchor, anchor != ""
}

func matchesKandjiEndpointDiskEncryptionDisabled(event *cerebrov1.EventEnvelope) bool {
	if !kandjiEndpointDiskEncryptionDisabledKindMatcher(event) || !hasRequiredAttributes(event, kandjiEndpointDiskEncryptionDisabledDefinition.RequiredAttributes...) {
		return false
	}
	return kandjiEndpointDiskEncryptionIsDisabled(eventAttributes(event))
}

func kandjiEndpointDiskEncryptionDisabledFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	deviceID := strings.TrimSpace(attrs["device_id"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	deviceURN := kandjiEndpointURN(tenantID, deviceID)
	if deviceURN == "" {
		return nil, nil
	}
	label := firstNonEmpty(strings.TrimSpace(attrs["device_name"]), strings.TrimSpace(attrs["hostname"]), strings.TrimSpace(attrs["serial_number"]), deviceID)
	attributes := map[string]string{
		"kandji_device_urn":    deviceURN,
		"device_id":            deviceID,
		"device_name":          strings.TrimSpace(attrs["device_name"]),
		"hostname":             strings.TrimSpace(attrs["hostname"]),
		"serial_number":        strings.TrimSpace(attrs["serial_number"]),
		"platform":             strings.TrimSpace(attrs["platform"]),
		"blueprint_name":       strings.TrimSpace(attrs["blueprint_name"]),
		"owner_email":          firstNonEmpty(strings.TrimSpace(attrs["owner_email"]), strings.TrimSpace(attrs["user_email"])),
		"mdm_enabled":          strings.TrimSpace(attrs["mdm_enabled"]),
		"filevault_enabled":    strings.TrimSpace(attrs["filevault_enabled"]),
		"compliance_status":    strings.TrimSpace(attrs["compliance_status"]),
		"event_id":             strings.TrimSpace(event.GetId()),
		"source_runtime_id":    strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn": deviceURN,
	}
	for key, value := range kandjiEndpointDiskEncryptionDisabledDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(kandjiEndpointDiskEncryptionDisabledRuleID, deviceURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          kandjiEndpointDiskEncryptionDisabledRuleID,
		Title:           kandjiEndpointDiskEncryptionDisabledTitle,
		Severity:        kandjiEndpointDiskEncryptionDisabledSeverity,
		Status:          kandjiEndpointDiskEncryptionDisabledStatus,
		Summary:         kandjiEndpointDiskEncryptionDisabledSummary(label),
		ResourceURNs:    []string{deviceURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         kandjiEndpointDiskEncryptionDisabledCheckID,
		CheckName:       kandjiEndpointDiskEncryptionDisabledCheckName,
		ControlRefs:     cloneFindingControlRefs(kandjiEndpointDiskEncryptionDisabledDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func kandjiEndpointDiskEncryptionIsDisabled(attributes map[string]string) bool {
	if kandjiEndpointDeprovisioned(attributes) {
		return false
	}
	enabled, ok := parseOptionalBoolAttribute(attributes, "filevault_enabled")
	return ok && !enabled
}

func kandjiEndpointDiskEncryptionRestored(attributes map[string]string) bool {
	enabled, ok := parseOptionalBoolAttribute(attributes, "filevault_enabled")
	return ok && enabled
}

func kandjiEndpointDeprovisioned(attributes map[string]string) bool {
	if managed, ok := parseOptionalBoolAttribute(attributes, "mdm_enabled"); ok && !managed {
		return true
	}
	if missing, ok := parseOptionalBoolAttribute(attributes, "is_missing"); ok && missing {
		return true
	}
	status := strings.ToLower(strings.TrimSpace(attributes["status"]))
	_, deprovisioned := kandjiEndpointDeprovisionedStatuses[status]
	return deprovisioned
}

func kandjiEndpointURN(tenantID string, deviceID string) string {
	tenantID = strings.TrimSpace(tenantID)
	deviceID = strings.TrimSpace(deviceID)
	if tenantID == "" || deviceID == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:kandji_device:%s", tenantID, deviceID)
}

func kandjiEndpointDiskEncryptionDisabledAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"kandji_device_urn": strings.TrimSpace(attributes["kandji_device_urn"]),
	}, "kandji_device_urn")
}

func kandjiEndpointDiskEncryptionDisabledSummary(label string) string {
	return fmt.Sprintf("Kandji endpoint %s has FileVault disk encryption disabled", firstNonEmpty(label, "unknown device"))
}
