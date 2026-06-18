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
	tailscaleTailnetDeviceApprovalDisabledRuleID    = "tailscale-tailnet-device-approval-disabled"
	tailscaleTailnetDeviceApprovalDisabledTitle     = "Tailscale Tailnet Device Approval Disabled"
	tailscaleTailnetDeviceApprovalDisabledSeverity  = "MEDIUM"
	tailscaleTailnetDeviceApprovalDisabledStatus    = "open"
	tailscaleTailnetDeviceApprovalDisabledCheckID   = "tailscale-tailnet-device-approval-disabled-current"
	tailscaleTailnetDeviceApprovalDisabledCheckName = "Tailscale Tailnet Device Approval Disabled (current state)"
)

var tailscaleTailnetDeviceApprovalDisabledControlRefs = []ports.FindingControlRef{
	{FrameworkName: "SOC 2", ControlID: "CC6.1"},
	{FrameworkName: "ISO 27001:2022", ControlID: "A.8.2"},
}

type tailscaleTailnetDeviceApprovalDisabledRule struct {
	Rule
	definition RuleDefinition
}

var tailscaleTailnetDeviceApprovalDisabledDefinition = RuleDefinition{
	ID:                 tailscaleTailnetDeviceApprovalDisabledRuleID,
	Name:               tailscaleTailnetDeviceApprovalDisabledTitle,
	Description:        "Detect Tailscale tailnets whose device approval is currently disabled, allowing new devices to join the tailnet without administrator review.",
	SourceID:           "tailscale",
	EventKinds:         []string{"tailscale.tailnet"},
	OutputKind:         "finding.tailscale_tailnet_device_approval_disabled",
	Severity:           tailscaleTailnetDeviceApprovalDisabledSeverity,
	Status:             tailscaleTailnetDeviceApprovalDisabledStatus,
	Maturity:           "test",
	Tags:               []string{"tailscale", "tailnet", "device-approval", "access-control"},
	References:         []string{"https://tailscale.com/kb/1099/device-approval"},
	FalsePositives:     []string{"Tailnets that intentionally rely on tag/ACL-based authorization instead of manual device approval."},
	Runbook:            "Confirm whether device approval should be enforced for this tailnet; if so, enable device approval so new devices require administrator review before joining.",
	RequiredAttributes: []string{"tailnet"},
	FingerprintFields:  []string{"tailscale_tailnet_urn"},
	ControlRefs:        tailscaleTailnetDeviceApprovalDisabledControlRefs,
	Lifecycle:          Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState},
}

var tailscaleTailnetDeviceApprovalDisabledKindMatcher = eventKindMatcher(tailscaleTailnetDeviceApprovalDisabledDefinition.EventKinds...)

func newTailscaleTailnetDeviceApprovalDisabledRule() Rule {
	rule := newEventRule(eventRuleConfig{
		definition: tailscaleTailnetDeviceApprovalDisabledDefinition,
		match:      matchesTailscaleTailnetDeviceApprovalDisabled,
		build: func(ctx context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return tailscaleTailnetDeviceApprovalDisabledFinding(event, runtime.GetId())
		},
	})
	return &tailscaleTailnetDeviceApprovalDisabledRule{
		Rule:       rule,
		definition: tailscaleTailnetDeviceApprovalDisabledDefinition,
	}
}

func (r *tailscaleTailnetDeviceApprovalDisabledRule) RuleMetadata() RuleDefinition {
	if r == nil {
		return RuleDefinition{}
	}
	return cloneRuleDefinition(r.definition)
}

func (r *tailscaleTailnetDeviceApprovalDisabledRule) OpenAnchor(attributes map[string]string) string {
	return tailscaleTailnetDeviceApprovalDisabledAnchor(attributes)
}

func (r *tailscaleTailnetDeviceApprovalDisabledRule) CloseOnEvent(event Event) (string, bool) {
	if !tailscaleTailnetDeviceApprovalDisabledKindMatcher(event) || !hasRequiredAttributes(event, tailscaleTailnetDeviceApprovalDisabledDefinition.RequiredAttributes...) {
		return "", false
	}
	attributes := eventAttributes(event)
	if !tailscaleTailnetDeviceApprovalRestored(attributes) {
		return "", false
	}
	tailnetURN := tailscaleTailnetDeviceApprovalDisabledURN(event.GetTenantId(), attributes["tailnet"])
	anchor := tailscaleTailnetDeviceApprovalDisabledAnchor(map[string]string{"tailscale_tailnet_urn": tailnetURN})
	return anchor, anchor != ""
}

func matchesTailscaleTailnetDeviceApprovalDisabled(event *cerebrov1.EventEnvelope) bool {
	if !tailscaleTailnetDeviceApprovalDisabledKindMatcher(event) || !hasRequiredAttributes(event, tailscaleTailnetDeviceApprovalDisabledDefinition.RequiredAttributes...) {
		return false
	}
	return tailscaleTailnetDeviceApprovalIsDisabled(eventAttributes(event))
}

func tailscaleTailnetDeviceApprovalDisabledFinding(event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	attrs := event.GetAttributes()
	tailnet := strings.TrimSpace(attrs["tailnet"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	tailnetURN := tailscaleTailnetDeviceApprovalDisabledURN(tenantID, tailnet)
	if tailnetURN == "" {
		return nil, nil
	}
	attributes := map[string]string{
		"tailscale_tailnet_urn":   tailnetURN,
		"tailnet":                 tailnet,
		"devices_approval_on":     strings.TrimSpace(attrs["devices_approval_on"]),
		"users_approval_on":       strings.TrimSpace(attrs["users_approval_on"]),
		"network_flow_logging_on": strings.TrimSpace(attrs["network_flow_logging_on"]),
		"event_id":                strings.TrimSpace(event.GetId()),
		"source_runtime_id":       strings.TrimSpace(attrs[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":    tailnetURN,
	}
	for key, value := range tailscaleTailnetDeviceApprovalDisabledDefinition.AttributeMap() {
		attributes["rule_"+key] = value
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(tailscaleTailnetDeviceApprovalDisabledRuleID, tailnetURN)
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        tenantID,
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          tailscaleTailnetDeviceApprovalDisabledRuleID,
		Title:           tailscaleTailnetDeviceApprovalDisabledTitle,
		Severity:        tailscaleTailnetDeviceApprovalDisabledSeverity,
		Status:          tailscaleTailnetDeviceApprovalDisabledStatus,
		Summary:         tailscaleTailnetDeviceApprovalDisabledSummary(tailnet),
		ResourceURNs:    []string{tailnetURN},
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		CheckID:         tailscaleTailnetDeviceApprovalDisabledCheckID,
		CheckName:       tailscaleTailnetDeviceApprovalDisabledCheckName,
		ControlRefs:     cloneFindingControlRefs(tailscaleTailnetDeviceApprovalDisabledDefinition.ControlRefs),
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func tailscaleTailnetDeviceApprovalIsDisabled(attributes map[string]string) bool {
	enabled, ok := parseOptionalBoolAttribute(attributes, "devices_approval_on")
	return ok && !enabled
}

func tailscaleTailnetDeviceApprovalRestored(attributes map[string]string) bool {
	enabled, ok := parseOptionalBoolAttribute(attributes, "devices_approval_on")
	return ok && enabled
}

func tailscaleTailnetDeviceApprovalDisabledURN(tenantID string, tailnet string) string {
	tenantID = strings.TrimSpace(tenantID)
	tailnet = strings.TrimSpace(tailnet)
	if tenantID == "" || tailnet == "" {
		return ""
	}
	return fmt.Sprintf("urn:cerebro:%s:tailscale_tailnet:%s", tenantID, tailnet)
}

func tailscaleTailnetDeviceApprovalDisabledAnchor(attributes map[string]string) string {
	return identityCounterEventAnchor(map[string]string{
		"tailscale_tailnet_urn": strings.TrimSpace(attributes["tailscale_tailnet_urn"]),
	}, "tailscale_tailnet_urn")
}

func tailscaleTailnetDeviceApprovalDisabledSummary(tailnet string) string {
	return fmt.Sprintf("Tailscale tailnet %s has device approval disabled", firstNonEmpty(tailnet, "unknown tailnet"))
}
