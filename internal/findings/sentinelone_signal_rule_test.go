package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSentinelOneProtectionControlTampering(t *testing.T) {
	rule := newSentinelOneProtectionControlTamperingRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("sentinelone-protection-control-tampering does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if err := definition.Validate(); err != nil {
		t.Fatalf("RuleDefinition.Validate() error = %v", err)
	}
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	if !cloudStringSlicesEqual(definition.EventKinds, []string{sentinelOneAgentEntityType}) {
		t.Fatalf("EventKinds = %v, want [%s]", definition.EventKinds, sentinelOneAgentEntityType)
	}
	if !cloudStringSlicesEqual(definition.RequiredAttributes, []string{"agent_id"}) {
		t.Fatalf("RequiredAttributes = %v, want [agent_id]", definition.RequiredAttributes)
	}
	if !cloudStringSlicesEqual(definition.FingerprintFields, []string{"agent_id", "control_type"}) {
		t.Fatalf("FingerprintFields = %v, want [agent_id control_type]", definition.FingerprintFields)
	}
	for _, field := range definition.FingerprintFields {
		if strings.EqualFold(field, "activity_id") {
			t.Fatalf("FingerprintFields = %v, must not include activity_id", definition.FingerprintFields)
		}
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("sentinelone-protection-control-tampering does not implement CounterEventRule")
	}

	runtimeA := &cerebrov1.SourceRuntime{Id: "example-sentinelone-agent-a", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}
	runtimeB := &cerebrov1.SourceRuntime{Id: "example-sentinelone-agent-b", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}
	tampered := sentinelOneProtectionControlStateEvent("s1-agent-control-tampered-a", "activity-a", "tampered", identityTrajectoryBaseTime)
	records, err := rule.Evaluate(context.Background(), runtimeA, tampered)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(tampered) = (%v, %v), want one finding", records, err)
	}
	first := records[0]
	wantFingerprint := hashFindingFingerprint(sentinelOneProtectionControlTamperingRuleID, "agent-99", "firewall")
	if got := first.Fingerprint; got != wantFingerprint {
		t.Fatalf("fingerprint = %q, want stable agent/control fingerprint %q", got, wantFingerprint)
	}
	if got := first.Attributes["agent_id"]; got != "agent-99" {
		t.Fatalf("attributes[agent_id] = %q, want agent-99", got)
	}
	if got := first.Attributes["control_type"]; got != "firewall" {
		t.Fatalf("attributes[control_type] = %q, want firewall", got)
	}
	if got := first.Attributes["control_state"]; got != "disabled" {
		t.Fatalf("attributes[control_state] = %q, want disabled derived from firewall_enabled=false", got)
	}
	if got := first.Attributes["firewall_enabled"]; got != "false" {
		t.Fatalf("attributes[firewall_enabled] = %q, want false", got)
	}
	if got := first.Attributes["activity_id"]; got != "activity-a" {
		t.Fatalf("attributes[activity_id] = %q, want activity-a as evidence only", got)
	}
	openAnchor := counterRule.OpenAnchor(first.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want agent/control anchor", first.Attributes)
	}

	tamperedAgain := sentinelOneProtectionControlStateEvent("s1-agent-control-tampered-b", "activity-b", "tampered", identityTrajectoryBaseTime.Add(time.Minute))
	records, err = rule.Evaluate(context.Background(), runtimeB, tamperedAgain)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(tampered again) = (%v, %v), want one finding", records, err)
	}
	if got := records[0].Fingerprint; got != first.Fingerprint {
		t.Fatalf("second fingerprint = %q, want stable %q despite activity_id/runtime change", got, first.Fingerprint)
	}

	restored := sentinelOneProtectionControlStateEvent("s1-agent-control-restored", "activity-c", "restored", identityTrajectoryBaseTime.Add(2*time.Minute))
	records, err = rule.Evaluate(context.Background(), runtimeA, restored)
	if err != nil {
		t.Fatalf("Evaluate(restored) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(restored) returned %d findings, want 0 once control is restored", len(records))
	}
	closeAnchor, closes := counterRule.CloseOnEvent(restored)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(restored) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	auditActivity := sentinelOneActivityControlTamperEvent("s1-activity-legacy")
	records, err = rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "example-sentinelone-activity", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "activity"}}, auditActivity)
	if err != nil {
		t.Fatalf("Evaluate(legacy activity) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(legacy activity) returned %d findings, want 0 old audit-event findings", len(records))
	}

	assertIdentityRuleRemediationTrajectory(t, rule, tampered, restored, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderRestored := sentinelOneProtectionControlStateEvent("s1-agent-control-restored-before-open", "activity-old-close", "restored", identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderRestored, tampered)
}

func sentinelOneProtectionControlStateEvent(id string, activityID string, controlState string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	firewallEnabled := "false"
	if strings.EqualFold(controlState, "restored") || strings.EqualFold(controlState, "enabled") {
		firewallEnabled = "true"
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "sentinelone",
		Kind:       sentinelOneAgentEntityType,
		OccurredAt: timestamppb.New(occurredAt),
		Attributes: map[string]string{
			"agent_id":         "agent-99",
			"computer_name":    "mac-99",
			"firewall_enabled": firewallEnabled,
			"activity_id":      activityID,
			"site_id":          "site-1",
			"site_name":        "Production",
			"group_id":         "group-1",
			"group_name":       "Default",
			"tenant_host":      "writer.sentinelone.example",
			"source_message":   "SentinelOne protection control state projection",
		},
	}
}

func sentinelOneActivityControlTamperEvent(id string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "sentinelone",
		Kind:       sentinelOneActivityEntityType,
		OccurredAt: timestamppb.New(identityTrajectoryBaseTime),
		Attributes: map[string]string{
			"activity_id":           "legacy-activity-1",
			"activity_type":         "42",
			"agent_id":              "agent-99",
			"primary_description":   "Policy updated to disable protection for agent",
			"secondary_description": "legacy audit activity should remain evidence-only",
		},
	}
}
