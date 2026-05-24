package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/workflowevents"
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
	wantFingerprint := hashFindingFingerprint(sentinelOneProtectionControlTamperingRuleID, "writer", "agent-99", "firewall")
	if got := first.Fingerprint; got != wantFingerprint {
		t.Fatalf("fingerprint = %q, want stable tenant/agent/control fingerprint %q", got, wantFingerprint)
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

func TestSentinelOneProtectionControlTampering_FirewallUnknownDoesNotFire(t *testing.T) {
	rule := newSentinelOneProtectionControlTamperingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "example-sentinelone-agent", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}

	for _, tt := range []struct {
		name  string
		event *cerebrov1.EventEnvelope
	}{
		{
			name:  "raw_source_missing_firewall",
			event: sentinelOneProtectionControlUnknownFirewallEvent("s1-agent-firewall-unknown-raw", false),
		},
		{
			name:  "typed_firewall_missing_state",
			event: sentinelOneProtectionControlUnknownFirewallEvent("s1-agent-firewall-unknown-typed", true),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attributes := eventAttributes(tt.event)
			if got := sentinelOneProtectionControlState(attributes); got != "unknown" {
				t.Fatalf("sentinelOneProtectionControlState(%v) = %q, want unknown", attributes, got)
			}
			if tampered, known := sentinelOneProtectionControlTampered(attributes); tampered || known {
				t.Fatalf("sentinelOneProtectionControlTampered(%v) = (%v, %v), want (false, false)", attributes, tampered, known)
			}
			records, err := rule.Evaluate(context.Background(), runtime, tt.event)
			if err != nil {
				t.Fatalf("Evaluate(unknown firewall) error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(unknown firewall) returned %d findings, want 0: %#v", len(records), records)
			}
		})
	}

	disabled := sentinelOneProtectionControlStateEvent("s1-agent-firewall-explicit-disabled", "activity-disabled", "tampered", identityTrajectoryBaseTime)
	if got := sentinelOneProtectionControlState(eventAttributes(disabled)); got != "disabled" {
		t.Fatalf("explicit firewall_enabled=false control state = %q, want disabled", got)
	}
	records, err := rule.Evaluate(context.Background(), runtime, disabled)
	if err != nil {
		t.Fatalf("Evaluate(disabled firewall) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(disabled firewall) returned %d findings, want 1", len(records))
	}
	if got := records[0].Attributes["control_state"]; got != "disabled" {
		t.Fatalf("disabled finding control_state = %q, want disabled", got)
	}
}

func TestSentinelOneProtectionControlTamperingCrossRuntimeRestoreResolvesOpenFinding(t *testing.T) {
	rule := newSentinelOneProtectionControlTamperingRule()
	spec := rule.Spec()
	if spec == nil || strings.TrimSpace(spec.GetId()) == "" {
		t.Fatal("rule must expose a non-empty RuleSpec.Id")
	}
	ruleID := strings.TrimSpace(spec.GetId())
	runtimeA := &cerebrov1.SourceRuntime{Id: "example-sentinelone-agent-runtime-a", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}
	runtimeB := &cerebrov1.SourceRuntime{Id: "example-sentinelone-agent-runtime-b", SourceId: "sentinelone", TenantId: "writer", Config: map[string]string{"family": "agent"}}
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", ruleID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeA.GetId(): runtimeA,
			runtimeB.GetId(): runtimeB,
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	open := sentinelOneProtectionControlStateEvent("s1-agent-control-cross-runtime-open", "activity-cross-runtime-open", "tampered", identityTrajectoryBaseTime)
	replayer.events = []*cerebrov1.EventEnvelope{open}
	firstResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeA.GetId(),
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("first EvaluateSourceRuntimeRules(%q) error = %v", ruleID, err)
	}
	if firstResult == nil || len(firstResult.Evaluations) != 1 {
		t.Fatalf("first result evaluations = %#v, want one", firstResult)
	}
	if got := len(firstResult.Evaluations[0].Findings); got != 1 {
		t.Fatalf("first pass emitted %d findings, want one opening finding", got)
	}
	openFinding := firstResult.Evaluations[0].Findings[0]
	if got := strings.TrimSpace(openFinding.RuntimeID); got != runtimeA.GetId() {
		t.Fatalf("opening finding RuntimeID = %q, want %q", got, runtimeA.GetId())
	}
	if got := strings.TrimSpace(openFinding.Status); got != findingStatusOpen {
		t.Fatalf("opening finding status = %q, want %q", got, findingStatusOpen)
	}

	restore := sentinelOneProtectionControlStateEvent("s1-agent-control-cross-runtime-restore", "activity-cross-runtime-restore", "restored", identityTrajectoryBaseTime.Add(2*time.Minute))
	replayer.events = []*cerebrov1.EventEnvelope{restore}
	secondResult, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeB.GetId(),
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("second EvaluateSourceRuntimeRules(%q) error = %v", ruleID, err)
	}
	if secondResult == nil || len(secondResult.Evaluations) != 1 {
		t.Fatalf("second result evaluations = %#v, want one", secondResult)
	}
	if got := len(secondResult.Evaluations[0].Findings); got != 0 {
		t.Fatalf("restore pass emitted %d findings, want remediation-only pass to emit none", got)
	}

	finalFinding := store.findings[strings.TrimSpace(openFinding.ID)]
	if finalFinding == nil {
		t.Fatalf("persisted opening finding %q not found", openFinding.ID)
	}
	if got := strings.TrimSpace(finalFinding.RuntimeID); got != runtimeA.GetId() {
		t.Fatalf("resolved finding RuntimeID = %q, want original runtime %q", got, runtimeA.GetId())
	}
	if got := strings.TrimSpace(finalFinding.Status); got != findingStatusResolved {
		t.Fatalf("cross-runtime restore final status = %q, want %q", got, findingStatusResolved)
	}
	if got := strings.TrimSpace(finalFinding.StatusReason); got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("cross-runtime restore status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
	if !containsTrimmed(finalFinding.EventIDs, open.GetId()) || !containsTrimmed(finalFinding.EventIDs, restore.GetId()) {
		t.Fatalf("resolved finding EventIDs = %#v, want opening and restore events", finalFinding.EventIDs)
	}
	statusEvent := findStatusChangedPayload(t, appendLog.events, openFinding.ID)
	if got := statusEvent.Reason; got != workflowevents.FindingStatusReasonClosedByCounterEvent {
		t.Fatalf("workflow status reason = %q, want %q", got, workflowevents.FindingStatusReasonClosedByCounterEvent)
	}
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

func sentinelOneProtectionControlUnknownFirewallEvent(id string, includeControlType bool) *cerebrov1.EventEnvelope {
	attributes := map[string]string{
		"agent_id":       "agent-99",
		"computer_name":  "mac-99",
		"activity_id":    "activity-unknown",
		"site_id":        "site-1",
		"site_name":      "Production",
		"group_id":       "group-1",
		"group_name":     "Default",
		"tenant_host":    "writer.sentinelone.example",
		"source_message": "SentinelOne protection control state projection",
	}
	if includeControlType {
		attributes["control_type"] = "firewall"
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "sentinelone",
		Kind:       sentinelOneAgentEntityType,
		OccurredAt: timestamppb.New(identityTrajectoryBaseTime),
		Attributes: attributes,
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
