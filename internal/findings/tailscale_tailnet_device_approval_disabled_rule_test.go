package findings

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func tailscaleTailnetEvent(id string, devicesApprovalOn string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "tailscale",
		Kind:       "tailscale.tailnet",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "tailscale/tailnet/v1",
		Attributes: map[string]string{
			"family":              "tailnet",
			"tailnet":             "writer.com",
			"devices_approval_on": devicesApprovalOn,
			"users_approval_on":   "true",
			"source_runtime_id":   "writer-tailscale-tailnet",
		},
	}
}

func TestTailscaleTailnetDeviceApprovalDisabledFixture(t *testing.T) {
	assertRuleFixture(t, newTailscaleTailnetDeviceApprovalDisabledRule(), "testdata/rules/tailscale-tailnet-device-approval-disabled.json")
}

func TestTailscaleTailnetDeviceApprovalRemediationResolves(t *testing.T) {
	open := tailscaleTailnetEvent("ts-tailnet-open", "false", time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	restored := tailscaleTailnetEvent("ts-tailnet-restored", "true", time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newTailscaleTailnetDeviceApprovalDisabledRule(), open, restored, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestTailscaleTailnetDeviceApprovalReopensOnRecurrence(t *testing.T) {
	rule := newTailscaleTailnetDeviceApprovalDisabledRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-tailscale-tailnet",
		SourceId: "tailscale",
		TenantId: "writer",
		Config:   map[string]string{"family": "tailnet"},
	}

	emitOpen := func(event *cerebrov1.EventEnvelope) *ports.FindingRecord {
		t.Helper()
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", event.GetId(), err)
		}
		if len(records) != 1 {
			t.Fatalf("Evaluate(%q) emitted %d findings, want 1", event.GetId(), len(records))
		}
		if got := strings.TrimSpace(records[0].Status); got != findingStatusOpen {
			t.Fatalf("Evaluate(%q) status = %q, want open", event.GetId(), got)
		}
		return records[0]
	}

	opened := emitOpen(tailscaleTailnetEvent("ts-tailnet-disabled-1", "false", time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	restoredEvent := tailscaleTailnetEvent("ts-tailnet-restored", "true", time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(restoredEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(restored) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(tailscaleTailnetEvent("ts-tailnet-disabled-2", "false", time.Date(2026, 4, 23, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}

func TestTailscaleTailnetRustAuthorityMatchesRetiredGoOracle(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-tailscale-tailnet",
		SourceId: "tailscale",
		TenantId: "writer",
		Config:   map[string]string{"family": "tailnet"},
	}
	event := tailscaleTailnetEvent("tailscale-tailnet-approval-off", "false", time.Date(2026, 4, 23, 12, 5, 0, 0, time.UTC))

	got, err := newTailscaleTailnetDeviceApprovalDisabledRule().Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatal(err)
	}
	want := []*ports.FindingRecord{retiredTailscaleGoOracle(event, runtime.GetId())}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Rust authority changed the public finding contract\nRust: %#v\nGo oracle: %#v", got, want)
	}
}

func TestTailscaleTailnetRustAuthorityFailsClosedWithoutGoFallback(t *testing.T) {
	evaluator := &recordingFindingRuleEvaluator{err: errors.New("kernel unavailable")}
	rule := &rustTailscaleRule{evaluator: evaluator}
	runtime := &cerebrov1.SourceRuntime{Id: "runtime-a", SourceId: "tailscale", TenantId: "tenant-a"}
	event := tailscaleTailnetEvent("event-a", "false", time.Date(2026, 4, 23, 12, 5, 0, 0, time.UTC))
	event.TenantId = "tenant-a"

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err == nil {
		t.Fatal("failed Rust authority unexpectedly fell back")
	}
	if len(records) != 0 || evaluator.calls != 1 {
		t.Fatalf("failed Rust authority returned records or invoked another path: records=%#v calls=%d", records, evaluator.calls)
	}
}

func TestTailscaleTailnetRustAuthorityRejectsCrossScopeReplay(t *testing.T) {
	rule := newTailscaleTailnetDeviceApprovalDisabledRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "runtime-a",
		SourceId: "tailscale",
		TenantId: "tenant-a",
		Config:   map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: "workspace-a"},
	}
	event := tailscaleTailnetEvent("event-a", "false", time.Date(2026, 4, 23, 12, 5, 0, 0, time.UTC))
	event.TenantId = "tenant-b"
	event.Attributes["cerebro_application_workspace_id"] = "workspace-b"

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err == nil {
		t.Fatal("cross-tenant and cross-workspace replay unexpectedly succeeded")
	}
	if len(records) != 0 {
		t.Fatalf("cross-scope replay returned findings: %#v", records)
	}
}

type recordingFindingRuleEvaluator struct {
	calls int
	err   error
}

func (e *recordingFindingRuleEvaluator) Evaluate(context.Context, []byte) ([]byte, error) {
	e.calls++
	return nil, e.err
}

func retiredTailscaleGoOracle(event *cerebrov1.EventEnvelope, runtimeID string) *ports.FindingRecord {
	attributes := event.GetAttributes()
	tailnet := strings.TrimSpace(attributes["tailnet"])
	tenantID := strings.TrimSpace(event.GetTenantId())
	tailnetURN := fmt.Sprintf("urn:cerebro:%s:tailscale_tailnet:%s", tenantID, tailnet)
	findingAttributes := map[string]string{
		"tailscale_tailnet_urn":   tailnetURN,
		"tailnet":                 tailnet,
		"devices_approval_on":     strings.TrimSpace(attributes["devices_approval_on"]),
		"users_approval_on":       strings.TrimSpace(attributes["users_approval_on"]),
		"network_flow_logging_on": strings.TrimSpace(attributes["network_flow_logging_on"]),
		"event_id":                strings.TrimSpace(event.GetId()),
		"source_runtime_id":       strings.TrimSpace(attributes[ports.EventAttributeSourceRuntimeID]),
		"primary_resource_urn":    tailnetURN,
	}
	for key, value := range tailscaleTailnetDeviceApprovalDisabledDefinition.AttributeMap() {
		findingAttributes["rule_"+key] = value
	}
	trimEmptyAttributes(findingAttributes)
	observedAt := event.GetOccurredAt().AsTime().UTC()
	fingerprint := hashFindingFingerprint(tailscaleTailnetDeviceApprovalDisabledRuleID, tailnetURN)
	return &ports.FindingRecord{
		ID: fingerprint, Fingerprint: fingerprint, TenantID: tenantID, RuntimeID: strings.TrimSpace(runtimeID),
		RuleID: tailscaleTailnetDeviceApprovalDisabledRuleID, Title: "Tailscale Tailnet Device Approval Disabled",
		Severity: "MEDIUM", Status: findingStatusOpen, Summary: fmt.Sprintf("Tailscale tailnet %s has device approval disabled", tailnet),
		ResourceURNs: []string{tailnetURN}, EventIDs: []string{strings.TrimSpace(event.GetId())},
		CheckID: "tailscale-tailnet-device-approval-disabled-current", CheckName: "Tailscale Tailnet Device Approval Disabled (current state)",
		ControlRefs: cloneFindingControlRefs(tailscaleTailnetDeviceApprovalDisabledDefinition.ControlRefs), Attributes: findingAttributes,
		FirstObservedAt: observedAt, LastObservedAt: observedAt,
	}
}
