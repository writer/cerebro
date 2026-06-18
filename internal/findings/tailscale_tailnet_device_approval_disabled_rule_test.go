package findings

import (
	"context"
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
