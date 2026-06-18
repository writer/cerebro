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

func cloudflareZoneEvent(id string, paused string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "cloudflare",
		Kind:       "cloudflare.zone",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "cloudflare/zone/v1",
		Attributes: map[string]string{
			"family":            "zone",
			"zone_id":           "zone-1",
			"account_id":        "acct-1",
			"name":              "example.com",
			"status":            "active",
			"paused":            paused,
			"source_runtime_id": "writer-cloudflare-zone",
		},
	}
}

func TestCloudflareZoneProtectionPausedFixture(t *testing.T) {
	assertRuleFixture(t, newCloudflareZoneProtectionPausedRule(), "testdata/rules/cloudflare-zone-protection-paused.json")
}

func TestCloudflareZoneProtectionPausedRemediationResolves(t *testing.T) {
	open := cloudflareZoneEvent("cf-zone-paused", "true", time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	restored := cloudflareZoneEvent("cf-zone-unpaused", "false", time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newCloudflareZoneProtectionPausedRule(), open, restored, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestCloudflareZoneProtectionPausedReopensOnRecurrence(t *testing.T) {
	rule := newCloudflareZoneProtectionPausedRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-cloudflare-zone",
		SourceId: "cloudflare",
		TenantId: "writer",
		Config:   map[string]string{"family": "zone"},
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

	// Initial active risk opens a finding.
	opened := emitOpen(cloudflareZoneEvent("cf-zone-paused-1", "true", time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	// Remediation produces a counter-event anchor that targets the open finding.
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	restoredEvent := cloudflareZoneEvent("cf-zone-unpaused", "false", time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(restoredEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(restored) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	// Recurrence re-emits the identical finding identity (same fingerprint and
	// id) so the durable reopen path reopens the same finding without duplicate
	// churn rather than minting a new one.
	reopened := emitOpen(cloudflareZoneEvent("cf-zone-paused-2", "true", time.Date(2026, 4, 23, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
