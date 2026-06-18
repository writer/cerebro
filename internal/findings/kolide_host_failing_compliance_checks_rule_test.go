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

func kolideDeviceEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "device",
		"device_id":         "device-1",
		"device_name":       "writer-host",
		"source_runtime_id": "writer-kolide-device",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "kolide",
		Kind:       "kolide.device",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "kolide/device/v1",
		Attributes: base,
	}
}

func TestKolideHostFailingComplianceChecksFixture(t *testing.T) {
	assertRuleFixture(t, newKolideHostFailingComplianceChecksRule(), "testdata/rules/kolide-host-failing-compliance-checks.json")
}

func TestKolideHostFailingComplianceChecksRemediationResolves(t *testing.T) {
	open := kolideDeviceEvent("kolide-open", map[string]string{"registered": "true", "failure_count": "2"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	resolved := kolideDeviceEvent("kolide-resolved", map[string]string{"registered": "true", "failure_count": "0"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newKolideHostFailingComplianceChecksRule(), open, resolved, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestKolideHostFailingComplianceChecksDeprovisionResolves(t *testing.T) {
	open := kolideDeviceEvent("kolide-open", map[string]string{"registered": "true", "failure_count": "2"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	offboarded := kolideDeviceEvent("kolide-offboarded", map[string]string{"registered": "false", "failure_count": "2"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newKolideHostFailingComplianceChecksRule(), open, offboarded, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestKolideHostFailingComplianceChecksReopensOnRecurrence(t *testing.T) {
	rule := newKolideHostFailingComplianceChecksRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-kolide-device",
		SourceId: "kolide",
		TenantId: "writer",
		Config:   map[string]string{"family": "device"},
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

	opened := emitOpen(kolideDeviceEvent("kolide-failing-1", map[string]string{"registered": "true", "failure_count": "2"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	resolvedEvent := kolideDeviceEvent("kolide-resolved", map[string]string{"registered": "true", "failure_count": "0"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(resolvedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(resolved) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(kolideDeviceEvent("kolide-failing-2", map[string]string{"registered": "true", "failure_count": "4"}, time.Date(2026, 4, 23, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
