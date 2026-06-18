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

func kandjiDeviceEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "device",
		"device_id":         "device-1",
		"device_name":       "writer-mac",
		"source_runtime_id": "writer-kandji-device",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "kandji",
		Kind:       "kandji.device",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "kandji/device/v1",
		Attributes: base,
	}
}

func TestKandjiEndpointDiskEncryptionDisabledFixture(t *testing.T) {
	assertRuleFixture(t, newKandjiEndpointDiskEncryptionDisabledRule(), "testdata/rules/kandji-endpoint-disk-encryption-disabled.json")
}

func TestKandjiEndpointDiskEncryptionRemediationResolves(t *testing.T) {
	open := kandjiDeviceEvent("kandji-open", map[string]string{"mdm_enabled": "true", "filevault_enabled": "false"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	restored := kandjiDeviceEvent("kandji-restored", map[string]string{"mdm_enabled": "true", "filevault_enabled": "true"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newKandjiEndpointDiskEncryptionDisabledRule(), open, restored, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestKandjiEndpointDiskEncryptionDeprovisionResolves(t *testing.T) {
	open := kandjiDeviceEvent("kandji-open", map[string]string{"mdm_enabled": "true", "filevault_enabled": "false"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	offboarded := kandjiDeviceEvent("kandji-offboarded", map[string]string{"mdm_enabled": "false", "filevault_enabled": "false"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newKandjiEndpointDiskEncryptionDisabledRule(), open, offboarded, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestKandjiEndpointDiskEncryptionReopensOnRecurrence(t *testing.T) {
	rule := newKandjiEndpointDiskEncryptionDisabledRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-kandji-device",
		SourceId: "kandji",
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

	opened := emitOpen(kandjiDeviceEvent("kandji-disabled-1", map[string]string{"mdm_enabled": "true", "filevault_enabled": "false"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	restoredEvent := kandjiDeviceEvent("kandji-restored", map[string]string{"mdm_enabled": "true", "filevault_enabled": "true"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(restoredEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(restored) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(kandjiDeviceEvent("kandji-disabled-2", map[string]string{"mdm_enabled": "true", "filevault_enabled": "false"}, time.Date(2026, 4, 23, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
