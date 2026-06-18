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

func cerebroAPIAccessEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"event_type":          "api_access",
		"method":              "GET",
		"route":               "GET /findings",
		"operation_family":    "finding",
		"operation_type":      "read",
		"outcome_result":      "allowed",
		"status_code":         "200",
		"effective_tenant_id": "writer",
		"principal":           "svc@example.com",
		"auth_mode":           "api_key",
		"source_runtime_id":   "writer-cerebro-access",
	}
	for key, value := range attrs {
		if value == "" {
			delete(base, key)
			continue
		}
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "cerebro",
		Kind:       "cerebro.api_access",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "cerebro/api_access/v1",
		Attributes: base,
	}
}

func TestCerebroHighRiskAPIAccessFixture(t *testing.T) {
	assertRuleFixture(t, newCerebroHighRiskAPIAccessRule(), "testdata/rules/cerebro-high-risk-api-access.json")
}

func TestCerebroHighRiskAPIAccessResolvesOnCleanAccess(t *testing.T) {
	open := cerebroAPIAccessEvent("cerebro-access-open", map[string]string{"requested_tenant_id": "tenant-b", "tenant_mismatch": "true"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	clean := cerebroAPIAccessEvent("cerebro-access-clean", map[string]string{"requested_tenant_id": "writer"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newCerebroHighRiskAPIAccessRule(), open, clean, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestCerebroHighRiskAPIAccessResolvesOnRiskDowngrade(t *testing.T) {
	open := cerebroAPIAccessEvent("cerebro-access-open", map[string]string{"risk_level": "critical"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	downgraded := cerebroAPIAccessEvent("cerebro-access-downgraded", map[string]string{"risk_level": "low"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newCerebroHighRiskAPIAccessRule(), open, downgraded, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestCerebroHighRiskAPIAccessReopensOnRecurrence(t *testing.T) {
	rule := newCerebroHighRiskAPIAccessRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-cerebro-access",
		SourceId: "cerebro",
		TenantId: "writer",
		Config:   map[string]string{"family": "access"},
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

	opened := emitOpen(cerebroAPIAccessEvent("cerebro-access-risky-1", map[string]string{"tenant_mismatch": "true", "requested_tenant_id": "tenant-b"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	cleanEvent := cerebroAPIAccessEvent("cerebro-access-cleaned", map[string]string{"requested_tenant_id": "writer"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(cleanEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(clean) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(cerebroAPIAccessEvent("cerebro-access-risky-2", map[string]string{"tenant_mismatch": "true", "requested_tenant_id": "tenant-b"}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
