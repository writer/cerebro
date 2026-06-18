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

func TestCerebroHighRiskAPIAccessDeniedDoesNotOpen(t *testing.T) {
	rule := newCerebroHighRiskAPIAccessRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-cerebro-access",
		SourceId: "cerebro",
		TenantId: "writer",
		Config:   map[string]string{"family": "access"},
	}

	cases := []struct {
		name  string
		attrs map[string]string
	}{
		{
			name:  "denied outcome with cross-tenant risk and 2xx status",
			attrs: map[string]string{"outcome_result": "denied", "tenant_mismatch": "true", "requested_tenant_id": "tenant-b", "status_code": "200", "effective_status_code": "200"},
		},
		{
			name:  "blocked outcome with high risk level and 2xx status",
			attrs: map[string]string{"outcome_result": "blocked", "risk_level": "critical", "status_code": "204"},
		},
		{
			name:  "denial reason set with 2xx status and high risk score",
			attrs: map[string]string{"outcome_result": "", "denial_reason": "insufficient_scope", "risk_score": "95", "status_code": "200"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := cerebroAPIAccessEvent("cerebro-access-denied", tc.attrs, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
			records, err := rule.Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate emitted %d findings for a denied access, want 0", len(records))
			}
		})
	}
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

func TestCerebroHighRiskAPIAccessSupportsConnectProcedure(t *testing.T) {
	rule := newCerebroHighRiskAPIAccessRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-cerebro-access",
		SourceId: "cerebro",
		TenantId: "writer",
		Config:   map[string]string{"family": "access"},
	}
	event := cerebroAPIAccessEvent("cerebro-connect-risk", map[string]string{
		"event_type":        "cerebro.v1.FindingsService/GetFinding",
		"route":             "",
		"connect_procedure": "cerebro.v1.FindingsService/GetFinding",
		"risk_level":        "critical",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(connect procedure) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(connect procedure) emitted %d findings, want 1", len(records))
	}
	if got := records[0].Attributes["connect_procedure"]; got != "cerebro.v1.FindingsService/GetFinding" {
		t.Fatalf("connect_procedure attribute = %q, want preserved procedure identity", got)
	}
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

	routeLessCleanEvent := cerebroAPIAccessEvent("cerebro-access-cleaned-route-less", map[string]string{"route": "", "connect_procedure": "", "requested_tenant_id": "writer"}, time.Date(2026, 5, 1, 13, 30, 0, 0, time.UTC))
	routeLessCloseAnchor, routeLessCloses := counterRule.CloseOnEvent(routeLessCleanEvent)
	if !routeLessCloses || routeLessCloseAnchor != closeAnchor {
		t.Fatalf("CloseOnEvent(route-less clean) = (%q, %v), want same principal anchor %q", routeLessCloseAnchor, routeLessCloses, closeAnchor)
	}

	otherPrincipalCleanEvent := cerebroAPIAccessEvent("cerebro-access-other-principal-cleaned", map[string]string{"principal": "other@example.com", "requested_tenant_id": "writer"}, time.Date(2026, 5, 1, 13, 45, 0, 0, time.UTC))
	otherCloseAnchor, otherCloses := counterRule.CloseOnEvent(otherPrincipalCleanEvent)
	if !otherCloses || otherCloseAnchor == "" || otherCloseAnchor == closeAnchor {
		t.Fatalf("CloseOnEvent(other principal clean) = (%q, %v), want distinct non-empty anchor from %q", otherCloseAnchor, otherCloses, closeAnchor)
	}

	reopened := emitOpen(cerebroAPIAccessEvent("cerebro-access-risky-2", map[string]string{"tenant_mismatch": "true", "requested_tenant_id": "tenant-b"}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}

	otherPrincipal := emitOpen(cerebroAPIAccessEvent("cerebro-access-other-principal-risky", map[string]string{"principal": "other@example.com", "tenant_mismatch": "true", "requested_tenant_id": "tenant-b"}, time.Date(2026, 5, 1, 14, 30, 0, 0, time.UTC)))
	if got := strings.TrimSpace(otherPrincipal.Fingerprint); got == "" || got == openFingerprint {
		t.Fatalf("other principal fingerprint = %q, want distinct from %q", got, openFingerprint)
	}
}
