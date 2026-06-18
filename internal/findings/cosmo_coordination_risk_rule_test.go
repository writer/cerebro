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

func cosmoCoordinationFactEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"key":           "coordination:risk:thread-7",
		"category":      "coordination_risk",
		"source":        "session:thread-7",
		"risk_state":    "active",
		"risk_reason":   "agent coordinated a privileged change across multiple sessions without approval",
		"risk_severity": "high",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "cosmo",
		Kind:       "cosmo.fact",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "cosmo/fact/v1",
		Attributes: base,
	}
}

func TestCosmoCoordinationActiveRiskFixture(t *testing.T) {
	assertRuleFixture(t, newCosmoCoordinationActiveRiskRule(), "testdata/rules/cosmo-coordination-active-risk.json")
}

func TestCosmoCoordinationActiveRiskDerivesStateFromPayload(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cosmo-fact", SourceId: "cosmo", TenantId: "writer", Config: map[string]string{"family": "fact"}}

	active := &cerebrov1.EventEnvelope{
		Id:         "cosmo-payload-active",
		TenantId:   "writer",
		SourceId:   "cosmo",
		Kind:       "cosmo.fact",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "cosmo/fact/v1",
		Attributes: map[string]string{"key": "coordination:risk:thread-9", "category": "coordination_risk", "source": "session:thread-9"},
		Payload:    []byte(`{"key":"coordination:risk:thread-9","category":"coordination_risk","status":"active","risk_reason":"agent reused another tenant credential mid-session","severity":"high"}`),
	}
	records, err := rule.Evaluate(context.Background(), runtime, active)
	if err != nil {
		t.Fatalf("Evaluate(active payload) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(active payload) emitted %d findings, want 1", len(records))
	}
	if got := records[0].Attributes["risk_reason"]; got == "" {
		t.Fatal("risk_reason = empty, want reason derived from payload")
	}
	if got := records[0].Attributes["risk_severity"]; got != "high" {
		t.Fatalf("risk_severity = %q, want high (from payload)", got)
	}

	benign := &cerebrov1.EventEnvelope{
		Id:         "cosmo-payload-benign",
		TenantId:   "writer",
		SourceId:   "cosmo",
		Kind:       "cosmo.fact",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "cosmo/fact/v1",
		Attributes: map[string]string{"key": "preference:tone", "category": "preference", "source": "session:thread-9"},
		Payload:    []byte(`{"key":"preference:tone","category":"preference","status":"active"}`),
	}
	benignRecords, err := rule.Evaluate(context.Background(), runtime, benign)
	if err != nil {
		t.Fatalf("Evaluate(benign) error = %v", err)
	}
	if len(benignRecords) != 0 {
		t.Fatalf("Evaluate(benign) emitted %d findings, want 0 for a non-coordination-risk fact", len(benignRecords))
	}
}

func TestCosmoCoordinationActiveRiskRemediationResolves(t *testing.T) {
	open := cosmoCoordinationFactEvent("cosmo-open", map[string]string{"risk_state": "active"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	resolved := cosmoCoordinationFactEvent("cosmo-resolved", map[string]string{"risk_state": "resolved"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newCosmoCoordinationActiveRiskRule(), open, resolved, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestCosmoCoordinationActiveRiskReopensOnRecurrence(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-cosmo-fact",
		SourceId: "cosmo",
		TenantId: "writer",
		Config:   map[string]string{"family": "fact"},
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

	opened := emitOpen(cosmoCoordinationFactEvent("cosmo-risk-1", map[string]string{"risk_state": "active"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	resolvedEvent := cosmoCoordinationFactEvent("cosmo-resolved", map[string]string{"risk_state": "resolved"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(resolvedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(resolved) = (%q, %v), want non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(cosmoCoordinationFactEvent("cosmo-risk-2", map[string]string{"risk_state": "active"}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
