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

func trustedEndpointGateEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"agent_id":          "dev-1",
		"action":            "git_push",
		"source_runtime_id": "writer-trusted-endpoint",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "trusted_endpoint",
		Kind:       "trusted_endpoint.trust_gate_decision",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "trusted_endpoint/trust_gate_decision/v1",
		Attributes: base,
	}
}

func TestTrustedEndpointActiveTrustGateFailureFixture(t *testing.T) {
	assertRuleFixture(t, newTrustedEndpointActiveTrustGateFailureRule(), "testdata/rules/trusted-endpoint-active-trust-gate-failure.json")
}

func TestTrustedEndpointActiveTrustGateFailureRemediationResolves(t *testing.T) {
	open := trustedEndpointGateEvent("te-open", map[string]string{"decision": "deny", "severity": "high"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	resolved := trustedEndpointGateEvent("te-resolved", map[string]string{"decision": "allow"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newTrustedEndpointActiveTrustGateFailureRule(), open, resolved, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestTrustedEndpointActiveTrustGateFailureReopensOnRecurrence(t *testing.T) {
	rule := newTrustedEndpointActiveTrustGateFailureRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-trusted-endpoint",
		SourceId: "trusted_endpoint",
		TenantId: "writer",
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

	opened := emitOpen(trustedEndpointGateEvent("te-deny-1", map[string]string{"decision": "deny", "severity": "high"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	resolvedEvent := trustedEndpointGateEvent("te-allow", map[string]string{"decision": "allow"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(resolvedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(allow) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(trustedEndpointGateEvent("te-deny-2", map[string]string{"decision": "deny", "severity": "high"}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}

func TestTrustedEndpointActiveTrustGateFailureIgnoresActionOutcome(t *testing.T) {
	rule := newTrustedEndpointActiveTrustGateFailureRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-trusted-endpoint", SourceId: "trusted_endpoint", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:         "te-action",
		TenantId:   "writer",
		SourceId:   "trusted_endpoint",
		Kind:       "trusted_endpoint.action_outcome",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "trusted_endpoint/action_outcome/v1",
		Attributes: map[string]string{"agent_id": "dev-1", "action": "remediation", "outcome_result": "success"},
	}
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("action_outcome produced %d findings, want 0 (temporal events must not become durable findings)", len(records))
	}
}
