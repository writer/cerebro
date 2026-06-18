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

func pagerDutyServiceEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "service",
		"service_id":        "PS-orphan",
		"name":              "Checkout API",
		"status":            "active",
		"source_runtime_id": "writer-pagerduty-service",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "pagerduty",
		Kind:       "pagerduty.service",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "pagerduty/service/v1",
		Attributes: base,
	}
}

func TestPagerDutyServiceWithoutEscalationFixture(t *testing.T) {
	assertRuleFixture(t, newPagerDutyServiceWithoutEscalationRule(), "testdata/rules/pagerduty-service-without-escalation-policy.json")
}

func TestPagerDutyServiceWithoutEscalationLinkedResolves(t *testing.T) {
	open := pagerDutyServiceEvent("pagerduty-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	linked := pagerDutyServiceEvent("pagerduty-linked", map[string]string{"escalation_policy_id": "PE1"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newPagerDutyServiceWithoutEscalationRule(), open, linked, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestPagerDutyServiceWithoutEscalationDisabledResolves(t *testing.T) {
	open := pagerDutyServiceEvent("pagerduty-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	disabled := pagerDutyServiceEvent("pagerduty-disabled", map[string]string{"status": "disabled"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newPagerDutyServiceWithoutEscalationRule(), open, disabled, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestPagerDutyServiceWithoutEscalationReopensOnRecurrence(t *testing.T) {
	rule := newPagerDutyServiceWithoutEscalationRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-pagerduty-service",
		SourceId: "pagerduty",
		TenantId: "writer",
		Config:   map[string]string{"family": "service"},
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

	opened := emitOpen(pagerDutyServiceEvent("pagerduty-open-1", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	linkedEvent := pagerDutyServiceEvent("pagerduty-linked", map[string]string{"escalation_policy_id": "PE1"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(linkedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(escalation linked) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(pagerDutyServiceEvent("pagerduty-open-2", map[string]string{}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
