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

func backstageComponentEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "component",
		"name":              "payments",
		"namespace":         "default",
		"kind":              "Component",
		"type":              "service",
		"lifecycle":         "production",
		"criticality":       "tier0",
		"source_runtime_id": "writer-backstage-component",
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
		SourceId:   "backstage",
		Kind:       "backstage.component",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "backstage/component/v1",
		Attributes: base,
	}
}

func TestBackstageCriticalComponentMissingOwnerFixture(t *testing.T) {
	assertRuleFixture(t, newBackstageCriticalComponentMissingOwnerRule(), "testdata/rules/backstage-critical-component-missing-owner.json")
}

func TestBackstageCriticalComponentMissingOwnerOwnershipResolves(t *testing.T) {
	open := backstageComponentEvent("backstage-open", map[string]string{"owner": ""}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	owned := backstageComponentEvent("backstage-owned", map[string]string{"owner": "group:platform/payments"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newBackstageCriticalComponentMissingOwnerRule(), open, owned, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestBackstageCriticalComponentMissingOwnerDowngradeResolves(t *testing.T) {
	open := backstageComponentEvent("backstage-open", map[string]string{"owner": ""}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	downgraded := backstageComponentEvent("backstage-downgraded", map[string]string{"owner": "", "criticality": "low"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newBackstageCriticalComponentMissingOwnerRule(), open, downgraded, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestBackstageCriticalComponentMissingOwnerDecommissionResolves(t *testing.T) {
	open := backstageComponentEvent("backstage-open", map[string]string{"owner": ""}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	retired := backstageComponentEvent("backstage-retired", map[string]string{"owner": "", "lifecycle": "deprecated"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newBackstageCriticalComponentMissingOwnerRule(), open, retired, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestBackstageCriticalComponentMissingOwnerReopensOnRecurrence(t *testing.T) {
	rule := newBackstageCriticalComponentMissingOwnerRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-backstage-component",
		SourceId: "backstage",
		TenantId: "writer",
		Config:   map[string]string{"family": "component"},
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

	opened := emitOpen(backstageComponentEvent("backstage-unowned-1", map[string]string{"owner": ""}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	ownedEvent := backstageComponentEvent("backstage-owned", map[string]string{"owner": "group:platform/payments"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(ownedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(owned) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(backstageComponentEvent("backstage-unowned-2", map[string]string{"owner": ""}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
