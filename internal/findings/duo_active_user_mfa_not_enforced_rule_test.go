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

func duoUserEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "user",
		"user_id":           "user-1",
		"username":          "alice",
		"email":             "alice@writer.com",
		"source_runtime_id": "writer-duo-user",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "duo",
		Kind:       "duo.user",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "duo/user/v1",
		Attributes: base,
	}
}

func TestDuoActiveUserMFANotEnforcedFixture(t *testing.T) {
	assertRuleFixture(t, newDuoActiveUserMFANotEnforcedRule(), "testdata/rules/duo-active-user-mfa-not-enforced.json")
}

func TestDuoActiveUserMFAEnrollmentRemediationResolves(t *testing.T) {
	open := duoUserEvent("duo-open", map[string]string{"status": "active", "is_enrolled": "false"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	enrolled := duoUserEvent("duo-enrolled", map[string]string{"status": "active", "is_enrolled": "true"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newDuoActiveUserMFANotEnforcedRule(), open, enrolled, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestDuoActiveUserMFABypassRemovalResolves(t *testing.T) {
	open := duoUserEvent("duo-open", map[string]string{"status": "bypass", "is_enrolled": "true"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	restored := duoUserEvent("duo-restored", map[string]string{"status": "active", "is_enrolled": "true"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newDuoActiveUserMFANotEnforcedRule(), open, restored, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestDuoActiveUserMFADeprovisionResolves(t *testing.T) {
	open := duoUserEvent("duo-open", map[string]string{"status": "active", "is_enrolled": "false"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC))
	disabled := duoUserEvent("duo-disabled", map[string]string{"status": "disabled", "is_enrolled": "false"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newDuoActiveUserMFANotEnforcedRule(), open, disabled, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestDuoActiveUserMFANotEnforcedReopensOnRecurrence(t *testing.T) {
	rule := newDuoActiveUserMFANotEnforcedRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-duo-user",
		SourceId: "duo",
		TenantId: "writer",
		Config:   map[string]string{"family": "user"},
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

	opened := emitOpen(duoUserEvent("duo-bypass-1", map[string]string{"status": "bypass", "is_enrolled": "true"}, time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	restoredEvent := duoUserEvent("duo-restored", map[string]string{"status": "active", "is_enrolled": "true"}, time.Date(2026, 4, 23, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(restoredEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(restored) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(duoUserEvent("duo-bypass-2", map[string]string{"status": "bypass", "is_enrolled": "true"}, time.Date(2026, 4, 23, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
