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

func slackUserEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "user",
		"user_id":           "U-admin",
		"team_id":           "T1",
		"name":              "alice",
		"real_name":         "Alice Admin",
		"is_admin":          "true",
		"has_2fa":           "false",
		"deleted":           "false",
		"source_runtime_id": "writer-slack-user",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "slack",
		Kind:       "slack.user",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "slack/user/v1",
		Attributes: base,
	}
}

func TestSlackPrivilegedUserWithoutMFAFixture(t *testing.T) {
	assertRuleFixture(t, newSlackPrivilegedUserWithoutMFARule(), "testdata/rules/slack-privileged-user-without-mfa.json")
}

func TestSlackPrivilegedUserWithoutMFAEnablementResolves(t *testing.T) {
	open := slackUserEvent("slack-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	enabled := slackUserEvent("slack-mfa-enabled", map[string]string{"has_2fa": "true"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newSlackPrivilegedUserWithoutMFARule(), open, enabled, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestSlackPrivilegedUserWithoutMFARoleRemovalResolves(t *testing.T) {
	open := slackUserEvent("slack-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	demoted := slackUserEvent("slack-demoted", map[string]string{"is_admin": "false"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newSlackPrivilegedUserWithoutMFARule(), open, demoted, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestSlackPrivilegedUserWithoutMFADeactivationResolves(t *testing.T) {
	open := slackUserEvent("slack-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	deleted := slackUserEvent("slack-deleted", map[string]string{"deleted": "true"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newSlackPrivilegedUserWithoutMFARule(), open, deleted, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestSlackPrivilegedUserWithoutMFAMissingVisibilityIsUnknown(t *testing.T) {
	rule := newSlackPrivilegedUserWithoutMFARule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-slack-user",
		SourceId: "slack",
		TenantId: "writer",
		Config:   map[string]string{"family": "user"},
	}
	unknown := slackUserEvent("slack-mfa-unknown", map[string]string{
		"has_2fa": "",
		"has_mfa": "",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	records, err := rule.Evaluate(context.Background(), runtime, unknown)
	if err != nil {
		t.Fatalf("Evaluate(unknown MFA) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(unknown MFA) emitted %d findings, want 0", len(records))
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	if anchor, closes := counterRule.CloseOnEvent(unknown); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(unknown MFA) = (%q, %v), want no close", anchor, closes)
	}
}

func TestSlackPrivilegedUserWithoutMFAReopensOnRecurrence(t *testing.T) {
	rule := newSlackPrivilegedUserWithoutMFARule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-slack-user",
		SourceId: "slack",
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

	opened := emitOpen(slackUserEvent("slack-open-1", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	enabledEvent := slackUserEvent("slack-mfa-enabled", map[string]string{"has_2fa": "true"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(enabledEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(mfa enabled) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(slackUserEvent("slack-open-2", map[string]string{}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
