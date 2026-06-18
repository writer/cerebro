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

func openAIAdminKeyEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "admin_api_key",
		"api_key_id":        "admin_1",
		"name":              "org-admin-key",
		"key_class":         "admin",
		"privileged":        "true",
		"source_runtime_id": "writer-openai-admin-api-key",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "openai",
		Kind:       "openai.admin_api_key",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "openai/admin_api_key/v1",
		Attributes: base,
	}
}

func TestOpenAIOrphanedPrivilegedAPIKeyFixture(t *testing.T) {
	assertRuleFixture(t, newOpenAIOrphanedPrivilegedAPIKeyRule(), "testdata/rules/openai-orphaned-privileged-api-key.json")
}

func TestOpenAIOrphanedPrivilegedAPIKeyOwnershipResolves(t *testing.T) {
	open := openAIAdminKeyEvent("openai-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	owned := openAIAdminKeyEvent("openai-owned", map[string]string{"owner_id": "user_123", "owner_type": "user"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newOpenAIOrphanedPrivilegedAPIKeyRule(), open, owned, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestOpenAIOrphanedPrivilegedAPIKeyRevocationResolves(t *testing.T) {
	open := openAIAdminKeyEvent("openai-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	revoked := openAIAdminKeyEvent("openai-revoked", map[string]string{"status": "deleted"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newOpenAIOrphanedPrivilegedAPIKeyRule(), open, revoked, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestOpenAIOrphanedPrivilegedAPIKeyReopensOnRecurrence(t *testing.T) {
	rule := newOpenAIOrphanedPrivilegedAPIKeyRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-openai-admin-api-key",
		SourceId: "openai",
		TenantId: "writer",
		Config:   map[string]string{"family": "admin_api_key"},
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

	opened := emitOpen(openAIAdminKeyEvent("openai-orphaned-1", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	ownedEvent := openAIAdminKeyEvent("openai-owned", map[string]string{"owner_id": "user_123", "owner_type": "user"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(ownedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(owned) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(openAIAdminKeyEvent("openai-orphaned-2", map[string]string{}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
