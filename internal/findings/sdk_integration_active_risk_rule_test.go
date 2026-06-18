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

func sdkIntegrationPostureEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"integration":       "jira",
		"resource_urn":      "urn:cerebro:writer:runtime:writer-sdk-jira-posture:workspace:writer",
		"resource_label":    "Writer Jira",
		"control":           "sso_enforced",
		"posture_status":    "at_risk",
		"source_runtime_id": "writer-sdk-jira-posture",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "sdk",
		Kind:       "sdk.integration_posture",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "sdk/integration_posture/v1",
		Attributes: base,
	}
}

func TestSDKIntegrationActiveRiskFixture(t *testing.T) {
	assertRuleFixture(t, newSDKIntegrationActiveRiskRule(), "testdata/rules/sdk-integration-active-risk.json")
}

func TestSDKIntegrationActiveRiskRemediationResolves(t *testing.T) {
	open := sdkIntegrationPostureEvent("sdk-open", map[string]string{"posture_status": "at_risk"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	secure := sdkIntegrationPostureEvent("sdk-secure", map[string]string{"posture_status": "secure"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newSDKIntegrationActiveRiskRule(), open, secure, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestSDKIntegrationActiveRiskReopensOnRecurrence(t *testing.T) {
	rule := newSDKIntegrationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-sdk-jira-posture",
		SourceId: "sdk",
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

	opened := emitOpen(sdkIntegrationPostureEvent("sdk-risk-1", map[string]string{"posture_status": "at_risk"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	secureEvent := sdkIntegrationPostureEvent("sdk-secure", map[string]string{"posture_status": "secure"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(secureEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(secure) = (%q, %v), want non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(sdkIntegrationPostureEvent("sdk-risk-2", map[string]string{"posture_status": "at_risk"}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}

func TestSDKIntegrationActiveRiskRejectsReservedTokenDelimiter(t *testing.T) {
	rule := newSDKIntegrationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-sdk-jira-posture",
		SourceId: "sdk",
		TenantId: "writer",
	}
	event := sdkIntegrationPostureEvent("sdk-risk-colon", map[string]string{"integration": "jira:prod"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate() emitted %d findings, want 0", len(records))
	}
}

func TestSDKIntegrationActiveRiskURNKeepsUnscopedResourceDistinct(t *testing.T) {
	scoped := sdkIntegrationPostureFindingURN("writer", "jira", "sso_enforced", "urn:cerebro:writer:foo:bar")
	unscoped := sdkIntegrationPostureFindingURN("writer", "jira", "sso_enforced", "urn:cerebro:foo:bar")
	if scoped == "" || unscoped == "" {
		t.Fatalf("posture URNs = %q/%q, want non-empty values", scoped, unscoped)
	}
	if scoped == unscoped {
		t.Fatalf("tenant-scoped and unscoped resource URNs collided at %q", scoped)
	}
}
