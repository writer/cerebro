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

func securityToolingMapControlMappingEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "control_mapping",
		"tool_id":           "agent-gateway",
		"tool_name":         "Agent Gateway",
		"control_id":        "CC6.1",
		"control_name":      "Logical access",
		"framework":         "SOC2",
		"coverage":          "partial",
		"source_runtime_id": "writer-security-tooling-map-control-mapping",
	}
	for key, value := range attrs {
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "security_tooling_map",
		Kind:       "security_tooling_map.control_mapping",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "security_tooling_map/control_mapping/v1",
		Attributes: base,
	}
}

func TestSecurityToolingMapControlCoverageGapFixture(t *testing.T) {
	assertRuleFixture(t, newSecurityToolingMapControlCoverageGapRule(), "testdata/rules/security-tooling-map-control-coverage-gap.json")
}

func TestSecurityToolingMapControlCoverageGapCoveredResolves(t *testing.T) {
	open := securityToolingMapControlMappingEvent("stm-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	covered := securityToolingMapControlMappingEvent("stm-covered", map[string]string{"coverage": "full"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newSecurityToolingMapControlCoverageGapRule(), open, covered, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestSecurityToolingMapControlCoverageGapRetiredResolves(t *testing.T) {
	open := securityToolingMapControlMappingEvent("stm-open", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	retired := securityToolingMapControlMappingEvent("stm-retired", map[string]string{"coverage": "none", "control_status": "retired"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newSecurityToolingMapControlCoverageGapRule(), open, retired, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestSecurityToolingMapControlCoverageGapUnknownCoverageDoesNotResolve(t *testing.T) {
	rule := newSecurityToolingMapControlCoverageGapRule()
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	unknown := securityToolingMapControlMappingEvent("stm-unknown", map[string]string{
		"coverage":        "",
		"coverage_status": "",
	}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	if anchor, closes := counterRule.CloseOnEvent(unknown); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(unknown coverage) = (%q, %v), want no close", anchor, closes)
	}
}

func TestSecurityToolingMapControlCoverageGapReopensOnRecurrence(t *testing.T) {
	rule := newSecurityToolingMapControlCoverageGapRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-security-tooling-map-control-mapping",
		SourceId: "security_tooling_map",
		TenantId: "writer",
		Config:   map[string]string{"family": "control_mapping"},
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

	opened := emitOpen(securityToolingMapControlMappingEvent("stm-open-1", map[string]string{}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	coveredEvent := securityToolingMapControlMappingEvent("stm-covered", map[string]string{"coverage": "full"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(coveredEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(covered) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(securityToolingMapControlMappingEvent("stm-open-2", map[string]string{}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}
