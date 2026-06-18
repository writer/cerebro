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
		"key":                               "coordination:risk:thread-7",
		"category":                          "coordination_risk",
		"source":                            "session:thread-7",
		"risk_state":                        "active",
		"risk_reason":                       "agent coordinated a privileged change across multiple sessions without approval",
		"risk_severity":                     "high",
		ports.EventAttributeSourceRuntimeID: "writer-cosmo-fact",
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

func TestCosmoCoordinationActiveRiskDoesNotUseGenericValueAsReason(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cosmo-fact", SourceId: "cosmo", TenantId: "writer", Config: map[string]string{"family": "fact"}}
	event := &cerebrov1.EventEnvelope{
		Id:         "cosmo-payload-value-only",
		TenantId:   "writer",
		SourceId:   "cosmo",
		Kind:       "cosmo.fact",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "cosmo/fact/v1",
		Attributes: map[string]string{"key": "coordination:risk:thread-9"},
		Payload:    []byte(`{"key":"coordination:risk:thread-9","category":"coordination_risk","source":"session:thread-9","status":"active","value":"attacker-controlled generic text"}`),
	}
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(value-only payload) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(value-only payload) emitted %d findings, want 1", len(records))
	}
	if got := records[0].Attributes["risk_reason"]; got != "" {
		t.Fatalf("risk_reason = %q, want omitted for generic value payload", got)
	}
}

func TestCosmoCoordinationActiveRiskRemediationResolves(t *testing.T) {
	open := cosmoCoordinationFactEvent("cosmo-open", map[string]string{"risk_state": "active"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	resolved := cosmoCoordinationFactEvent("cosmo-resolved", map[string]string{"risk_state": "resolved"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newCosmoCoordinationActiveRiskRule(), open, resolved, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestCosmoCoordinationActiveRiskCloseRequiresRuntimeAnchor(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{
		Id:       "writer-cosmo-fact",
		SourceId: "cosmo",
		TenantId: "writer",
		Config:   map[string]string{"family": "fact"},
	}
	opened, err := rule.Evaluate(context.Background(), runtime, cosmoCoordinationFactEvent("cosmo-open", map[string]string{"risk_state": "active"}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Evaluate(open) error = %v", err)
	}
	if len(opened) != 1 {
		t.Fatalf("Evaluate(open) emitted %d findings, want 1", len(opened))
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	openAnchor := counterRule.OpenAnchor(opened[0].Attributes)

	otherRuntime := cosmoCoordinationFactEvent("cosmo-resolved-other-runtime", map[string]string{
		"risk_state":                        "resolved",
		ports.EventAttributeSourceRuntimeID: "writer-cosmo-fact-shadow",
	}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	otherAnchor, closes := counterRule.CloseOnEvent(otherRuntime)
	if !closes || otherAnchor == "" {
		t.Fatalf("CloseOnEvent(other runtime) = (%q, %v), want close anchor for the other runtime", otherAnchor, closes)
	}
	if otherAnchor == openAnchor {
		t.Fatalf("CloseOnEvent(other runtime) anchor = %q, want distinct from open anchor", otherAnchor)
	}

	missingRuntime := cosmoCoordinationFactEvent("cosmo-resolved-missing-runtime", map[string]string{"risk_state": "resolved"}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	delete(missingRuntime.Attributes, ports.EventAttributeSourceRuntimeID)
	if anchor, closes := counterRule.CloseOnEvent(missingRuntime); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(missing runtime) = (%q, %v), want no close", anchor, closes)
	}
}

func TestCosmoCoordinationActiveRiskSummaryDoesNotEchoFactStrings(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cosmo-fact", SourceId: "cosmo", TenantId: "writer", Config: map[string]string{"family": "fact"}}
	event := cosmoCoordinationFactEvent("cosmo-hostile-summary", map[string]string{
		"key":    "coordination:risk:<script>alert(1)</script>\n",
		"source": "session:<script>alert(2)</script>\r",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate(hostile summary) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(hostile summary) emitted %d findings, want 1", len(records))
	}
	if got, want := records[0].Summary, "Cosmo agent memory records active coordination risk"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
	if strings.Contains(records[0].Summary, "<script>") || strings.ContainsAny(records[0].Summary, "\r\n\t") {
		t.Fatalf("Summary echoed unsafe fact/session text: %q", records[0].Summary)
	}
}

func TestCosmoCoordinationActiveRiskResourceURNsUseGraphKeys(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-cosmo-fact", SourceId: "cosmo", TenantId: "writer", Config: map[string]string{"family": "fact"}}
	event := cosmoCoordinationFactEvent("cosmo-graph-resource", map[string]string{
		"key":    "coordination:risk:thread-7",
		"source": "session:thread-7",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate() emitted %d findings, want 1", len(records))
	}
	wantFactURN := "urn:cerebro:writer:cosmo_fact:" + cosmoExternalIDKey("coordination:risk:thread-7")
	wantSessionURN := "urn:cerebro:writer:cosmo_session:" + cosmoExternalIDKey("thread-7")
	if got := records[0].ResourceURNs; len(got) != 2 || got[0] != wantFactURN || got[1] != wantSessionURN {
		t.Fatalf("ResourceURNs = %#v, want [%q %q]", got, wantFactURN, wantSessionURN)
	}
	if got := records[0].Attributes["primary_resource_urn"]; got != wantFactURN {
		t.Fatalf("primary_resource_urn = %q, want %q", got, wantFactURN)
	}

	colonURN := cosmoFactResourceURN("writer", "coordination:risk")
	slashURN := cosmoFactResourceURN("writer", "coordination/risk")
	if colonURN == "" || slashURN == "" {
		t.Fatalf("fact URNs = %q/%q, want non-empty values", colonURN, slashURN)
	}
	if colonURN == slashURN {
		t.Fatalf("fact URNs collided at %q", colonURN)
	}
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
