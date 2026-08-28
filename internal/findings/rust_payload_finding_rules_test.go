package findings

import (
	"context"
	"errors"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type failingFindingRuleEvaluator struct{ err error }

func (e failingFindingRuleEvaluator) Evaluate(context.Context, []byte) ([]byte, error) {
	return nil, e.err
}

type staticFindingRuleEvaluator struct{ output []byte }

func (e staticFindingRuleEvaluator) Evaluate(context.Context, []byte) ([]byte, error) {
	return append([]byte(nil), e.output...), nil
}

func payloadRuleRuntime(sourceID, runtimeID, workspaceID string) *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{Id: runtimeID, SourceId: sourceID, TenantId: "writer", Config: map[string]string{ports.SourceRuntimeApplicationWorkspaceIDConfigKey: workspaceID}}
}

func TestRustPayloadRulesUseOneFailClosedEvaluator(t *testing.T) {
	rule := newRustPayloadFindingRule(aureliusPromotedVulnerabilityActiveDefinition, aureliusRustDefinitionDigest, "aurelius/finding/v1")
	rule.evaluator = failingFindingRuleEvaluator{err: errors.New("invocation failed")}
	records, err := rule.Evaluate(context.Background(), payloadRuleRuntime("aurelius", "writer-aurelius-finding", "workspace-a"), aureliusPromotedVulnerabilityEvent("event-1", nil, time.Now().UTC()))
	if !errors.Is(err, errRustFindingAuthorityUnavailable) {
		t.Fatalf("Evaluate() error = %v, want typed Rust authority failure", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate() records = %d, want no write candidate", len(records))
	}
}

func TestRustPayloadRulesRejectMalformedAndDuplicateResponses(t *testing.T) {
	for _, output := range [][]byte{
		[]byte(`{"schema_version":"v1"`),
		[]byte(`{"schema_version":"v1","schema_version":"v2"}`),
		[]byte(`{"schema_version":"v1","unknown":true}`),
	} {
		rule := newRustPayloadFindingRule(aureliusPromotedVulnerabilityActiveDefinition, aureliusRustDefinitionDigest, "aurelius/finding/v1")
		rule.evaluator = staticFindingRuleEvaluator{output: output}
		if _, err := rule.Evaluate(context.Background(), payloadRuleRuntime("aurelius", "writer-aurelius-finding", "workspace-a"), aureliusPromotedVulnerabilityEvent("event-1", nil, time.Now().UTC())); err == nil {
			t.Fatalf("Evaluate(%q) error = nil, want closed response rejection", output)
		}
	}
}

func TestRustPayloadRulesPreservePublicIdentityAcrossWorkspaceEnvelope(t *testing.T) {
	event := aureliusPromotedVulnerabilityEvent("event-1", nil, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC))
	rule := newAureliusPromotedVulnerabilityActiveRule()
	first, err := rule.Evaluate(context.Background(), payloadRuleRuntime("aurelius", "writer-aurelius-finding", "workspace-a"), event)
	if err != nil || len(first) != 1 {
		t.Fatalf("first Evaluate() len=%d err=%v", len(first), err)
	}
	second, err := rule.Evaluate(context.Background(), payloadRuleRuntime("aurelius", "writer-aurelius-finding", "workspace-b"), event)
	if err != nil || len(second) != 1 {
		t.Fatalf("second Evaluate() len=%d err=%v", len(second), err)
	}
	if first[0].ID != second[0].ID || first[0].Fingerprint != second[0].Fingerprint {
		t.Fatal("trusted workspace changed the public finding identity")
	}
	if first[0].ApplicationWorkspaceID != "workspace-a" || second[0].ApplicationWorkspaceID != "workspace-b" {
		t.Fatalf("workspace envelope = %q/%q", first[0].ApplicationWorkspaceID, second[0].ApplicationWorkspaceID)
	}
}

func TestRustPayloadRuleCloseAdmissionAndAnchorParity(t *testing.T) {
	rule := newAureliusPromotedVulnerabilityActiveRule().(*rustPayloadFindingRule)
	runtime := payloadRuleRuntime("aurelius", "writer-aurelius-finding", "workspace-a")
	opened, err := rule.Evaluate(context.Background(), runtime, aureliusPromotedVulnerabilityEvent("open", nil, time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)))
	if err != nil || len(opened) != 1 {
		t.Fatalf("open len=%d err=%v", len(opened), err)
	}
	openAnchor, err := rule.OpenAnchorForFindingContext(context.Background(), opened[0])
	if err != nil || openAnchor == "" {
		t.Fatalf("open anchor=%q err=%v", openAnchor, err)
	}
	closed := aureliusPromotedVulnerabilityEvent("close", map[string]string{"state": "fixed", "severity": ""}, time.Date(2026, 5, 22, 13, 0, 0, 0, time.UTC))
	closed.Payload = []byte(`{"state":`)
	closeAnchor, closes, err := rule.CloseOnEventForRuntimeContext(context.Background(), runtime, closed)
	if err != nil || !closes || closeAnchor != openAnchor {
		t.Fatalf("close=(%q,%v,%v), want anchor %q", closeAnchor, closes, err, openAnchor)
	}
	duplicate := aureliusPromotedVulnerabilityEvent("duplicate", map[string]string{"state": ""}, time.Now().UTC())
	duplicate.Payload = []byte(`{"state":"fixed","state":"open"}`)
	if _, _, err := rule.CloseOnEventForRuntimeContext(context.Background(), runtime, duplicate); err == nil {
		t.Fatal("duplicate close payload error = nil")
	}
}

func TestRustCosmoRuleNeverCloses(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule().(*rustPayloadFindingRule)
	anchor, closes, err := rule.CloseOnEventForRuntimeContext(context.Background(), payloadRuleRuntime("cosmo", "writer-cosmo-fact", "workspace-a"), cosmoCoordinationFactEvent("resolved", map[string]string{"risk_state": "resolved"}, time.Now().UTC()))
	if err != nil || closes || anchor != "" {
		t.Fatalf("CloseOnEventForRuntimeContext() = (%q,%v,%v), want none", anchor, closes, err)
	}
}
