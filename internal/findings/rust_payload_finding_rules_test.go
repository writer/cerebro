package findings

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

func TestRustPayloadRuleCloseProjectionEnforcesClosedPayloadBounds(t *testing.T) {
	rule := newAureliusPromotedVulnerabilityActiveRule().(*rustPayloadFindingRule)
	runtime := payloadRuleRuntime("aurelius", "writer-aurelius-finding", "workspace-a")
	arrayItems := strings.Repeat("0,", closedJSONMaximumCollectionItems) + "0"
	objectFields := make([]string, 0, closedJSONMaximumCollectionItems+1)
	for index := 0; index <= closedJSONMaximumCollectionItems; index++ {
		objectFields = append(objectFields, fmt.Sprintf(`"field_%d":0`, index))
	}
	invalidUTF8 := append([]byte(`{"state":"fixed","image_digest":"sha256:`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
	tests := map[string][]byte{
		"truncated":       []byte(`{"state":`),
		"null":            []byte(`null`),
		"invalid UTF-8":   invalidUTF8,
		"duplicate":       []byte(`{"state":"fixed","state":"open"}`),
		"oversized":       []byte(`{"state":"` + strings.Repeat("a", closedJSONMaximumBytes) + `"}`),
		"too deep":        []byte(`{"state":[[[[[[[["fixed"]]]]]]]]}`),
		"too many items":  []byte(`{"state":[` + arrayItems + `]}`),
		"too many fields": []byte(`{` + strings.Join(objectFields, ",") + `}`),
		"string too long": []byte(`{"state":"` + strings.Repeat("a", closedJSONMaximumStringBytes+1) + `"}`),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			event := aureliusPromotedVulnerabilityEvent("close-"+name, map[string]string{"state": ""}, time.Now().UTC())
			event.Payload = payload
			if _, _, err := rule.CloseOnEventForRuntimeContext(context.Background(), runtime, event); err == nil {
				t.Fatal("CloseOnEventForRuntimeContext() error = nil, want closed payload rejection")
			}
		})
	}
}

func TestValidateRustFindingResponseRejectsHostOwnedState(t *testing.T) {
	observedAt := time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC)
	request := rustFindingRequest{RuleID: aureliusPromotedVulnerabilityActiveRuleID, RuntimeID: "writer-aurelius-finding", RuntimeTenantID: "writer"}
	base := ports.FindingRecord{
		ID: "finding-1", Fingerprint: "finding-1", TenantID: "writer", RuntimeID: "writer-aurelius-finding", RuleID: aureliusPromotedVulnerabilityActiveRuleID,
		Status: findingStatusOpen, FirstObservedAt: observedAt, LastObservedAt: observedAt,
	}
	if err := validateRustFindingResponse(request, rustFindingResponse{Action: "open", Finding: &base}); err != nil {
		t.Fatalf("valid default response error = %v", err)
	}
	tests := map[string]func(*ports.FindingRecord){
		"workspace": func(finding *ports.FindingRecord) { finding.ApplicationWorkspaceID = "forged" },
		"graph evidence": func(finding *ports.FindingRecord) {
			finding.GraphEvidenceRows = []*cerebrov1.GraphEvidenceRow{}
		},
		"risk": func(finding *ports.FindingRecord) { finding.RiskReasons = []string{} },
		"workflow": func(finding *ports.FindingRecord) {
			finding.Notes = []ports.FindingNote{}
		},
		"tombstone":      func(finding *ports.FindingRecord) { finding.Tombstoned = true },
		"resolved state": func(finding *ports.FindingRecord) { finding.Status = findingStatusResolved },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			finding := base
			mutate(&finding)
			if err := validateRustFindingResponse(request, rustFindingResponse{Action: "open", Finding: &finding}); err == nil {
				t.Fatal("validateRustFindingResponse() error = nil, want host-boundary rejection")
			}
		})
	}
}

func TestRustCosmoRuleNeverCloses(t *testing.T) {
	rule := newCosmoCoordinationActiveRiskRule().(*rustPayloadFindingRule)
	anchor, closes, err := rule.CloseOnEventForRuntimeContext(context.Background(), payloadRuleRuntime("cosmo", "writer-cosmo-fact", "workspace-a"), cosmoCoordinationFactEvent("resolved", map[string]string{"risk_state": "resolved"}, time.Now().UTC()))
	if err != nil || closes || anchor != "" {
		t.Fatalf("CloseOnEventForRuntimeContext() = (%q,%v,%v), want none", anchor, closes, err)
	}
}
