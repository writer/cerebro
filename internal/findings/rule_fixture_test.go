package findings

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type ruleFixture struct {
	RuleID           string                   `json:"rule_id"`
	Runtime          ruleFixtureRuntime       `json:"runtime"`
	Events           []ruleFixtureEvent       `json:"events"`
	ExpectedFindings []ruleFixtureFinding     `json:"expected_findings"`
	ExpectedNoMatch  []ruleFixtureExpectation `json:"expected_no_match,omitempty"`
}

type ruleFixtureRuntime struct {
	ID       string            `json:"id"`
	SourceID string            `json:"source_id"`
	TenantID string            `json:"tenant_id"`
	Config   map[string]string `json:"config,omitempty"`
}

type ruleFixtureEvent struct {
	ID         string            `json:"id"`
	TenantID   string            `json:"tenant_id"`
	SourceID   string            `json:"source_id"`
	Kind       string            `json:"kind"`
	OccurredAt string            `json:"occurred_at"`
	SchemaRef  string            `json:"schema_ref"`
	Attributes map[string]string `json:"attributes"`
}

type ruleFixtureFinding struct {
	RuleID     string            `json:"rule_id"`
	Severity   string            `json:"severity"`
	Status     string            `json:"status"`
	Summary    string            `json:"summary,omitempty"`
	PolicyID   string            `json:"policy_id,omitempty"`
	EventIDs   []string          `json:"event_ids,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type ruleFixtureExpectation struct {
	EventID string `json:"event_id"`
	Reason  string `json:"reason,omitempty"`
}

func TestOktaPolicyRuleLifecycleTamperingFixture(t *testing.T) {
	assertRuleFixture(t, newOktaPolicyRuleLifecycleTamperingRule(), "testdata/rules/identity-okta-policy-rule-lifecycle-tampering.json")
}

func TestGitHubDependabotOpenAlertFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubDependabotOpenAlertRule(), "testdata/rules/github-dependabot-open-alert.json")
}

func assertRuleFixture(t *testing.T, rule Rule, path string) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %q: %v", path, err)
	}
	var fixture ruleFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("unmarshal fixture %q: %v", path, err)
	}
	if rule == nil {
		t.Fatal("rule = nil")
	}
	if got := rule.Spec().GetId(); got != fixture.RuleID {
		t.Fatalf("RuleSpec().Id = %q, want %q", got, fixture.RuleID)
	}
	runtime := fixture.Runtime.proto()
	findings := []*ports.FindingRecord{}
	eventsByID := map[string]ruleFixtureEvent{}
	for _, eventFixture := range fixture.Events {
		eventsByID[eventFixture.ID] = eventFixture
		event := eventFixture.proto(t)
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", event.GetId(), err)
		}
		findings = append(findings, records...)
	}
	if got := len(findings); got != len(fixture.ExpectedFindings) {
		t.Fatalf("len(findings) = %d, want %d", got, len(fixture.ExpectedFindings))
	}
	for index, expected := range fixture.ExpectedFindings {
		assertFixtureFinding(t, findings[index], expected)
	}
	for _, expectation := range fixture.ExpectedNoMatch {
		eventFixture, ok := eventsByID[expectation.EventID]
		if !ok {
			t.Fatalf("expected_no_match event_id %q is not present in fixture events", expectation.EventID)
		}
		records, err := rule.Evaluate(context.Background(), runtime, eventFixture.proto(t))
		if err != nil {
			t.Fatalf("Evaluate(%q) for expected_no_match error = %v", expectation.EventID, err)
		}
		if len(records) != 0 {
			t.Fatalf("Evaluate(%q) returned %d findings, want no match", expectation.EventID, len(records))
		}
	}
}

func (f ruleFixtureRuntime) proto() *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{
		Id:       f.ID,
		SourceId: f.SourceID,
		TenantId: f.TenantID,
		Config:   f.Config,
	}
}

func (f ruleFixtureEvent) proto(t *testing.T) *cerebrov1.EventEnvelope {
	t.Helper()
	occurredAt, err := time.Parse(time.RFC3339, f.OccurredAt)
	if err != nil {
		t.Fatalf("parse event %q occurred_at: %v", f.ID, err)
	}
	return &cerebrov1.EventEnvelope{
		Id:         f.ID,
		TenantId:   f.TenantID,
		SourceId:   f.SourceID,
		Kind:       f.Kind,
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  f.SchemaRef,
		Attributes: f.Attributes,
	}
}

func assertFixtureFinding(t *testing.T, finding *ports.FindingRecord, expected ruleFixtureFinding) {
	t.Helper()
	if finding == nil {
		t.Fatal("finding = nil")
	}
	if expected.RuleID != "" && finding.RuleID != expected.RuleID {
		t.Fatalf("Finding.RuleID = %q, want %q", finding.RuleID, expected.RuleID)
	}
	if expected.Severity != "" && finding.Severity != expected.Severity {
		t.Fatalf("Finding.Severity = %q, want %q", finding.Severity, expected.Severity)
	}
	if expected.Status != "" && finding.Status != expected.Status {
		t.Fatalf("Finding.Status = %q, want %q", finding.Status, expected.Status)
	}
	if expected.Summary != "" && finding.Summary != expected.Summary {
		t.Fatalf("Finding.Summary = %q, want %q", finding.Summary, expected.Summary)
	}
	if expected.PolicyID != "" && finding.PolicyID != expected.PolicyID {
		t.Fatalf("Finding.PolicyID = %q, want %q", finding.PolicyID, expected.PolicyID)
	}
	if len(expected.EventIDs) != 0 {
		if got := strings.Join(finding.EventIDs, ","); got != strings.Join(expected.EventIDs, ",") {
			t.Fatalf("Finding.EventIDs = %q, want %q", got, strings.Join(expected.EventIDs, ","))
		}
	}
	for key, want := range expected.Attributes {
		if got := finding.Attributes[key]; got != want {
			t.Fatalf("Finding.Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}
