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

// The GitHub mirror-rule fixtures below previously asserted findings; the
// rules are now retired (match returns false). The fixture path is kept on
// disk as the canonical event shape that the durable replacement posture
// graph rule will consume as evidence, so we still load it but assert that
// the retired wrapper now emits zero findings for every event in the
// fixture.

func TestGitHubSecretScanningDisabledFixtureRetired(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubSecretScanningDisabledRule(), "testdata/rules/github-secret-scanning-disabled.json")
}

func TestGitHubPushProtectionDisabledFixtureRetired(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubPushProtectionDisabledRule(), "testdata/rules/github-push-protection-disabled.json")
}

func TestGitHubBranchProtectionDisabledFixtureRetired(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubBranchProtectionDisabledRule(), "testdata/rules/github-branch-protection-disabled.json")
}

func TestGitHubRepositoryMadePublicFixtureRetired(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubRepositoryMadePublicRule(), "testdata/rules/github-repository-made-public.json")
}

func TestGitHubSecretScanningAlertCreatedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubSecretScanningAlertCreatedRule(), "testdata/rules/github-secret-scanning-alert-created.json")
}

func TestGitHubSelfHostedRunnerChangeFixtureRetired(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubSelfHostedRunnerChangeRule(), "testdata/rules/github-self-hosted-runner-change.json")
}

func TestGitHubRepositoryCollaboratorAddedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubRepositoryCollaboratorAddedRule(), "testdata/rules/github-repository-collaborator-added.json")
}

func TestGitHubOrganizationOwnerAddedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubOrganizationOwnerAddedRule(), "testdata/rules/github-organization-owner-added.json")
}

func TestGitHubCodeSecurityControlsDisabledFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubCodeSecurityControlsDisabledRule(), "testdata/rules/github-code-security-controls-disabled.json")
}

func TestGitHubOrgAuthControlModifiedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubOrgAuthControlModifiedRule(), "testdata/rules/github-org-auth-control-modified.json")
}

func TestGitHubOrgIPAllowListModifiedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubOrgIPAllowListModifiedRule(), "testdata/rules/github-org-ip-allow-list-modified.json")
}

func TestGitHubAppIntegrationInstalledFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubAppIntegrationInstalledRule(), "testdata/rules/github-app-integration-installed.json")
}

func TestGitHubPersonalAccessTokenCreatedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubPersonalAccessTokenCreatedRule(), "testdata/rules/github-personal-access-token-created.json")
}

func TestGitHubProtectedBranchPolicyOverrideFixtureRetired(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubProtectedBranchPolicyOverrideRule(), "testdata/rules/github-protected-branch-policy-override.json")
}

func TestGitHubRepositoryRulesetModifiedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubRepositoryRulesetModifiedRule(), "testdata/rules/github-repository-ruleset-modified.json")
}

func TestGitHubCriticalResourceDeletedFixture(t *testing.T) {
	assertRetiredEventRuleFixture(t, newGitHubCriticalResourceDeletedRule(), "testdata/rules/github-critical-resource-deleted.json")
}

func TestGitHubWebhookModifiedFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubWebhookModifiedRule(), "testdata/rules/github-webhook-modified.json")
}

func TestGitHubPrivateRepositoryForkingEnabledFixture(t *testing.T) {
	assertRuleFixture(t, newGitHubPrivateRepositoryForkingEnabledRule(), "testdata/rules/github-private-repository-forking-enabled.json")
}

func TestSentinelOneMitigationFailedFixture(t *testing.T) {
	assertRuleFixture(t, newSentinelOneMitigationFailedRule(), "testdata/rules/sentinelone-mitigation-failed.json")
}

func TestSentinelOneAgentDetectOnlyModeFixture(t *testing.T) {
	assertRuleFixture(t, newSentinelOneAgentDetectOnlyModeRule(), "testdata/rules/sentinelone-agent-detect-only-mode.json")
}

func TestSentinelOneProtectionControlTamperingFixture(t *testing.T) {
	assertRuleFixture(t, newSentinelOneProtectionControlTamperingRule(), "testdata/rules/sentinelone-protection-control-tampering.json")
}

func TestSentinelOneRiskyExclusionFixture(t *testing.T) {
	assertRuleFixture(t, newSentinelOneRiskyExclusionRule(), "testdata/rules/sentinelone-risky-exclusion.json")
}

func TestRetiredSentinelOneRulesDoNotEmitFindings(t *testing.T) {
	runtime := &cerebrov1.SourceRuntime{Id: "writer-sentinelone-threat", SourceId: "sentinelone", TenantId: "writer"}
	event := ruleFixtureEvent{
		ID:         "s1-threat-retired",
		TenantID:   "writer",
		SourceID:   "sentinelone",
		Kind:       "sentinelone.threat",
		OccurredAt: "2026-05-09T06:20:00Z",
		SchemaRef:  "sentinelone/threat/v1",
		Attributes: map[string]string{
			"threat_id":         "threat-retired",
			"threat_name":       "Malware Sample",
			"incident_status":   "unresolved",
			"mitigation_status": "not_mitigated",
			"is_infected":       "true",
			"agent_id":          "agent-retired",
		},
	}.proto(t)
	rules := []Rule{
		newRetiredSentinelOneRule(sentinelOneRetiredUnresolvedThreatRuleID, "Retired SentinelOne Unresolved Threat", "finding.sentinelone_unresolved_threat"),
		newRetiredSentinelOneRule(sentinelOneRetiredMaliciousOrFilelessRuleID, "Retired SentinelOne Malicious Or Fileless Threat", "finding.sentinelone_malicious_or_fileless_threat"),
		newRetiredSentinelOneRule(sentinelOneRetiredInfectedEndpointRuleID, "Retired SentinelOne Infected Endpoint", "finding.sentinelone_infected_endpoint"),
	}
	for _, rule := range rules {
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", rule.Spec().GetId(), err)
		}
		if len(records) != 0 {
			t.Fatalf("Evaluate(%q) returned %d findings, want none", rule.Spec().GetId(), len(records))
		}
		retirementRule, ok := rule.(openFindingRetirementRule)
		if !ok || !retirementRule.RetiresOpenFindings() {
			t.Fatalf("RetiresOpenFindings(%q) = false, want true so stale retired findings are resolved", rule.Spec().GetId())
		}
	}
}

func assertRetiredEventRuleFixture(t *testing.T, rule Rule, path string) {
	t.Helper()
	payload, err := os.ReadFile(path) // #nosec G304 -- test fixture path is repository-controlled.
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
	for _, eventFixture := range fixture.Events {
		event := eventFixture.proto(t)
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", event.GetId(), err)
		}
		if len(records) != 0 {
			t.Fatalf("Evaluate(%q) returned %d findings, want none for retired rule", event.GetId(), len(records))
		}
	}
}

func assertRuleFixture(t *testing.T, rule Rule, path string) {
	t.Helper()
	payload, err := os.ReadFile(path) // #nosec G304 -- test fixture path is repository-controlled.
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
