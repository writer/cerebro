package agentplatform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSecurityAgentEvalSuiteFixture(t *testing.T) {
	cases := loadSecurityAgentEvalCases(t)
	report := RunSecurityAgentEvalSuite(cases)
	if report.Version != ContractVersion {
		t.Fatalf("report version = %q, want %q", report.Version, ContractVersion)
	}
	if report.SuiteID != agentEvalSuite().ID {
		t.Fatalf("suite id = %q, want %q", report.SuiteID, agentEvalSuite().ID)
	}
	if report.Total != len(cases) || report.Passed != len(cases) || report.Failed != 0 {
		t.Fatalf("eval report = %+v, failures: %s", report, evalFailureSummary(report))
	}
}

func TestSecurityAgentEvalFixtureCoversSecurityScenarios(t *testing.T) {
	cases := loadSecurityAgentEvalCases(t)
	coveredScenarios := stringSet(SecurityAgentEvalScenarioIDs(cases))
	for _, scenario := range agentEvalSuite().Scenarios {
		if !securityAgentEvalScenario(scenario.ID) {
			continue
		}
		if !coveredScenarios[scenario.ID] {
			t.Fatalf("eval fixture missing scenario %q", scenario.ID)
		}
	}

	coveredStrategies := stringSet(SecurityAgentEvalStrategyIDs(cases))
	for _, strategy := range integrationStrategies() {
		if !securityAgentEvalStrategy(strategy.ID) {
			continue
		}
		if !coveredStrategies[strategy.ID] {
			t.Fatalf("eval fixture missing strategy %q", strategy.ID)
		}
	}
}

func TestRunAgentPlatformEvalSuiteFixture(t *testing.T) {
	cases := loadAgentPlatformEvalCases(t)
	report := RunAgentPlatformEvalSuite(cases)
	if report.Version != ContractVersion {
		t.Fatalf("report version = %q, want %q", report.Version, ContractVersion)
	}
	if report.SuiteID != agentEvalSuite().ID {
		t.Fatalf("suite id = %q, want %q", report.SuiteID, agentEvalSuite().ID)
	}
	if report.Total != len(cases) || report.Passed != len(cases) || report.Failed != 0 {
		t.Fatalf("eval report = %+v, failures: %s", report, platformEvalFailureSummary(report))
	}
}

func TestAgentPlatformEvalFixtureCoversControlPlane(t *testing.T) {
	cases := loadAgentPlatformEvalCases(t)
	coveredScenarios := stringSet(AgentPlatformEvalScenarioIDs(cases))
	for _, scenario := range agentEvalSuite().Scenarios {
		if !coveredScenarios[scenario.ID] {
			t.Fatalf("platform eval fixture missing scenario %q", scenario.ID)
		}
	}

	coveredStrategies := stringSet(AgentPlatformEvalStrategyIDs(cases))
	for _, strategy := range integrationStrategies() {
		if !coveredStrategies[strategy.ID] {
			t.Fatalf("platform eval fixture missing strategy %q", strategy.ID)
		}
	}
}

func TestRunSecurityAgentEvalSuiteReportsFailures(t *testing.T) {
	no := false
	report := RunSecurityAgentEvalSuite([]SecurityAgentEvalCase{{
		ID:         "bad-expectation",
		ScenarioID: "tenant-isolation",
		Request: EvidencePacketRequest{
			TenantID:        "tenant-1",
			ScopeURN:        "urn:cerebro:tenant-1:asset:app",
			CapabilityIDs:   []string{"graph-reasoning"},
			RequestedScopes: []string{ScopeCosmoSecurityRead},
		},
		Expect: SecurityAgentEvalExpectation{
			PreflightEnabled: &no,
			ConfidenceLevel:  "blocked",
		},
	}})
	if report.Total != 1 || report.Passed != 0 || report.Failed != 1 {
		t.Fatalf("report = %+v, want one failed eval", report)
	}
	if len(report.Results) != 1 || len(report.Results[0].Failures) == 0 {
		t.Fatalf("result = %+v, want failure details", report.Results)
	}
}

func loadSecurityAgentEvalCases(t *testing.T) []SecurityAgentEvalCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "security_agent_eval_cases.json"))
	if err != nil {
		t.Fatalf("read eval fixture: %v", err)
	}
	var cases []SecurityAgentEvalCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode eval fixture: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("eval fixture must include cases")
	}
	return cases
}

func loadAgentPlatformEvalCases(t *testing.T) []AgentPlatformEvalCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "agent_platform_eval_cases.json"))
	if err != nil {
		t.Fatalf("read platform eval fixture: %v", err)
	}
	var cases []AgentPlatformEvalCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode platform eval fixture: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("platform eval fixture must include cases")
	}
	return cases
}

func evalFailureSummary(report SecurityAgentEvalReport) string {
	lines := []string{}
	for _, result := range report.Results {
		if result.Passed {
			continue
		}
		lines = append(lines, result.ID+": "+strings.Join(result.Failures, "; "))
	}
	return strings.Join(lines, "\n")
}

func platformEvalFailureSummary(report AgentPlatformEvalReport) string {
	lines := []string{}
	for _, result := range report.Results {
		if result.Passed {
			continue
		}
		lines = append(lines, result.ID+": "+strings.Join(result.Failures, "; "))
	}
	return strings.Join(lines, "\n")
}

func securityAgentEvalScenario(id string) bool {
	switch id {
	case "tenant-isolation", "stale-data-refusal", "prompt-injection-resistance", "remediation-safety", "graph-action-execution-safety", "false-positive-suppression", "ai-governance-posture", "simulation-bounds":
		return true
	default:
		return false
	}
}

func securityAgentEvalStrategy(id string) bool {
	switch id {
	case "a2a-protocol-boundary", "event-subscription-webhooks", "public-idempotency-contract", "graph-ask-regression-evals", "model-provider-comparison":
		return false
	default:
		return true
	}
}
