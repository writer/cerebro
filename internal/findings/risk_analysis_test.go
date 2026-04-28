package findings

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

func TestAnalyzeFindingExposureCorrelatesCrossSourceFindings(t *testing.T) {
	base := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	oktaOne := compoundRiskFinding("okta-1", oktaPolicyRuleLifecycleTamperingRuleID, "HIGH", "admin@writer.com", "", "urn:cerebro:writer:okta_resource:policyrule:rule-1", "policy.rule.update")
	oktaOne.RuntimeID = "writer-okta-audit"
	oktaOne.EventIDs = []string{"okta-event-1"}
	oktaOne.FirstObservedAt = base
	oktaOne.LastObservedAt = base
	oktaOne.Attributes["primary_actor_urn"] = "urn:cerebro:writer:okta_actor:user:00u1"
	oktaOne.Attributes["rule_source_id"] = "okta"
	oktaOne.Attributes["actor_privileged"] = "true"
	delete(oktaOne.Attributes, "repo")

	oktaTwo := compoundRiskFinding("okta-2", "identity-okta-admin-factor-reset", "MEDIUM", "admin@writer.com", "", "urn:cerebro:writer:okta_resource:policyrule:rule-1", "user.mfa.factor.reset")
	oktaTwo.RuntimeID = "writer-okta-audit"
	oktaTwo.EventIDs = []string{"okta-event-2"}
	oktaTwo.FirstObservedAt = base.Add(10 * time.Minute)
	oktaTwo.LastObservedAt = base.Add(10 * time.Minute)
	oktaTwo.Attributes["primary_actor_urn"] = "urn:cerebro:writer:okta_actor:user:00u1"
	oktaTwo.Attributes["rule_source_id"] = "okta"
	oktaTwo.Attributes["actor_privileged"] = "true"
	delete(oktaTwo.Attributes, "repo")

	dependabot := compoundRiskFinding("gh-1", githubDependabotOpenAlertRuleID, "HIGH", "", "", "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:7", "")
	dependabot.RuntimeID = "writer-github"
	dependabot.EventIDs = []string{"gh-event-1"}
	dependabot.FirstObservedAt = base.Add(20 * time.Minute)
	dependabot.LastObservedAt = base.Add(20 * time.Minute)
	dependabot.Attributes["repository"] = "writer/cerebro"
	dependabot.Attributes["rule_source_id"] = "github"
	dependabot.Attributes["is_kev"] = "true"
	dependabot.Attributes["epss_score"] = "0.8"
	delete(dependabot.Attributes, "repo")

	dependabotTwo := compoundRiskFinding("gh-2", githubDependabotOpenAlertRuleID, "HIGH", "", "", "urn:cerebro:writer:github_dependabot_alert:writer/cerebro:8", "")
	dependabotTwo.RuntimeID = "writer-github"
	dependabotTwo.EventIDs = []string{"gh-event-2"}
	dependabotTwo.FirstObservedAt = base.Add(25 * time.Minute)
	dependabotTwo.LastObservedAt = base.Add(25 * time.Minute)
	dependabotTwo.Attributes["repository"] = "writer/cerebro"
	dependabotTwo.Attributes["rule_source_id"] = "github"
	dependabotTwo.Attributes["is_kev"] = "true"
	dependabotTwo.Attributes["epss_score"] = "0.8"
	delete(dependabotTwo.Attributes, "repo")

	report := AnalyzeFindingExposure([]*ports.FindingRecord{oktaOne, oktaTwo, dependabot, dependabotTwo}, FindingExposureAnalysisOptions{
		Limit:             10,
		CorrelationWindow: time.Hour,
		GraphNeighborhoods: map[string]*ports.EntityNeighborhood{
			"okta": {
				Root: &ports.NeighborhoodNode{
					URN:        "urn:cerebro:writer:finding:okta-1",
					EntityType: "finding",
					Label:      "okta-1",
				},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:okta_actor:user:00u1", EntityType: "okta.actor", Label: "admin@writer.com"},
					{URN: "urn:cerebro:writer:okta_resource:policyrule:rule-1", EntityType: "okta.policy_rule", Label: "rule-1"},
					{URN: "urn:cerebro:writer:finding:okta-2", EntityType: "finding", Label: "okta-2"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:okta_actor:user:00u1", Relation: "acted_on", ToURN: "urn:cerebro:writer:okta_resource:policyrule:rule-1"},
					{FromURN: "urn:cerebro:writer:okta_resource:policyrule:rule-1", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:okta-1"},
					{FromURN: "urn:cerebro:writer:okta_resource:policyrule:rule-1", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:okta-2"},
				},
			},
		},
	})

	if !compoundRiskGroupsContain(report.CompoundRisks.Sources, "okta") || !compoundRiskGroupsContain(report.CompoundRisks.Sources, "github") {
		t.Fatalf("sources = %#v, want cross-source groups", report.CompoundRisks.Sources)
	}
	if len(report.Correlations) == 0 {
		t.Fatal("Correlations = 0, want generic temporal correlation")
	}
	oktaActorCorrelation := findingCorrelationByDimension(report.Correlations, compoundRiskKindActor, "urn:cerebro:writer:okta_actor:user:00u1")
	if oktaActorCorrelation == nil {
		t.Fatalf("Correlations = %#v, want Okta actor correlation", report.Correlations)
	}
	if got := oktaActorCorrelation.Kind; got != "temporal_ordered" {
		t.Fatalf("Okta actor correlation Kind = %q, want temporal_ordered", got)
	}
	if got := oktaActorCorrelation.Evidence.EventCount; got != 2 {
		t.Fatalf("Okta actor correlation Evidence.EventCount = %d, want 2", got)
	}
	if len(report.AttackPaths) == 0 {
		t.Fatal("AttackPaths = 0, want graph-derived attack path")
	}
	if !findingAttackPathsContainPattern(report.AttackPaths, "okta.actor --acted_on--> okta.policy_rule --has_finding--> finding") {
		t.Fatalf("AttackPaths = %#v, want generic Okta graph path", report.AttackPaths)
	}
}

func findingCorrelationByDimension(correlations []FindingCorrelation, dimension string, key string) *FindingCorrelation {
	for idx := range correlations {
		if correlations[idx].Dimension == dimension && correlations[idx].Key == key {
			return &correlations[idx]
		}
	}
	return nil
}

func findingAttackPathsContainPattern(paths []FindingAttackPath, pattern string) bool {
	for _, path := range paths {
		if path.Pattern == pattern {
			return true
		}
	}
	return false
}

func TestAnalyzeFindingRiskContextUsesGenericSignals(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	finding := compoundRiskFinding("finding-1", "vuln-runtime-open-critical", "HIGH", "", "", "urn:cerebro:writer:container_image:sha256:abc", "scan.detected")
	finding.LastObservedAt = now.Add(-30 * time.Minute)
	finding.EventIDs = []string{"event-1", "event-2"}
	finding.ControlRefs = []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC6.6"}}
	finding.Attributes["asset_criticality"] = "critical"
	finding.Attributes["internet_exposed"] = "true"
	finding.Attributes["is_kev"] = "true"
	finding.Attributes["epss_score"] = "0.72"
	finding.Attributes["data_classification"] = "confidential"

	context := AnalyzeFindingRiskContext(finding, now)
	for _, reason := range []string{"critical_asset", "external_exposure", "known_exploited", "epss_high", "sensitive_data", "recent_24h"} {
		if !stringSliceContains(context.Reasons, reason) {
			t.Fatalf("Risk reasons = %#v, want %q", context.Reasons, reason)
		}
	}
	if context.Score < 80 {
		t.Fatalf("Risk score = %d, want generic contextual score >= 80", context.Score)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
