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

func TestAnalyzeFindingPatternCorrelationsDetectsGitHubSecretExposurePattern(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	staleControlDisabled := compoundRiskFinding("gh-stale-control", githubCodeSecurityControlsDisabledRuleID, "HIGH", "admin@example.com", "example/cerebro", "urn:cerebro:example:github_code_repository:example/cerebro", "repository_secret_scanning.disable")
	staleControlDisabled.FirstObservedAt = base.Add(-72 * time.Hour)
	staleControlDisabled.LastObservedAt = base.Add(-72 * time.Hour)
	staleControlDisabled.EventIDs = []string{"event-stale-control"}
	staleControlDisabled.Attributes["repository"] = "example/cerebro"
	delete(staleControlDisabled.Attributes, "repo")

	controlDisabled := compoundRiskFinding("gh-control", githubCodeSecurityControlsDisabledRuleID, "HIGH", "admin@example.com", "example/cerebro", "urn:cerebro:example:github_code_repository:example/cerebro", "repository_secret_scanning.disable")
	controlDisabled.FirstObservedAt = base
	controlDisabled.LastObservedAt = base
	controlDisabled.EventIDs = []string{"event-control"}
	controlDisabled.Attributes["repository"] = "example/cerebro"
	delete(controlDisabled.Attributes, "repo")

	secretAlert := compoundRiskFinding("gh-secret", githubSecretScanningAlertCreatedRuleID, "HIGH", "admin@example.com", "example/cerebro", "urn:cerebro:example:github_code_repository:example/cerebro", "secret_scanning_alert.create")
	secretAlert.FirstObservedAt = base.Add(30 * time.Minute)
	secretAlert.LastObservedAt = base.Add(30 * time.Minute)
	secretAlert.EventIDs = []string{"event-secret"}
	secretAlert.Attributes["repository"] = "example/cerebro"
	delete(secretAlert.Attributes, "repo")

	correlations := AnalyzeFindingPatternCorrelations([]*ports.FindingRecord{staleControlDisabled, controlDisabled, secretAlert}, FindingExposureAnalysisOptions{
		CorrelationWindow: time.Hour,
	})
	correlation := findingCorrelationByPattern(correlations, "github-code-security-control-disabled-with-secret-alert")
	if correlation == nil {
		t.Fatalf("Correlations = %#v, want GitHub secret exposure pattern", correlations)
	}
	if correlation.Kind != "pattern" {
		t.Fatalf("Correlation.Kind = %q, want pattern", correlation.Kind)
	}
	if correlation.Dimension != compoundRiskKindRepository {
		t.Fatalf("Correlation.Dimension = %q, want repository", correlation.Dimension)
	}
	if got := correlation.Evidence.EventCount; got != 2 {
		t.Fatalf("Correlation.Evidence.EventCount = %d, want 2", got)
	}
	if stringSliceContains(correlation.FindingIDs, staleControlDisabled.ID) {
		t.Fatalf("Correlation.FindingIDs = %#v, want stale control outside window excluded", correlation.FindingIDs)
	}
	if !stringSliceContains(correlation.Reasons, "secret_exposure") {
		t.Fatalf("Correlation.Reasons = %#v, want secret_exposure", correlation.Reasons)
	}
}

func TestAnalyzeFindingPatternCorrelationsDetectsIdentityTamperCredentialHint(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	controlTamper := compoundRiskFinding("identity-control", identityAuthControlLifecycleTamperingRuleID, "HIGH", "admin@writer.com", "", "urn:cerebro:writer:okta_resource:policy:pol-1", "policy.rule.deactivate")
	controlTamper.FirstObservedAt = base
	controlTamper.LastObservedAt = base
	controlTamper.EventIDs = []string{"event-control"}
	controlTamper.Attributes["primary_actor_urn"] = "urn:cerebro:writer:okta_actor:user:00u-admin"
	controlTamper.Attributes["rule_source_id"] = "identity"
	delete(controlTamper.Attributes, "repo")

	credentialChange := compoundRiskFinding("identity-credential", identityAPIOrOAuthCredentialCreatedRuleID, "HIGH", "admin@writer.com", "", "urn:cerebro:writer:okta_resource:api_token:token-1", "system.api_token.create")
	credentialChange.FirstObservedAt = base.Add(30 * time.Minute)
	credentialChange.LastObservedAt = base.Add(30 * time.Minute)
	credentialChange.EventIDs = []string{"event-credential"}
	credentialChange.Attributes["primary_actor_urn"] = "urn:cerebro:writer:okta_actor:user:00u-admin"
	credentialChange.Attributes["rule_source_id"] = "identity"
	delete(credentialChange.Attributes, "repo")

	correlations := AnalyzeFindingPatternCorrelations([]*ports.FindingRecord{controlTamper, credentialChange}, FindingExposureAnalysisOptions{
		CorrelationWindow: time.Hour,
	})
	correlation := findingCorrelationByPattern(correlations, "identity-control-tamper-with-credential-change")
	if correlation == nil {
		t.Fatalf("Correlations = %#v, want runtime identity control/credential hint", correlations)
	}
	if correlation.Kind != "pattern" {
		t.Fatalf("Correlation.Kind = %q, want pattern", correlation.Kind)
	}
	if correlation.Dimension != compoundRiskKindActor {
		t.Fatalf("Correlation.Dimension = %q, want actor", correlation.Dimension)
	}
	if got := correlation.Evidence.EventCount; got != 2 {
		t.Fatalf("Correlation.Evidence.EventCount = %d, want 2", got)
	}
	for _, reason := range []string{"control_tamper", "credential_change"} {
		if !stringSliceContains(correlation.Reasons, reason) {
			t.Fatalf("Correlation.Reasons = %#v, want %q", correlation.Reasons, reason)
		}
	}
}

func TestAnalyzeFindingPatternCorrelationsRequiresSharedCloudResource(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	publicExposure := compoundRiskFinding("cloud-public-a", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_bucket:public-a", "public_network_ingress")
	publicExposure.FirstObservedAt = base
	publicExposure.LastObservedAt = base
	publicExposure.Attributes["rule_source_id"] = "cloud"
	publicExposure.Attributes["internet_exposed"] = "true"

	privilegePath := compoundRiskFinding("cloud-priv-b", cloudPrivilegePathGrantedRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_role:admin-b", "privilege_path_granted")
	privilegePath.FirstObservedAt = base.Add(15 * time.Minute)
	privilegePath.LastObservedAt = base.Add(15 * time.Minute)
	privilegePath.Attributes["rule_source_id"] = "cloud"
	privilegePath.Attributes["privileged"] = "true"

	correlations := AnalyzeFindingPatternCorrelations([]*ports.FindingRecord{publicExposure, privilegePath}, FindingExposureAnalysisOptions{
		CorrelationWindow: time.Hour,
	})
	if correlation := findingCorrelationByPattern(correlations, "cloud-public-exposure-with-privilege-path"); correlation != nil {
		t.Fatalf("unexpected cloud pattern correlation across different resources: %#v", correlation)
	}
}

func findingCorrelationByPattern(correlations []FindingCorrelation, patternID string) *FindingCorrelation {
	for idx := range correlations {
		if correlations[idx].PatternID == patternID {
			return &correlations[idx]
		}
	}
	return nil
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
	finding.Attributes["crown_jewel"] = "true"
	finding.Attributes["data_classification"] = "confidential"

	context := AnalyzeFindingRiskContext(finding, now)
	for _, reason := range []string{"critical_asset", "external_exposure", "known_exploited", "epss_high", "sensitive_data", "crown_jewel", "recent_24h"} {
		if !stringSliceContains(context.Reasons, reason) {
			t.Fatalf("Risk reasons = %#v, want %q", context.Reasons, reason)
		}
	}
	if context.Score < 80 {
		t.Fatalf("Risk score = %d, want generic contextual score >= 80", context.Score)
	}
	if context.EffectiveSeverity != "CRITICAL" {
		t.Fatalf("EffectiveSeverity = %q, want CRITICAL", context.EffectiveSeverity)
	}
	if context.LikelihoodScore < 80 {
		t.Fatalf("LikelihoodScore = %d, want >= 80", context.LikelihoodScore)
	}
	if context.ImpactScore < 80 {
		t.Fatalf("ImpactScore = %d, want >= 80", context.ImpactScore)
	}
	if context.ConfidenceScore == 0 {
		t.Fatal("ConfidenceScore = 0, want populated confidence")
	}
	if context.LikelihoodLevel == "" || context.ImpactLevel == "" || context.RiskModelVersion == "" {
		t.Fatalf("Risk metadata = %#v, want levels and model version", context)
	}
}

func TestEffectiveSeverityFromRiskScore(t *testing.T) {
	for _, tt := range []struct {
		score int
		want  string
	}{
		{score: 95, want: "CRITICAL"},
		{score: 75, want: "HIGH"},
		{score: 50, want: "MEDIUM"},
		{score: 20, want: "LOW"},
		{score: 0, want: ""},
	} {
		if got := EffectiveSeverityFromRiskScore(tt.score); got != tt.want {
			t.Fatalf("EffectiveSeverityFromRiskScore(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestAnalyzeFindingRiskContextUsesSourceSeverityForScoring(t *testing.T) {
	finding := compoundRiskFinding("finding-calibrated", "rule-1", "HIGH", "", "", "urn:cerebro:writer:asset:1", "")
	finding.Attributes[FindingSourceSeverityAttribute] = "LOW"
	context := AnalyzeFindingRiskContext(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC))
	if stringSliceContains(context.Reasons, "severity:HIGH") {
		t.Fatalf("Risk reasons = %#v, want source severity to avoid calibrated severity feedback", context.Reasons)
	}
	if !stringSliceContains(context.Reasons, "severity:LOW") {
		t.Fatalf("Risk reasons = %#v, want source severity LOW", context.Reasons)
	}
}

func TestAnalyzeFindingRiskContextDoesNotTreatNonProductionAsProduction(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	for _, environment := range []string{"nonprod", "non-prod", "preprod", "pre-production", "staging"} {
		finding := compoundRiskFinding("finding-"+environment, "cloud-env", "MEDIUM", "", "", "urn:cerebro:writer:asset:"+environment, "scan.detected")
		finding.Attributes["environment"] = environment
		context := AnalyzeFindingRiskContext(finding, now)
		if stringSliceContains(context.Reasons, "production_environment") {
			t.Fatalf("Risk reasons for environment %q = %#v, want no production_environment", environment, context.Reasons)
		}
	}
	production := compoundRiskFinding("finding-prod", "cloud-env", "MEDIUM", "", "", "urn:cerebro:writer:asset:prod", "scan.detected")
	production.Attributes["environment"] = "writer-prod"
	context := AnalyzeFindingRiskContext(production, now)
	if !stringSliceContains(context.Reasons, "production_environment") {
		t.Fatalf("Risk reasons for production environment = %#v, want production_environment", context.Reasons)
	}
}

func TestAnalyzeFindingRiskContextRecognizesActiveThreatSignals(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	for name, attributes := range map[string]map[string]string{
		"runtime_evidence_type": {
			"evidence_type": "credential_use",
		},
		"runtime_action": {
			"action": "token_exchange",
		},
		"sentinelone_infected": {
			"is_infected":    "true",
			"active_threats": "2",
		},
	} {
		finding := compoundRiskFinding("finding-"+name, "runtime-active-threat", "HIGH", "", "", "urn:cerebro:writer:runtime_evidence:"+name, "")
		finding.Attributes = attributes
		context := AnalyzeFindingRiskContext(finding, now)
		if !stringSliceContains(context.Reasons, "active_threat") {
			t.Fatalf("Risk reasons for %s = %#v, want active_threat", name, context.Reasons)
		}
	}
}

func TestAnalyzeFindingRiskContextDoesNotTreatGenericMalwareClassificationAsActiveThreat(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	finding := compoundRiskFinding("finding-sentinelone-mitigation", "sentinelone-mitigation-failed", "HIGH", "", "", "urn:cerebro:writer:sentinelone_agent:agent-1", "")
	finding.Attributes = map[string]string{"classification": "Malware"}
	context := AnalyzeFindingRiskContext(finding, now)
	if stringSliceContains(context.Reasons, "active_threat") {
		t.Fatalf("Risk reasons = %#v, want no active_threat for generic malware classification", context.Reasons)
	}
}

func TestAnalyzeFindingRiskContextIgnoresExplicitNonSensitiveData(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	for _, classification := range []string{"not_sensitive", "non_sensitive", "no_sensitive_data"} {
		finding := compoundRiskFinding("finding-"+classification, "data-classification", "MEDIUM", "", "", "urn:cerebro:writer:dataset:"+classification, "")
		finding.Attributes = map[string]string{"data_classification": classification}
		context := AnalyzeFindingRiskContext(finding, now)
		if stringSliceContains(context.Reasons, "sensitive_data") {
			t.Fatalf("Risk reasons for %q = %#v, want no sensitive_data", classification, context.Reasons)
		}
	}
}

func TestAnalyzeFindingRiskContextCapsPrivateNetworkWithoutReachability(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	finding := compoundRiskFinding("finding-private", "cloud-private-exposure", "CRITICAL", "", "", "urn:cerebro:writer:aws_instance:i-1", "scan.detected")
	finding.LastObservedAt = now
	finding.Attributes["network_scope"] = "private"
	finding.Attributes["is_kev"] = "true"
	finding.Attributes["epss_score"] = "0.91"
	finding.Attributes["asset_criticality"] = "critical"

	context := AnalyzeFindingRiskContext(finding, now)
	if context.LikelihoodScore > 35 {
		t.Fatalf("LikelihoodScore = %d, want private network cap <= 35 without reachability", context.LikelihoodScore)
	}
	if !stringSliceContains(context.Reasons, "private_network_context") {
		t.Fatalf("Risk reasons = %#v, want private_network_context", context.Reasons)
	}
}

func TestAnalyzeFindingAttackPathsUsesRelationWeights(t *testing.T) {
	finding := compoundRiskFinding("cloud-1", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_secret_store:prod-secrets", "public_network_ingress")
	finding.Attributes["internet_exposed"] = "true"
	paths := AnalyzeFindingAttackPaths([]*ports.FindingRecord{finding}, map[string]*ports.EntityNeighborhood{
		"cloud": {
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
				{URN: "urn:cerebro:writer:aws_user:viewer", EntityType: "aws.user", Label: "viewer"},
				{URN: "urn:cerebro:writer:finding:cloud-1", EntityType: "finding", Label: "cloud-1"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
				{FromURN: "urn:cerebro:writer:aws_user:viewer", Relation: "member_of", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
				{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-1"},
			},
		},
	}, FindingExposureAnalysisOptions{Limit: 10})
	if len(paths) < 2 {
		t.Fatalf("len(paths) = %d, want at least 2", len(paths))
	}
	if got := paths[0].Steps[0].Relation; got != "can_reach" {
		t.Fatalf("top path relation = %q, want can_reach from weighted scoring; paths=%#v", got, paths)
	}
	if !stringSliceContains(paths[0].Reasons, "edge_weight:can_reach:7") {
		t.Fatalf("top path reasons = %#v, want can_reach weight", paths[0].Reasons)
	}
}

func TestRiskDeltaSimulationRemovesPublicExposurePath(t *testing.T) {
	finding := compoundRiskFinding("cloud-public-prod-secrets", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:aws_secret_store:prod-secrets", "public_network_ingress")
	finding.Attributes["internet_exposed"] = "true"
	finding.Attributes["crown_jewel"] = "true"
	neighborhood := map[string]*ports.EntityNeighborhood{
		"cloud": {
			Root: &ports.NeighborhoodNode{URN: "urn:cerebro:writer:aws_secret_store:prod-secrets", EntityType: "aws.secret_store", Label: "prod-secrets"},
			Neighbors: []*ports.NeighborhoodNode{
				{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
				{URN: "urn:cerebro:writer:aws_role:admin", EntityType: "aws.role", Label: "admin"},
				{URN: "urn:cerebro:writer:finding:cloud-public-prod-secrets", EntityType: "finding", Label: "cloud-public-prod-secrets"},
			},
			Relations: []*ports.NeighborhoodRelation{
				{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
				{FromURN: "urn:cerebro:writer:aws_role:admin", Relation: "can_admin", ToURN: "urn:cerebro:writer:aws_secret_store:prod-secrets"},
				{FromURN: "urn:cerebro:writer:aws_secret_store:prod-secrets", Relation: "has_finding", ToURN: "urn:cerebro:writer:finding:cloud-public-prod-secrets"},
			},
		},
	}
	before := AnalyzeFindingAttackPaths([]*ports.FindingRecord{finding}, neighborhood, FindingExposureAnalysisOptions{Limit: 10})
	after := AnalyzeFindingAttackPaths([]*ports.FindingRecord{finding}, cloneNeighborhoodWithoutRelation(neighborhood, "can_reach"), FindingExposureAnalysisOptions{Limit: 10})

	if !attackPathContainsRelation(before, "can_reach") {
		t.Fatalf("before paths = %#v, want public exposure path", before)
	}
	if attackPathContainsRelation(after, "can_reach") {
		t.Fatalf("after paths = %#v, want public exposure path removed", after)
	}
	if len(before) == 0 || len(after) == 0 {
		t.Fatalf("before=%#v after=%#v, want comparable path sets", before, after)
	}
	if sumAttackPathScores(before) <= sumAttackPathScores(after) {
		t.Fatalf("total score before=%d after=%d, want public exposure removal to lower modeled attack-path score", sumAttackPathScores(before), sumAttackPathScores(after))
	}
}

func TestRiskDeltaSimulationPatchVulnerabilityLowersModeledRisk(t *testing.T) {
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	before := compoundRiskFinding("runtime-kev", githubDependabotOpenAlertRuleID, "HIGH", "", "writer/cerebro", "urn:cerebro:writer:container_image:sha256:abc", "scan.detected")
	before.LastObservedAt = now
	before.Attributes["is_kev"] = "true"
	before.Attributes["epss_score"] = "0.91"
	before.Attributes["cvss_score"] = "9.8"
	before.Attributes["exploit_available"] = "true"
	before.Attributes["internet_exposed"] = "true"
	before.Attributes["environment"] = "production"
	before.Attributes["crown_jewel"] = "true"

	after := cloneFindingWithoutAttributes(before, "is_kev", "epss_score", "cvss_score", "exploit_available")
	beforeContext := AnalyzeFindingRiskContext(before, now)
	afterContext := AnalyzeFindingRiskContext(after, now)

	for _, reason := range []string{"known_exploited", "epss_high", "cvss_critical", "exploit_available"} {
		if !stringSliceContains(beforeContext.Reasons, reason) {
			t.Fatalf("before reasons = %#v, want %q", beforeContext.Reasons, reason)
		}
		if stringSliceContains(afterContext.Reasons, reason) {
			t.Fatalf("after reasons = %#v, want %q removed", afterContext.Reasons, reason)
		}
	}
	if beforeContext.Score <= afterContext.Score {
		t.Fatalf("risk score before=%d after=%d, want vulnerability patch simulation to lower modeled risk", beforeContext.Score, afterContext.Score)
	}
	if beforeContext.LikelihoodScore <= afterContext.LikelihoodScore {
		t.Fatalf("likelihood before=%d after=%d, want vulnerability patch simulation to lower likelihood", beforeContext.LikelihoodScore, afterContext.LikelihoodScore)
	}
}

func cloneNeighborhoodWithoutRelation(neighborhoods map[string]*ports.EntityNeighborhood, relation string) map[string]*ports.EntityNeighborhood {
	cloned := make(map[string]*ports.EntityNeighborhood, len(neighborhoods))
	for key, neighborhood := range neighborhoods {
		if neighborhood == nil {
			continue
		}
		copyNeighborhood := *neighborhood
		copyNeighborhood.Relations = nil
		for _, edge := range neighborhood.Relations {
			if edge == nil || edge.Relation == relation {
				continue
			}
			copyEdge := *edge
			copyNeighborhood.Relations = append(copyNeighborhood.Relations, &copyEdge)
		}
		cloned[key] = &copyNeighborhood
	}
	return cloned
}

func attackPathContainsRelation(paths []FindingAttackPath, relation string) bool {
	for _, path := range paths {
		for _, step := range path.Steps {
			if step.Relation == relation {
				return true
			}
		}
	}
	return false
}

func sumAttackPathScores(paths []FindingAttackPath) int {
	total := 0
	for _, path := range paths {
		total += path.Score
	}
	return total
}

func cloneFindingWithoutAttributes(finding *ports.FindingRecord, keys ...string) *ports.FindingRecord {
	cloned := *finding
	cloned.Attributes = make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		cloned.Attributes[key] = value
	}
	for _, key := range keys {
		delete(cloned.Attributes, key)
	}
	return &cloned
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
