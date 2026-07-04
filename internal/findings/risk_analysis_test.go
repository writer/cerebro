package findings

import (
	"fmt"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
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

func TestEnrichFindingRiskUsesConnectorValidationConfidence(t *testing.T) {
	now := time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC)
	base := compoundRiskFinding("connector-confidence", "rule-1", "HIGH", "", "", "urn:cerebro:writer:runtime_asset:1", "")
	base.EventIDs = []string{"event-1"}
	base.FirstObservedAt = now
	base.LastObservedAt = now

	validatedInput := cloneFindingWithoutAttributes(base)
	generatedInput := cloneFindingWithoutAttributes(base)
	validated := enrichFindingRisk(validatedInput, &cerebrov1.SourceRuntime{
		Id:       "writer-okta-users",
		SourceId: "okta",
		TenantId: "writer",
		Config:   map[string]string{"family": "users"},
	}, now)
	generated := enrichFindingRisk(generatedInput, &cerebrov1.SourceRuntime{
		Id:       "writer-unvalidated-users",
		SourceId: "unvalidated_connector",
		TenantId: "writer",
		Config:   map[string]string{"family": "users"},
	}, now)

	if validated.ConfidenceScore <= generated.ConfidenceScore {
		t.Fatalf("validated confidence = %d, generated = %d, want validated higher", validated.ConfidenceScore, generated.ConfidenceScore)
	}
	if validated.Attributes[FindingConnectorValidationGradeAttribute] != "fixture_validated" {
		t.Fatalf("validated grade attr = %q, want fixture_validated", validated.Attributes[FindingConnectorValidationGradeAttribute])
	}
	if !stringSliceContainsPrefix(validated.RiskReasons, "connector_validated") {
		t.Fatalf("validated reasons = %#v, want connector_validated", validated.RiskReasons)
	}
	if !stringSliceContainsPrefix(generated.RiskReasons, "connector_unvalidated") {
		t.Fatalf("generated reasons = %#v, want connector_unvalidated", generated.RiskReasons)
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

func TestAnalyzeFindingPatternCorrelationsDetectsDependabotControlPattern(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	controlDisabled := compoundRiskFinding("gh-control", githubCodeSecurityControlsDisabledRuleID, "HIGH", "admin@example.com", "example/cerebro", "urn:cerebro:example:github_code_repository:example/cerebro", "repository_code_scanning.disable")
	controlDisabled.FirstObservedAt = base
	controlDisabled.LastObservedAt = base
	controlDisabled.EventIDs = []string{"event-control"}
	controlDisabled.Attributes["repository"] = "example/cerebro"
	controlDisabled.Attributes["repo_owner"] = "appsec"
	delete(controlDisabled.Attributes, "repo")

	dependabot := compoundRiskFinding("gh-dependabot", githubDependabotOpenAlertRuleID, "HIGH", "", "example/cerebro", "urn:cerebro:example:github_dependabot_alert:example/cerebro:7", "dependabot_alert.open")
	dependabot.FirstObservedAt = base.Add(30 * time.Minute)
	dependabot.LastObservedAt = base.Add(30 * time.Minute)
	dependabot.EventIDs = []string{"event-dependabot"}
	dependabot.Attributes["repository"] = "example/cerebro"
	delete(dependabot.Attributes, "repo")

	correlations := AnalyzeFindingPatternCorrelations([]*ports.FindingRecord{controlDisabled, dependabot}, FindingExposureAnalysisOptions{
		CorrelationWindow: time.Hour,
	})
	correlation := findingCorrelationByPattern(correlations, "github-code-security-control-disabled-with-dependabot-alert")
	if correlation == nil {
		t.Fatalf("Correlations = %#v, want GitHub Dependabot control pattern", correlations)
	}
	if correlation.Dimension != compoundRiskKindRepository {
		t.Fatalf("Correlation.Dimension = %q, want repository", correlation.Dimension)
	}
	if !stringSliceContains(correlation.Reasons, "vulnerable_dependency") {
		t.Fatalf("Correlation.Reasons = %#v, want vulnerable_dependency", correlation.Reasons)
	}
}

func TestAnalyzeFindingPatternCorrelationsDetectsContainerImagePatternUsingNormalizedImageURN(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	trivy := compoundRiskFinding("trivy-1", trivyImageVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:trivy_vulnerability:sha256:abc:CVE-2026-1:openssl", "scan.detected")
	trivy.FirstObservedAt = base
	trivy.LastObservedAt = base
	trivy.EventIDs = []string{"event-trivy"}
	trivy.Attributes["trivy_image_urn"] = "urn:cerebro:writer:trivy_image:sha256:abc"
	trivy.Attributes["image_digest"] = "sha256:abc"
	trivy.Attributes["image_uri"] = "registry.example/app@sha256:abc"

	aurelius := compoundRiskFinding("aurelius-1", aureliusPromotedVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:aurelius_vulnerability:vuln-1", "promoted")
	aurelius.FirstObservedAt = base.Add(20 * time.Minute)
	aurelius.LastObservedAt = base.Add(20 * time.Minute)
	aurelius.EventIDs = []string{"event-aurelius"}
	aurelius.Attributes["container_image_urn"] = "urn:cerebro:writer:container_image_digest:sha256:abc"
	aurelius.Attributes["aurelius_image_urn"] = "urn:cerebro:writer:container_image_digest:sha256:abc"
	aurelius.Attributes["image_digest"] = "sha256:abc"
	aurelius.Attributes["image_uri"] = "registry.example/app@sha256:abc"

	correlations := AnalyzeFindingPatternCorrelations([]*ports.FindingRecord{trivy, aurelius}, FindingExposureAnalysisOptions{
		CorrelationWindow: time.Hour,
	})
	correlation := findingCorrelationByPattern(correlations, "container-image-promoted-vulnerability-with-trivy-scan")
	if correlation == nil {
		t.Fatalf("Correlations = %#v, want container image pattern", correlations)
	}
	if correlation.Dimension != compoundRiskKindContainerImage {
		t.Fatalf("Correlation.Dimension = %q, want container_image", correlation.Dimension)
	}
	if got := correlation.Key; got != "urn:cerebro:writer:container_image_digest:sha256:abc" {
		t.Fatalf("Correlation.Key = %q, want normalized container image urn", got)
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

func TestAnalyzeFindingPatternCorrelationsDetectsRuntimeThreatExposurePattern(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	publicExposure := compoundRiskFinding("cloud-public", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:kubernetes_workload:prod/api", "public_network_ingress")
	publicExposure.FirstObservedAt = base
	publicExposure.LastObservedAt = base
	publicExposure.EventIDs = []string{"event-cloud"}
	publicExposure.Attributes["internet_exposed"] = "true"

	runtimeThreat := compoundRiskFinding("runtime-threat", runtimeActiveThreatEvidenceRuleID, "HIGH", "", "", "urn:cerebro:writer:kubernetes_workload:prod/api", "credential_use")
	runtimeThreat.FirstObservedAt = base.Add(15 * time.Minute)
	runtimeThreat.LastObservedAt = base.Add(15 * time.Minute)
	runtimeThreat.EventIDs = []string{"event-runtime"}
	runtimeThreat.Attributes["evidence_type"] = "credential_use"
	runtimeThreat.Attributes["verdict"] = "active"

	correlations := AnalyzeFindingPatternCorrelations([]*ports.FindingRecord{publicExposure, runtimeThreat}, FindingExposureAnalysisOptions{
		CorrelationWindow: time.Hour,
	})
	correlation := findingCorrelationByPattern(correlations, "runtime-active-threat-with-public-exposure")
	if correlation == nil {
		t.Fatalf("Correlations = %#v, want runtime threat exposure hint", correlations)
	}
	if correlation.Dimension != compoundRiskKindResource {
		t.Fatalf("Correlation.Dimension = %q, want resource", correlation.Dimension)
	}
	for _, reason := range []string{"active_threat", "external_exposure"} {
		if !stringSliceContains(correlation.Reasons, reason) {
			t.Fatalf("Correlation.Reasons = %#v, want %q", correlation.Reasons, reason)
		}
	}
}

func TestAnalyzeFindingPatternCorrelationsRejectsMismatchedDimensionsAndWindows(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)

	secretControl := compoundRiskFinding("gh-secret-control", githubCodeSecurityControlsDisabledRuleID, "HIGH", "admin@example.com", "example/cerebro", "urn:cerebro:example:github_code_repository:example/cerebro", "repository_secret_scanning.disable")
	secretControl.FirstObservedAt = base
	secretControl.LastObservedAt = base
	secretControl.Attributes["repository"] = "example/cerebro"
	delete(secretControl.Attributes, "repo")
	secretAlertOtherRepo := compoundRiskFinding("gh-secret-alert", githubSecretScanningAlertCreatedRuleID, "HIGH", "", "example/other", "urn:cerebro:example:github_code_repository:example/other", "secret_scanning_alert.create")
	secretAlertOtherRepo.FirstObservedAt = base.Add(30 * time.Minute)
	secretAlertOtherRepo.LastObservedAt = base.Add(30 * time.Minute)
	secretAlertOtherRepo.Attributes["repository"] = "example/other"
	delete(secretAlertOtherRepo.Attributes, "repo")

	dependabotControl := compoundRiskFinding("gh-dependabot-control", githubCodeSecurityControlsDisabledRuleID, "HIGH", "admin@example.com", "example/cerebro", "urn:cerebro:example:github_code_repository:example/cerebro", "repository_code_scanning.disable")
	dependabotControl.FirstObservedAt = base
	dependabotControl.LastObservedAt = base
	dependabotControl.Attributes["repository"] = "example/cerebro"
	delete(dependabotControl.Attributes, "repo")
	dependabotOtherRepo := compoundRiskFinding("gh-dependabot-other", githubDependabotOpenAlertRuleID, "HIGH", "", "example/other", "urn:cerebro:example:github_dependabot_alert:example/other:7", "dependabot_alert.open")
	dependabotOtherRepo.FirstObservedAt = base.Add(30 * time.Minute)
	dependabotOtherRepo.LastObservedAt = base.Add(30 * time.Minute)
	dependabotOtherRepo.Attributes["repository"] = "example/other"
	delete(dependabotOtherRepo.Attributes, "repo")
	dependabotLate := compoundRiskFinding("gh-dependabot-late", githubDependabotOpenAlertRuleID, "HIGH", "", "example/cerebro", "urn:cerebro:example:github_dependabot_alert:example/cerebro:8", "dependabot_alert.open")
	dependabotLate.FirstObservedAt = base.Add(25 * time.Hour)
	dependabotLate.LastObservedAt = base.Add(25 * time.Hour)
	dependabotLate.Attributes["repository"] = "example/cerebro"
	delete(dependabotLate.Attributes, "repo")

	trivy := compoundRiskFinding("trivy-1", trivyImageVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:trivy_vulnerability:sha256:abc:CVE-2026-1:openssl", "scan.detected")
	trivy.FirstObservedAt = base
	trivy.LastObservedAt = base
	trivy.Attributes["image_digest"] = "sha256:abc"
	aureliusOtherImage := compoundRiskFinding("aurelius-1", aureliusPromotedVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:aurelius_vulnerability:vuln-1", "promoted")
	aureliusOtherImage.FirstObservedAt = base.Add(20 * time.Minute)
	aureliusOtherImage.LastObservedAt = base.Add(20 * time.Minute)
	aureliusOtherImage.Attributes["container_image_urn"] = "urn:cerebro:writer:container_image_digest:sha256:def"
	aureliusOtherImage.Attributes["image_digest"] = "sha256:def"

	controlTamper := compoundRiskFinding("identity-control", identityAuthControlLifecycleTamperingRuleID, "HIGH", "admin@writer.com", "", "urn:cerebro:writer:okta_resource:policy:pol-1", "policy.rule.deactivate")
	controlTamper.FirstObservedAt = base
	controlTamper.LastObservedAt = base
	controlTamper.Attributes["primary_actor_urn"] = "urn:cerebro:writer:okta_actor:user:00u-admin"
	delete(controlTamper.Attributes, "repo")
	credentialOtherActor := compoundRiskFinding("identity-credential", identityAPIOrOAuthCredentialCreatedRuleID, "HIGH", "other@writer.com", "", "urn:cerebro:writer:okta_resource:api_token:token-1", "system.api_token.create")
	credentialOtherActor.FirstObservedAt = base.Add(30 * time.Minute)
	credentialOtherActor.LastObservedAt = base.Add(30 * time.Minute)
	credentialOtherActor.Attributes["primary_actor_urn"] = "urn:cerebro:writer:okta_actor:user:00u-other"
	delete(credentialOtherActor.Attributes, "repo")

	publicExposure := compoundRiskFinding("cloud-public", cloudPublicResourceExposureRuleID, "HIGH", "", "", "urn:cerebro:writer:kubernetes_workload:prod/api", "public_network_ingress")
	publicExposure.FirstObservedAt = base
	publicExposure.LastObservedAt = base
	publicExposure.Attributes["internet_exposed"] = "true"
	runtimeThreatOtherResource := compoundRiskFinding("runtime-threat", runtimeActiveThreatEvidenceRuleID, "HIGH", "", "", "urn:cerebro:writer:kubernetes_workload:prod/worker", "credential_use")
	runtimeThreatOtherResource.FirstObservedAt = base.Add(15 * time.Minute)
	runtimeThreatOtherResource.LastObservedAt = base.Add(15 * time.Minute)
	runtimeThreatOtherResource.Attributes["evidence_type"] = "credential_use"

	for _, tt := range []struct {
		name      string
		patternID string
		records   []*ports.FindingRecord
	}{
		{
			name:      "secret control and alert require same repository",
			patternID: "github-code-security-control-disabled-with-secret-alert",
			records:   []*ports.FindingRecord{secretControl, secretAlertOtherRepo},
		},
		{
			name:      "dependabot control and alert require same repository",
			patternID: "github-code-security-control-disabled-with-dependabot-alert",
			records:   []*ports.FindingRecord{dependabotControl, dependabotOtherRepo},
		},
		{
			name:      "dependabot control and alert require shared window",
			patternID: "github-code-security-control-disabled-with-dependabot-alert",
			records:   []*ports.FindingRecord{dependabotControl, dependabotLate},
		},
		{
			name:      "container pattern requires same normalized image",
			patternID: "container-image-promoted-vulnerability-with-trivy-scan",
			records:   []*ports.FindingRecord{trivy, aureliusOtherImage},
		},
		{
			name:      "identity hint requires same actor",
			patternID: "identity-control-tamper-with-credential-change",
			records:   []*ports.FindingRecord{controlTamper, credentialOtherActor},
		},
		{
			name:      "runtime threat exposure requires same resource",
			patternID: "runtime-active-threat-with-public-exposure",
			records:   []*ports.FindingRecord{publicExposure, runtimeThreatOtherResource},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			correlations := AnalyzeFindingPatternCorrelations(tt.records, FindingExposureAnalysisOptions{
				CorrelationWindow: time.Hour,
			})
			if correlation := findingCorrelationByPattern(correlations, tt.patternID); correlation != nil {
				t.Fatalf("unexpected pattern correlation: %#v", correlation)
			}
		})
	}
}

func TestAnalyzeFindingExposureReturnsActionCandidatesForCorrelatedFindings(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	trivy := compoundRiskFinding("trivy-1", trivyImageVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:trivy_vulnerability:sha256:abc:CVE-2026-1:openssl", "scan.detected")
	trivy.FirstObservedAt = base
	trivy.LastObservedAt = base
	trivy.EventIDs = []string{"event-trivy"}
	trivy.Attributes["image_digest"] = "sha256:abc"
	trivy.Attributes["service_owner"] = "containers"

	aurelius := compoundRiskFinding("aurelius-1", aureliusPromotedVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:aurelius_vulnerability:vuln-1", "promoted")
	aurelius.FirstObservedAt = base.Add(20 * time.Minute)
	aurelius.LastObservedAt = base.Add(20 * time.Minute)
	aurelius.EventIDs = []string{"event-aurelius"}
	aurelius.Attributes["container_image_urn"] = "urn:cerebro:writer:container_image_digest:sha256:abc"
	aurelius.Attributes["image_digest"] = "sha256:abc"

	report := AnalyzeFindingExposure([]*ports.FindingRecord{trivy, aurelius}, FindingExposureAnalysisOptions{
		Limit:             10,
		CorrelationWindow: time.Hour,
	})
	if len(report.ActionCandidates) == 0 {
		t.Fatalf("ActionCandidates = 0, want correlated remediation candidate; report=%#v", report)
	}
	candidate := report.ActionCandidates[0]
	if candidate.ActionType != "remediate_promoted_container_vulnerability" {
		t.Fatalf("ActionType = %q, want remediate_promoted_container_vulnerability", candidate.ActionType)
	}
	if candidate.TargetURN != "urn:cerebro:writer:container_image_digest:sha256:abc" {
		t.Fatalf("TargetURN = %q, want normalized container image urn", candidate.TargetURN)
	}
	if candidate.Owner != "containers" {
		t.Fatalf("Owner = %q, want containers", candidate.Owner)
	}
	for _, reason := range []string{"action_type:remediate_promoted_container_vulnerability", "source:correlation:pattern", "pattern:container-image-promoted-vulnerability-with-trivy-scan"} {
		if !stringSliceContains(candidate.Reasons, reason) {
			t.Fatalf("Reasons = %#v, want %q", candidate.Reasons, reason)
		}
	}
	for _, factor := range []string{"score:", "finding_count:2", "rule_count:2", "action_type:remediate_promoted_container_vulnerability", "source:correlation:pattern"} {
		if !stringSliceContainsPrefix(candidate.RankFactors, factor) {
			t.Fatalf("RankFactors = %#v, want prefix %q", candidate.RankFactors, factor)
		}
	}
	if got := candidate.Evidence.FindingCount; got != 2 {
		t.Fatalf("Evidence.FindingCount = %d, want 2", got)
	}
	for _, ruleID := range []string{trivyImageVulnerabilityActiveRuleID, aureliusPromotedVulnerabilityActiveRuleID} {
		if !stringSliceContains(candidate.RuleIDs, ruleID) {
			t.Fatalf("RuleIDs = %#v, want %q", candidate.RuleIDs, ruleID)
		}
	}
}

func TestBuildFindingActionCandidatesUsesIndependentLimitAndRankOrder(t *testing.T) {
	first := compoundRiskFinding("first-1", runtimeActiveThreatEvidenceRuleID, "HIGH", "", "", "urn:cerebro:writer:kubernetes_workload:prod/api", "credential_use")
	second := compoundRiskFinding("second-1", githubDependabotOpenAlertRuleID, "HIGH", "", "", "urn:cerebro:writer:github_dependabot_alert:example/cerebro:7", "dependabot_alert.open")
	correlations := []FindingCorrelation{
		{
			Kind:       "pattern",
			PatternID:  "lower",
			Dimension:  compoundRiskKindResource,
			Key:        "urn:cerebro:writer:github_dependabot_alert:example/cerebro:7",
			Score:      50,
			FindingIDs: []string{second.ID},
			RuleIDs:    []string{githubDependabotOpenAlertRuleID},
			Reasons:    []string{"vulnerable_dependency"},
			Evidence:   newFindingEvidenceBundle([]*ports.FindingRecord{second}),
		},
		{
			Kind:       "pattern",
			PatternID:  "higher",
			Dimension:  compoundRiskKindResource,
			Key:        "urn:cerebro:writer:kubernetes_workload:prod/api",
			Score:      90,
			FindingIDs: []string{first.ID},
			RuleIDs:    []string{runtimeActiveThreatEvidenceRuleID},
			Reasons:    []string{"active_threat"},
			Evidence:   newFindingEvidenceBundle([]*ports.FindingRecord{first}),
		},
	}

	candidates := buildFindingActionCandidates([]*ports.FindingRecord{first, second}, correlations, nil, FindingExposureAnalysisOptions{
		Limit:                1,
		ActionCandidateLimit: 2,
	})
	if got := len(candidates); got != 2 {
		t.Fatalf("len(candidates) = %d, want action candidate limit to override global limit", got)
	}
	if candidates[0].TargetURN != "urn:cerebro:writer:kubernetes_workload:prod/api" {
		t.Fatalf("first candidate TargetURN = %q, want highest score first", candidates[0].TargetURN)
	}
	if !stringSliceContains(candidates[0].Reasons, "active_threat") {
		t.Fatalf("first candidate Reasons = %#v, want active_threat", candidates[0].Reasons)
	}
	if !stringSliceContains(candidates[0].RankFactors, "score:90") {
		t.Fatalf("first candidate RankFactors = %#v, want score:90", candidates[0].RankFactors)
	}
}

func TestAnalyzeFindingExposureUsesIndependentCorrelationAndAttackPathLimits(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	resourceURN := "urn:cerebro:writer:aws_secret_store:prod-secrets"
	publicExposure := compoundRiskFinding("cloud-public", cloudPublicResourceExposureRuleID, "HIGH", "admin@example.com", "writer/cerebro", resourceURN, "public_network_ingress")
	publicExposure.RuntimeID = "writer-cloud"
	publicExposure.FirstObservedAt = base
	publicExposure.LastObservedAt = base
	publicExposure.EventIDs = []string{"event-public"}
	publicExposure.Attributes["rule_source_id"] = "cloud"
	publicExposure.Attributes["internet_exposed"] = "true"

	privilegePath := compoundRiskFinding("cloud-privilege", cloudPrivilegePathGrantedRuleID, "HIGH", "admin@example.com", "writer/cerebro", resourceURN, "privilege_path_granted")
	privilegePath.RuntimeID = "writer-cloud"
	privilegePath.FirstObservedAt = base.Add(15 * time.Minute)
	privilegePath.LastObservedAt = privilegePath.FirstObservedAt
	privilegePath.EventIDs = []string{"event-privilege"}
	privilegePath.Attributes["rule_source_id"] = "cloud"
	privilegePath.Attributes["privileged"] = "true"

	report := AnalyzeFindingExposure([]*ports.FindingRecord{publicExposure, privilegePath}, FindingExposureAnalysisOptions{
		Limit:             1,
		CorrelationLimit:  2,
		AttackPathLimit:   2,
		CorrelationWindow: time.Hour,
		GraphNeighborhoods: map[string]*ports.EntityNeighborhood{
			"cloud": {
				Root: &ports.NeighborhoodNode{URN: resourceURN, EntityType: "aws.secret_store", Label: "prod-secrets"},
				Neighbors: []*ports.NeighborhoodNode{
					{URN: "urn:cerebro:writer:aws_public_principal:public_internet", EntityType: "aws.public_principal", Label: "public internet"},
					{URN: "urn:cerebro:writer:aws_role:admin", EntityType: "aws.role", Label: "admin"},
				},
				Relations: []*ports.NeighborhoodRelation{
					{FromURN: "urn:cerebro:writer:aws_public_principal:public_internet", Relation: "can_reach", ToURN: resourceURN},
					{FromURN: "urn:cerebro:writer:aws_role:admin", Relation: "can_admin", ToURN: resourceURN},
				},
			},
		},
	})
	if got := len(report.Correlations); got != 2 {
		t.Fatalf("len(Correlations) = %d, want correlation limit to override global limit", got)
	}
	if got := len(report.AttackPaths); got != 2 {
		t.Fatalf("len(AttackPaths) = %d, want attack path limit to override global limit", got)
	}
}

func TestAnalyzeFindingExposureBuildsActionCandidatesBeforeApplyingOutputLimit(t *testing.T) {
	base := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	noTargetFindings := []*ports.FindingRecord{
		compoundRiskFinding("high-1", "high-risk-actor-rule-1", "CRITICAL", "admin@example.com", "", "", "disable_control"),
		compoundRiskFinding("high-2", "high-risk-actor-rule-2", "CRITICAL", "admin@example.com", "", "", "credential_use"),
		compoundRiskFinding("high-3", "high-risk-actor-rule-3", "CRITICAL", "admin@example.com", "", "", "public_expose"),
	}
	for idx, finding := range noTargetFindings {
		finding.RuntimeID = "runtime-no-target"
		finding.FirstObservedAt = base.Add(time.Duration(idx) * time.Minute)
		finding.LastObservedAt = finding.FirstObservedAt
		finding.EventIDs = []string{fmt.Sprintf("event-high-%d", idx)}
		finding.ResourceURNs = nil
		delete(finding.Attributes, "primary_resource_urn")
		finding.Attributes["asset_criticality"] = "critical"
		finding.Attributes["crown_jewel"] = "true"
		finding.Attributes["privileged"] = "true"
	}
	trivy := compoundRiskFinding("trivy-1", trivyImageVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:trivy_vulnerability:sha256:abc:CVE-2026-1:openssl", "scan.detected")
	trivy.FirstObservedAt = base.Add(time.Hour)
	trivy.LastObservedAt = trivy.FirstObservedAt
	trivy.EventIDs = []string{"event-trivy"}
	trivy.Attributes["image_digest"] = "sha256:abc"
	trivy.ResourceURNs = []string{"urn:cerebro:writer:container_image_digest:sha256:abc"}
	trivy.Attributes["primary_resource_urn"] = "urn:cerebro:writer:container_image_digest:sha256:abc"

	aurelius := compoundRiskFinding("aurelius-1", aureliusPromotedVulnerabilityActiveRuleID, "HIGH", "", "", "urn:cerebro:writer:aurelius_vulnerability:vuln-1", "promoted")
	aurelius.FirstObservedAt = base.Add(time.Hour + 20*time.Minute)
	aurelius.LastObservedAt = aurelius.FirstObservedAt
	aurelius.EventIDs = []string{"event-aurelius"}
	aurelius.Attributes["container_image_urn"] = "urn:cerebro:writer:container_image_digest:sha256:abc"
	aurelius.Attributes["image_digest"] = "sha256:abc"
	aurelius.ResourceURNs = []string{"urn:cerebro:writer:container_image_digest:sha256:abc"}
	aurelius.Attributes["primary_resource_urn"] = "urn:cerebro:writer:container_image_digest:sha256:abc"

	records := append(noTargetFindings, trivy, aurelius)
	report := AnalyzeFindingExposure(records, FindingExposureAnalysisOptions{
		Limit:             1,
		CorrelationWindow: 24 * time.Hour,
	})
	if got := len(report.Correlations); got != 1 {
		t.Fatalf("len(Correlations) = %d, want output limit applied", got)
	}
	if len(report.ActionCandidates) == 0 {
		t.Fatalf("ActionCandidates = 0, want candidate built from unbounded correlations; report=%#v", report)
	}
	candidate := report.ActionCandidates[0]
	if candidate.TargetURN != "urn:cerebro:writer:container_image_digest:sha256:abc" {
		t.Fatalf("TargetURN = %q, want normalized container image urn", candidate.TargetURN)
	}
	if candidate.ActionType != "remediate_promoted_container_vulnerability" {
		t.Fatalf("ActionType = %q, want remediate_promoted_container_vulnerability", candidate.ActionType)
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
	byID := map[string]ports.FindingRiskFactor{}
	for _, factor := range context.Factors {
		byID[factor.FactorID] = factor
	}
	for _, factorID := range []string{"critical_asset", "external_exposure", "known_exploited", "epss_high"} {
		factor := byID[factorID]
		if factor.FactorID == "" {
			t.Fatalf("risk factors = %#v, want factor %q", context.Factors, factorID)
		}
		if len(factor.EvidenceRefs) == 0 {
			t.Fatalf("risk factor %q evidence refs empty: %#v", factorID, factor)
		}
		if factor.SuppressionScope != "factor:"+factorID {
			t.Fatalf("risk factor %q suppression scope = %q", factorID, factor.SuppressionScope)
		}
	}
}

func TestAnalyzeFindingRiskContextUsesMITREContext(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	finding := compoundRiskFinding("finding-mitre", "policy-mitre", "MEDIUM", "", "", "urn:cerebro:writer:security_tool:agent-gateway", "control.coverage")
	finding.Attributes["mitre_attack_tactics"] = "Defense Evasion"
	finding.Attributes["mitre_attack_techniques"] = "T1562"
	finding.Attributes["coverage_status"] = "gap"

	context := AnalyzeFindingRiskContext(finding, now)
	for _, reason := range []string{"mitre_attack_context", "mitre_high_pressure_tactic", "mitre_coverage_gap"} {
		if !stringSliceContains(context.Reasons, reason) {
			t.Fatalf("Risk reasons = %#v, want %q", context.Reasons, reason)
		}
	}
	if context.ConfidenceScore <= 85 {
		t.Fatalf("ConfidenceScore = %d, want MITRE confidence context to increase baseline", context.ConfidenceScore)
	}
}

func TestFindingRiskFactorsDoNotChangeFindingFingerprint(t *testing.T) {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	baseline := compoundRiskFinding("finding-risk-factor-baseline", "identity-risk", "HIGH", "", "", "urn:cerebro:writer:okta_user:00u1", "")
	baseline.Fingerprint = "stable-user-fingerprint"
	baseline.LastObservedAt = now
	baseline.Attributes["internet_exposed"] = "true"
	enrichedBaseline := enrichFindingRisk(baseline, nil, now)

	changed := compoundRiskFinding("finding-risk-factor-changed", "identity-risk", "HIGH", "", "", "urn:cerebro:writer:okta_user:00u1", "")
	changed.Fingerprint = "stable-user-fingerprint"
	changed.LastObservedAt = now
	changed.Attributes["internet_exposed"] = "false"
	enrichedChanged := enrichFindingRisk(changed, nil, now)

	if enrichedBaseline.Fingerprint != "stable-user-fingerprint" || enrichedChanged.Fingerprint != "stable-user-fingerprint" {
		t.Fatalf("fingerprints = %q/%q, want stable-user-fingerprint", enrichedBaseline.Fingerprint, enrichedChanged.Fingerprint)
	}
	if !stringSliceContains(enrichedBaseline.RiskReasons, "external_exposure") {
		t.Fatalf("baseline risk reasons = %#v, want external_exposure", enrichedBaseline.RiskReasons)
	}
	if stringSliceContains(enrichedChanged.RiskReasons, "external_exposure") {
		t.Fatalf("changed risk reasons = %#v, want no external_exposure", enrichedChanged.RiskReasons)
	}
	if enrichedBaseline.Attributes[FindingRiskFactorsAttribute] == enrichedChanged.Attributes[FindingRiskFactorsAttribute] {
		t.Fatalf("risk factor JSON did not change with factor input: %q", enrichedBaseline.Attributes[FindingRiskFactorsAttribute])
	}
	if factors := ParseRiskFactors(enrichedBaseline.Attributes[FindingRiskFactorsAttribute]); len(factors) == 0 {
		t.Fatalf("ParseRiskFactors(%q) returned no factors", enrichedBaseline.Attributes[FindingRiskFactorsAttribute])
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

func TestAnalyzeFindingRiskContextWithConfigUsesCustomThresholds(t *testing.T) {
	config := DefaultRiskScoringConfig("writer")
	config.Thresholds.Critical = 95
	config.Thresholds.High = 80
	config.Thresholds.Medium = 60
	finding := compoundRiskFinding("finding-custom-thresholds", "rule-1", "HIGH", "", "", "urn:cerebro:writer:asset:1", "")
	finding.Attributes["internet_exposed"] = "true"

	defaultContext := AnalyzeFindingRiskContext(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC))
	customContext := AnalyzeFindingRiskContextWithConfig(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC), &config)

	if defaultContext.Score != customContext.Score {
		t.Fatalf("custom thresholds changed score %d -> %d", defaultContext.Score, customContext.Score)
	}
	if defaultContext.EffectiveSeverity == customContext.EffectiveSeverity {
		t.Fatalf("EffectiveSeverity = %q for both default and custom thresholds, want threshold-driven change", customContext.EffectiveSeverity)
	}
	if customContext.RiskModelVersion == FindingRiskModelVersion {
		t.Fatalf("RiskModelVersion = %q, want config-scoped model version", customContext.RiskModelVersion)
	}
}

func TestEnrichFindingRiskWithConfigUsesCustomThresholdLevels(t *testing.T) {
	config := DefaultRiskScoringConfig("writer")
	config.Thresholds.Critical = 95
	config.Thresholds.High = 80
	config.Thresholds.Medium = 60
	finding := &ports.FindingRecord{
		ID:       "finding-custom-levels",
		TenantID: "writer",
		Severity: "LOW",
		Status:   findingStatusOpen,
		FindingRisk: ports.FindingRisk{
			RiskScore:       75,
			LikelihoodScore: 75,
			ImpactScore:     75,
		},
		Attributes: map[string]string{},
	}

	enriched := enrichFindingRiskWithConfig(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC), &config)

	if enriched.LikelihoodLevel != "medium" || enriched.ImpactLevel != "medium" {
		t.Fatalf("levels = %q/%q, want medium/medium under custom thresholds", enriched.LikelihoodLevel, enriched.ImpactLevel)
	}
	if got := enriched.Attributes[FindingEffectiveSeverityAttribute]; got != "MEDIUM" {
		t.Fatalf("effective severity = %q, want MEDIUM", got)
	}
}

func TestAnalyzeFindingRiskContextWithConfigUsesFactorWeights(t *testing.T) {
	config := DefaultRiskScoringConfig("writer")
	config.FactorWeights["external_exposure"] = ports.RiskScoringFactorWeight{Likelihood: 5}
	finding := compoundRiskFinding("finding-custom-factor", "rule-1", "MEDIUM", "", "", "urn:cerebro:writer:asset:1", "")
	finding.Attributes["internet_exposed"] = "true"

	defaultContext := AnalyzeFindingRiskContext(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC))
	customContext := AnalyzeFindingRiskContextWithConfig(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC), &config)

	if customContext.LikelihoodScore >= defaultContext.LikelihoodScore {
		t.Fatalf("LikelihoodScore = %d, want below default %d", customContext.LikelihoodScore, defaultContext.LikelihoodScore)
	}
	if !stringSliceContains(customContext.Reasons, "external_exposure") {
		t.Fatalf("Risk reasons = %#v, want external_exposure reason preserved", customContext.Reasons)
	}
}

func TestAnalyzeFindingRiskContextWithConfigUsesPrivateNetworkSignalCap(t *testing.T) {
	config := DefaultRiskScoringConfig("writer")
	config.Signals.PrivateNetworkLikelihoodCap = 5
	finding := compoundRiskFinding("finding-private-network-cap", "rule-1", "HIGH", "", "", "urn:cerebro:writer:asset:1", "")
	finding.Attributes["private_network"] = "true"

	context := AnalyzeFindingRiskContextWithConfig(finding, time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC), &config)

	if context.LikelihoodScore != 5 {
		t.Fatalf("LikelihoodScore = %d, want signal cap 5", context.LikelihoodScore)
	}
	if !stringSliceContains(context.Reasons, "private_network_context") {
		t.Fatalf("Risk reasons = %#v, want private_network_context", context.Reasons)
	}
}

func TestWeightedAttackPathScoreWithConfigUsesRelationWeights(t *testing.T) {
	steps := []FindingAttackPathStep{
		{FromURN: "a", Relation: "can_admin", ToURN: "b"},
		{FromURN: "b", Relation: "member_of", ToURN: "c"},
	}
	defaultScore, _ := weightedAttackPathScore(steps)
	config := DefaultRiskScoringConfig("writer")
	config.RelationWeights["can_admin"] = 1
	config.RelationWeights["member_of"] = 1
	customScore, reasons := weightedAttackPathScoreWithConfig(steps, &config)
	if customScore >= defaultScore {
		t.Fatalf("customScore = %d, want below default %d", customScore, defaultScore)
	}
	if !stringSliceContains(reasons, "edge_weight:can_admin:1") {
		t.Fatalf("reasons = %#v, want custom relation weight reason", reasons)
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
	neighborhoods := map[string]*ports.EntityNeighborhood{
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
	}
	paths := AnalyzeFindingAttackPaths([]*ports.FindingRecord{finding}, neighborhoods, FindingExposureAnalysisOptions{Limit: 10})
	if len(paths) < 2 {
		t.Fatalf("len(paths) = %d, want at least 2", len(paths))
	}
	if got := paths[0].Steps[0].Relation; got != "can_reach" {
		t.Fatalf("top path relation = %q, want can_reach from weighted scoring; paths=%#v", got, paths)
	}
	if !stringSliceContains(paths[0].Reasons, "edge_weight:can_reach:7") {
		t.Fatalf("top path reasons = %#v, want can_reach weight", paths[0].Reasons)
	}

	config := DefaultRiskScoringConfig("writer")
	config.RelationWeights["can_reach"] = 1
	config.RelationWeights["member_of"] = 20
	weighted := AnalyzeFindingAttackPaths([]*ports.FindingRecord{finding}, neighborhoods, FindingExposureAnalysisOptions{
		Limit:             10,
		RiskScoringConfig: &config,
	})
	if len(weighted) < 2 {
		t.Fatalf("len(weighted) = %d, want at least 2", len(weighted))
	}
	if got := weighted[0].Steps[0].Relation; got != "member_of" {
		t.Fatalf("custom top path relation = %q, want member_of from configured relation weights; paths=%#v", got, weighted)
	}
	if !stringSliceContains(weighted[0].Reasons, "edge_weight:member_of:20") {
		t.Fatalf("custom top path reasons = %#v, want configured member_of weight", weighted[0].Reasons)
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

func stringSliceContainsPrefix(values []string, wantPrefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, wantPrefix) {
			return true
		}
	}
	return false
}
