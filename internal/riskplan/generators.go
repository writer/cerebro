package riskplan

import (
	"strings"
	"time"

	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

type publicExposureGenerator struct{}

func (publicExposureGenerator) ID() string {
	return "public_exposure"
}

func (publicExposureGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if !findingSupportsAction(input.Finding, input.RiskContext, findinganalysis.RiskDeltaScenarioRemovePublicExposure) {
		return nil
	}
	targetURN := actionTargetURN(input.TenantID, input.Finding, findinganalysis.RiskDeltaScenarioRemovePublicExposure)
	if targetURN == "" {
		return nil
	}
	return []CandidateSeed{{
		Title:               actionTitle(findinganalysis.RiskDeltaScenarioRemovePublicExposure, targetLabel(input.Finding, targetURN)),
		ActionType:          findinganalysis.RiskDeltaScenarioRemovePublicExposure,
		ScenarioType:        findinganalysis.RiskDeltaScenarioRemovePublicExposure,
		TargetURN:           targetURN,
		SimulationSupported: true,
		Reasons:             []string{"candidate_generator:public_exposure"},
	}}
}

type privilegeGenerator struct{}

func (privilegeGenerator) ID() string {
	return "privilege"
}

func (privilegeGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if !findingSupportsAction(input.Finding, input.RiskContext, findinganalysis.RiskDeltaScenarioRemovePrivilege) {
		return nil
	}
	targetURN := actionTargetURN(input.TenantID, input.Finding, findinganalysis.RiskDeltaScenarioRemovePrivilege)
	if targetURN == "" {
		return nil
	}
	return []CandidateSeed{{
		Title:               actionTitle(findinganalysis.RiskDeltaScenarioRemovePrivilege, targetLabel(input.Finding, targetURN)),
		ActionType:          findinganalysis.RiskDeltaScenarioRemovePrivilege,
		ScenarioType:        findinganalysis.RiskDeltaScenarioRemovePrivilege,
		TargetURN:           targetURN,
		SimulationSupported: true,
		Reasons:             []string{"candidate_generator:privilege"},
	}}
}

type vulnerabilityGenerator struct{}

func (vulnerabilityGenerator) ID() string {
	return "vulnerability"
}

func (vulnerabilityGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if !findingSupportsAction(input.Finding, input.RiskContext, findinganalysis.RiskDeltaScenarioPatchVulnerability) {
		return nil
	}
	targetURN := actionTargetURN(input.TenantID, input.Finding, findinganalysis.RiskDeltaScenarioPatchVulnerability)
	if targetURN == "" {
		return nil
	}
	return []CandidateSeed{{
		Title:               actionTitle(findinganalysis.RiskDeltaScenarioPatchVulnerability, targetLabel(input.Finding, targetURN)),
		ActionType:          findinganalysis.RiskDeltaScenarioPatchVulnerability,
		ScenarioType:        findinganalysis.RiskDeltaScenarioPatchVulnerability,
		TargetURN:           targetURN,
		SimulationSupported: true,
		Reasons:             []string{"candidate_generator:vulnerability"},
	}}
}

type ownerAssignmentGenerator struct{}

func (ownerAssignmentGenerator) ID() string {
	return "owner_assignment"
}

func (ownerAssignmentGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if input.Finding == nil {
		return nil
	}
	if owner, _ := findingOwner(input.Finding); owner != "" {
		return nil
	}
	if input.RiskContext.Score < 70 && input.Finding.RiskScore < 70 {
		return nil
	}
	targetURN := actionTargetURN(input.TenantID, input.Finding, ActionTypeAssignOwner)
	if targetURN == "" {
		return nil
	}
	return []CandidateSeed{{
		Title:               "Assign owner for " + targetLabel(input.Finding, targetURN),
		ActionType:          ActionTypeAssignOwner,
		TargetURN:           targetURN,
		SimulationSupported: false,
		Reasons:             []string{"candidate_generator:owner_assignment", "missing_owner"},
	}}
}

type evidenceRefreshGenerator struct{}

func (evidenceRefreshGenerator) ID() string {
	return "evidence_refresh"
}

func (evidenceRefreshGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if input.Finding == nil {
		return nil
	}
	if !findingNeedsEvidenceRefresh(input.Finding, input.RiskContext, input.Now) {
		return nil
	}
	targetURN := actionTargetURN(input.TenantID, input.Finding, ActionTypeRefreshEvidence)
	if targetURN == "" {
		return nil
	}
	return []CandidateSeed{{
		Title:               "Refresh evidence for " + targetLabel(input.Finding, targetURN),
		ActionType:          ActionTypeRefreshEvidence,
		TargetURN:           targetURN,
		SimulationSupported: false,
		Reasons:             []string{"candidate_generator:evidence_refresh", "limited_or_stale_evidence"},
	}}
}

func findingSupportsAction(finding *ports.FindingRecord, context findinganalysis.FindingRiskContext, actionType string) bool {
	if finding == nil {
		return false
	}
	attributes := finding.Attributes
	reasons := map[string]struct{}{}
	for _, reason := range append(append([]string{}, finding.RiskReasons...), context.Reasons...) {
		addStringSetValue(reasons, reason)
	}
	for _, factor := range append(append([]ports.FindingRiskFactor{}, finding.RiskFactors...), context.Factors...) {
		addStringSetValue(reasons, factor.FactorID)
	}
	action := strings.ToLower(strings.TrimSpace(attributes["action"]))
	switch actionType {
	case findinganalysis.RiskDeltaScenarioRemovePublicExposure:
		return stringSetContains(reasons, "external_exposure") ||
			attributeBool(attributes, "internet_exposed", "public", "externally_exposed", "external_exposure", "is_public", "is_internet_facing", "reachable", "directly_reachable", "internet_reachable", "can_reach") ||
			containsAny(action, "public", "expose", "internet", "can_reach")
	case findinganalysis.RiskDeltaScenarioRemovePrivilege:
		return stringSetContains(reasons, "privileged_actor") ||
			stringSetContains(reasons, "privilege_or_control_plane") ||
			attributeBool(attributes, "privileged", "actor_privileged", "admin", "is_admin", "has_admin", "can_admin", "admin_reachable", "privileged_access", "has_admin_path") ||
			containsAny(action, "can_admin", "can_assume", "can_impersonate", "administratoraccess")
	case findinganalysis.RiskDeltaScenarioPatchVulnerability:
		return stringSetContains(reasons, "known_exploited") ||
			stringSetContains(reasons, "epss_high") ||
			stringSetContains(reasons, "epss_elevated") ||
			stringSetContains(reasons, "exploit_available") ||
			stringSetContains(reasons, "cvss_critical") ||
			stringSetContains(reasons, "cvss_high") ||
			stringSetContainsPrefix(reasons, "exploit_maturity:") ||
			attributePresent(attributes, "vulnerability_urn", "package_urn", "image_urn", "cve", "cve_id", "vulnerability_id", "package", "purl", "cvss_score", "cvss", "epss_score", "epss") ||
			attributeBool(attributes, "is_kev", "kev", "known_exploited", "known_exploited_vulnerability", "exploit_available", "public_exploit", "weaponized_exploit") ||
			parseFloatAttribute(attributes, "cvss_score", "cvss") >= 7 ||
			parseFloatAttribute(attributes, "epss_score", "epss") >= 0.5
	default:
		return false
	}
}

func actionTargetURN(tenantID string, finding *ports.FindingRecord, actionType string) string {
	if finding == nil {
		return ""
	}
	attributes := finding.Attributes
	switch actionType {
	case findinganalysis.RiskDeltaScenarioRemovePublicExposure:
		return firstTenantScopedURN(tenantID, attributes["exposed_resource_urn"], attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	case findinganalysis.RiskDeltaScenarioRemovePrivilege:
		return firstTenantScopedURN(tenantID, attributes["principal_urn"], attributes["identity_urn"], attributes["actor_urn"], attributes["permission_urn"], attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	case findinganalysis.RiskDeltaScenarioPatchVulnerability:
		return firstTenantScopedURN(tenantID, attributes["vulnerability_urn"], attributes["package_urn"], attributes["image_urn"], attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	case ActionTypeAssignOwner, ActionTypeRefreshEvidence:
		return firstTenantScopedURN(tenantID, attributes["target_urn"], attributes["asset_urn"], attributes["resource_urn"], attributes["primary_resource_urn"], primaryResourceURN(finding))
	default:
		return ""
	}
}

func actionTitle(actionType string, targetLabel string) string {
	switch actionType {
	case findinganalysis.RiskDeltaScenarioRemovePublicExposure:
		return "Remove public exposure from " + targetLabel
	case findinganalysis.RiskDeltaScenarioRemovePrivilege:
		return "Remove excess privilege from " + targetLabel
	case findinganalysis.RiskDeltaScenarioPatchVulnerability:
		return "Patch exploitable vulnerability on " + targetLabel
	default:
		return "Reduce risk on " + targetLabel
	}
}

func targetLabel(finding *ports.FindingRecord, targetURN string) string {
	if finding != nil {
		for _, value := range []string{
			finding.Attributes["resource_label"],
			finding.Attributes["resource_name"],
			finding.Attributes["asset_name"],
			finding.Attributes["repository"],
			finding.Attributes["package"],
			finding.Title,
		} {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				return trimmed
			}
		}
	}
	targetURN = strings.TrimSpace(targetURN)
	if targetURN == "" {
		return "target"
	}
	parts := strings.FieldsFunc(targetURN, func(r rune) bool {
		return r == ':' || r == '/' || r == '#'
	})
	if len(parts) == 0 {
		return targetURN
	}
	return parts[len(parts)-1]
}

func findingNeedsEvidenceRefresh(finding *ports.FindingRecord, context findinganalysis.FindingRiskContext, now time.Time) bool {
	confidence := finding.ConfidenceScore
	if confidence == 0 {
		confidence = context.ConfidenceScore
	}
	if confidence > 0 && confidence < 65 {
		return true
	}
	if !finding.LastObservedAt.IsZero() && now.Sub(finding.LastObservedAt) > 30*24*time.Hour {
		return true
	}
	evidenceRefs := 0
	for _, factor := range append(append([]ports.FindingRiskFactor{}, finding.RiskFactors...), context.Factors...) {
		evidenceRefs += len(factor.EvidenceRefs)
	}
	return evidenceRefs == 0 && len(finding.EventIDs) == 0 && len(finding.GraphEvidenceRows) == 0
}
