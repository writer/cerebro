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
	if credentialGovernanceHandlesPrivilege(input) {
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

type credentialGovernanceGenerator struct{}

func (credentialGovernanceGenerator) ID() string {
	return "credential_governance"
}

func (credentialGovernanceGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if input.Finding == nil {
		return nil
	}
	targetURN := credentialTargetURN(input.TenantID, input.Finding)
	if targetURN == "" || credentialRevoked(input.Finding.Attributes) {
		return nil
	}
	label := targetLabel(input.Finding, targetURN)
	privileged := credentialPrivileged(input)
	recentUse := credentialRecentlyUsed(input.Finding.Attributes, input.Now)
	staleUse := credentialStaleUse(input.Finding.Attributes, input.Now)
	missingOwner := credentialMissingOwner(input.Finding)
	seeds := []CandidateSeed{}
	if privileged || (recentUse && missingOwner) {
		reasons := []string{"candidate_generator:credential_governance", "credential_rotation"}
		if privileged {
			reasons = append(reasons, "privileged_credential")
		}
		if recentUse {
			reasons = append(reasons, "recent_credential_use")
		}
		if missingOwner {
			reasons = append(reasons, "missing_credential_owner")
		}
		seeds = append(seeds, CandidateSeed{
			Title:               "Rotate credential for " + label,
			ActionType:          ActionTypeRotateCredential,
			ScenarioType:        findinganalysis.RiskDeltaScenarioRemovePrivilege,
			TargetURN:           targetURN,
			SimulationSupported: findingSupportsAction(input.Finding, input.RiskContext, findinganalysis.RiskDeltaScenarioRemovePrivilege),
			Reasons:             reasons,
		})
	}
	if staleUse {
		seeds = append(seeds, CandidateSeed{
			Title:               "Revoke unused credential for " + label,
			ActionType:          ActionTypeRevokeCredential,
			TargetURN:           targetURN,
			SimulationSupported: false,
			Reasons:             []string{"candidate_generator:credential_governance", "stale_credential_use"},
		})
	}
	if missingOwner {
		seeds = append(seeds, CandidateSeed{
			Title:               "Review credential owner for " + label,
			ActionType:          ActionTypeReviewCredentialOwner,
			TargetURN:           targetURN,
			SimulationSupported: false,
			Reasons:             []string{"candidate_generator:credential_governance", "missing_credential_owner"},
		})
	}
	return seeds
}

type ownerAssignmentGenerator struct{}

func (ownerAssignmentGenerator) ID() string {
	return "owner_assignment"
}

func (ownerAssignmentGenerator) Generate(input CandidateGeneratorInput) []CandidateSeed {
	if input.Finding == nil {
		return nil
	}
	if credentialTargetURN(input.TenantID, input.Finding) != "" {
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
	case ActionTypeRotateCredential, ActionTypeRevokeCredential, ActionTypeReviewCredentialOwner:
		return credentialTargetURN(tenantID, finding)
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
			finding.Attributes["name"],
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

func credentialGovernanceHandlesPrivilege(input CandidateGeneratorInput) bool {
	if input.Finding == nil {
		return false
	}
	if credentialTargetURN(input.TenantID, input.Finding) == "" || credentialRevoked(input.Finding.Attributes) {
		return false
	}
	return credentialPrivileged(input)
}

func credentialTargetURN(tenantID string, finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	attributes := finding.Attributes
	if targetURN := firstTenantScopedURN(
		tenantID,
		attributes["credential_urn"],
		attributes["api_key_urn"],
		attributes["openai_credential_urn"],
		attributes["anthropic_credential_urn"],
		attributes["github_credential_urn"],
	); targetURN != "" {
		return targetURN
	}
	if secretURN := firstTenantScopedURN(tenantID, attributes["secret_urn"]); secretURN != "" {
		return secretURN
	}
	targetURN := firstTenantScopedURN(
		tenantID,
		attributes["secret_urn"],
		attributes["target_urn"],
		attributes["primary_resource_urn"],
		primaryResourceURN(finding),
	)
	if !credentialLikeURN(targetURN) {
		return ""
	}
	return targetURN
}

func credentialLikeURN(urn string) bool {
	value := strings.ToLower(strings.TrimSpace(urn))
	if value == "" {
		return false
	}
	return strings.Contains(value, "credential") ||
		strings.Contains(value, "api_key")
}

func credentialPrivileged(input CandidateGeneratorInput) bool {
	if input.Finding == nil {
		return false
	}
	if findingSupportsAction(input.Finding, input.RiskContext, findinganalysis.RiskDeltaScenarioRemovePrivilege) {
		return true
	}
	attributes := input.Finding.Attributes
	return strings.EqualFold(strings.TrimSpace(attributes["key_class"]), "admin") ||
		containsAny(input.Finding.RuleID, "privileged", "admin") ||
		containsAny(input.Finding.Title, "privileged", "admin")
}

func credentialMissingOwner(finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if owner, _ := findingOwner(finding); owner != "" {
		return false
	}
	attributes := finding.Attributes
	if attributeBool(attributes, "has_owner") {
		return false
	}
	return strings.TrimSpace(attributes["owner_id"]) == "" &&
		strings.TrimSpace(attributes["owner_user_id"]) == "" &&
		strings.TrimSpace(attributes["owner_service_account_id"]) == ""
}

func credentialRevoked(attributes map[string]string) bool {
	status := strings.ToLower(strings.TrimSpace(attributes["status"]))
	if status == "" {
		status = strings.ToLower(strings.TrimSpace(attributes["credential_status"]))
	}
	switch status {
	case "deleted", "revoked", "disabled", "inactive", "expired", "suspended", "archived":
		return true
	default:
		return false
	}
}

func credentialRecentlyUsed(attributes map[string]string, now time.Time) bool {
	lastUsedAt, ok := credentialLastUsedAt(attributes)
	if ok && !now.IsZero() {
		return !lastUsedAt.After(now) && now.Sub(lastUsedAt) <= 30*24*time.Hour
	}
	return attributeBool(attributes, "credential_use", "runtime_credential_use", "recent_credential_use")
}

func credentialStaleUse(attributes map[string]string, now time.Time) bool {
	if now.IsZero() {
		return false
	}
	lastUsedAt, ok := credentialLastUsedAt(attributes)
	if !ok {
		createdAt, created := parseCredentialTime(firstCredentialAttribute(attributes["created_at"], attributes["created"]))
		return created && !createdAt.After(now) && now.Sub(createdAt) >= 90*24*time.Hour
	}
	return !lastUsedAt.After(now) && now.Sub(lastUsedAt) >= 90*24*time.Hour
}

func credentialLastUsedAt(attributes map[string]string) (time.Time, bool) {
	return parseCredentialTime(firstCredentialAttribute(attributes["last_used_at"], attributes["last_used_time"], attributes["last_used"], attributes["last_seen_at"]))
}

func firstCredentialAttribute(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func parseCredentialTime(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}
