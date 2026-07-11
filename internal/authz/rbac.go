package authz

import "strings"

const (
	ScopeCosmoSecurityRead         = "cerebro.cosmo.security.read"
	ScopeFindingCandidatePromote   = "cerebro.finding_candidates.promote"
	ScopeFindingLifecycleWrite     = "cerebro.findings.write"
	ScopeGRCInventoryWrite         = "cerebro.grc.inventory.write"
	ScopeGRCPolicyLifecycleWrite   = "cerebro.grc.policy_lifecycle.write"
	ScopeConnectorCredentialsRead  = "cerebro.connector_credentials.read"
	ScopeConnectorCredentialsWrite = "cerebro.connector_credentials.write"
	ScopeRuntimeResponseWrite      = "cerebro.runtime_response.write"
	ScopeGraphActionsWrite         = "cerebro.graph_actions.write"
	ScopeReportsRun                = "cerebro.reports.run"
	ScopeKnowledgeWrite            = "cerebro.knowledge.write"
	ScopeWorkflowReplay            = "cerebro.workflow.replay"
	ScopeSourcesPreview            = "cerebro.sources.preview"
	ScopeConnectorDefinitionsWrite = "cerebro.connector_definitions.write"
	ScopeConnectorsWrite           = "cerebro.connectors.write"
	ScopeJobsWrite                 = "cerebro.jobs.write"
	ScopeSourceRuntimesWrite       = "cerebro.source_runtimes.write"
	ScopeAskQueriesWrite           = "cerebro.ask_queries.write"
	ScopeDashboardsWrite           = "cerebro.dashboards.write"
	ScopeRiskScoringWrite          = "cerebro.risk_scoring.write"
	ScopeUserPreferencesWrite      = "cerebro.user_preferences.write"
	ScopeComplianceProgramsRead    = "cerebro.compliance.programs.read"
	ScopeComplianceEvidenceRead    = "cerebro.compliance.evidence.read"
	ScopeComplianceAssessmentsRead = "cerebro.compliance.assessments.read"
	ScopeComplianceWorkRead        = "cerebro.compliance.work.read"

	RoleCerebroAdmin            = "cerebro.admin"
	RoleCerebroViewer           = "cerebro.viewer"
	RoleCerebroAnalyst          = "cerebro.analyst"
	RoleCerebroFindingManager   = "cerebro.finding_manager"
	RoleCerebroGRCReviewer      = "cerebro.grc_reviewer"
	RoleCerebroConnectorManager = "cerebro.connector_manager"
	RoleCerebroResponder        = "cerebro.responder"
	RoleCerebroSourceManager    = "cerebro.source_manager"
	RoleCerebroJobManager       = "cerebro.job_manager"
)

var allScopes = []string{
	ScopeCosmoSecurityRead,
	ScopeFindingCandidatePromote,
	ScopeFindingLifecycleWrite,
	ScopeGRCInventoryWrite,
	ScopeGRCPolicyLifecycleWrite,
	ScopeConnectorCredentialsRead,
	ScopeConnectorCredentialsWrite,
	ScopeRuntimeResponseWrite,
	ScopeGraphActionsWrite,
	ScopeReportsRun,
	ScopeKnowledgeWrite,
	ScopeWorkflowReplay,
	ScopeSourcesPreview,
	ScopeConnectorDefinitionsWrite,
	ScopeConnectorsWrite,
	ScopeJobsWrite,
	ScopeSourceRuntimesWrite,
	ScopeAskQueriesWrite,
	ScopeDashboardsWrite,
	ScopeRiskScoringWrite,
	ScopeUserPreferencesWrite,
	ScopeComplianceProgramsRead,
	ScopeComplianceEvidenceRead,
	ScopeComplianceAssessmentsRead,
	ScopeComplianceWorkRead,
}

var complianceReadScopes = []string{
	ScopeComplianceProgramsRead,
	ScopeComplianceEvidenceRead,
	ScopeComplianceAssessmentsRead,
	ScopeComplianceWorkRead,
}

var roleScopes = map[string][]string{
	RoleCerebroViewer: append([]string{ScopeCosmoSecurityRead, ScopeUserPreferencesWrite}, complianceReadScopes...),
	"viewer":          append([]string{ScopeCosmoSecurityRead, ScopeUserPreferencesWrite}, complianceReadScopes...),
	"reader":          append([]string{ScopeCosmoSecurityRead, ScopeUserPreferencesWrite}, complianceReadScopes...),
	"read_only":       append([]string{ScopeCosmoSecurityRead, ScopeUserPreferencesWrite}, complianceReadScopes...),
	RoleCerebroAnalyst: {
		ScopeCosmoSecurityRead,
		ScopeUserPreferencesWrite,
		ScopeFindingCandidatePromote,
		ScopeFindingLifecycleWrite,
		ScopeGRCInventoryWrite,
		ScopeGRCPolicyLifecycleWrite,
		ScopeAskQueriesWrite,
		ScopeDashboardsWrite,
		ScopeRiskScoringWrite,
		ScopeComplianceProgramsRead,
		ScopeComplianceEvidenceRead,
		ScopeComplianceAssessmentsRead,
		ScopeComplianceWorkRead,
	},
	"analyst": {
		ScopeCosmoSecurityRead,
		ScopeUserPreferencesWrite,
		ScopeFindingCandidatePromote,
		ScopeFindingLifecycleWrite,
		ScopeGRCInventoryWrite,
		ScopeGRCPolicyLifecycleWrite,
		ScopeAskQueriesWrite,
		ScopeDashboardsWrite,
		ScopeRiskScoringWrite,
		ScopeComplianceProgramsRead,
		ScopeComplianceEvidenceRead,
		ScopeComplianceAssessmentsRead,
		ScopeComplianceWorkRead,
	},
	"editor": {
		ScopeCosmoSecurityRead,
		ScopeUserPreferencesWrite,
		ScopeFindingCandidatePromote,
		ScopeFindingLifecycleWrite,
		ScopeGRCInventoryWrite,
		ScopeGRCPolicyLifecycleWrite,
		ScopeAskQueriesWrite,
		ScopeDashboardsWrite,
		ScopeRiskScoringWrite,
		ScopeComplianceProgramsRead,
		ScopeComplianceEvidenceRead,
		ScopeComplianceAssessmentsRead,
		ScopeComplianceWorkRead,
	},
	RoleCerebroFindingManager: {ScopeCosmoSecurityRead, ScopeUserPreferencesWrite, ScopeFindingCandidatePromote, ScopeFindingLifecycleWrite, ScopeGRCPolicyLifecycleWrite, ScopeAskQueriesWrite, ScopeRiskScoringWrite},
	RoleCerebroGRCReviewer:    append([]string{ScopeCosmoSecurityRead, ScopeUserPreferencesWrite, ScopeGRCInventoryWrite, ScopeGRCPolicyLifecycleWrite, ScopeAskQueriesWrite, ScopeDashboardsWrite, ScopeRiskScoringWrite}, complianceReadScopes...),
	RoleCerebroConnectorManager: {
		ScopeCosmoSecurityRead,
		ScopeUserPreferencesWrite,
		ScopeConnectorCredentialsRead,
		ScopeConnectorCredentialsWrite,
		ScopeConnectorDefinitionsWrite,
		ScopeConnectorsWrite,
	},
	RoleCerebroResponder: {ScopeCosmoSecurityRead, ScopeUserPreferencesWrite, ScopeRuntimeResponseWrite},
	RoleCerebroSourceManager: {
		ScopeCosmoSecurityRead,
		ScopeUserPreferencesWrite,
		ScopeReportsRun,
		ScopeSourcesPreview,
		ScopeSourceRuntimesWrite,
	},
	RoleCerebroJobManager: {ScopeCosmoSecurityRead, ScopeUserPreferencesWrite, ScopeJobsWrite},
	RoleCerebroAdmin:      allScopes,
	"admin":               allScopes,
	"owner":               allScopes,
}

func ScopesForRoles(roles []string) []string {
	var scopes []string
	for _, role := range normalize(roles) {
		scopes = append(scopes, roleScopes[role]...)
	}
	return normalize(scopes)
}

func ExpandedScopes(scopes []string, roles []string) []string {
	return normalize(append(clone(scopes), ScopesForRoles(roles)...))
}

func HasRole(roles []string) bool {
	return len(normalize(roles)) > 0
}

func HasAdminRole(roles []string) bool {
	roles = normalize(roles)
	return contains(roles, RoleCerebroAdmin) || contains(roles, "admin") || contains(roles, "owner")
}

func normalize(values []string) []string {
	seen := map[string]struct{}{}
	var normalized []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func clone(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func contains(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}
