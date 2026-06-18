package bootstrap

const (
	roleCerebroAdmin            = "cerebro.admin"
	roleCerebroViewer           = "cerebro.viewer"
	roleCerebroAnalyst          = "cerebro.analyst"
	roleCerebroFindingManager   = "cerebro.finding_manager"
	roleCerebroGRCReviewer      = "cerebro.grc_reviewer"
	roleCerebroConnectorManager = "cerebro.connector_manager"
	roleCerebroResponder        = "cerebro.responder"
	roleCerebroSourceManager    = "cerebro.source_manager"
	roleCerebroJobManager       = "cerebro.job_manager"
)

var allRBACScopes = []string{
	scopeCosmoSecurityRead,
	scopeFindingCandidatePromote,
	scopeFindingLifecycleWrite,
	scopeGRCInventoryWrite,
	scopeConnectorCredentialsRead,
	scopeConnectorCredentialsWrite,
	scopeRuntimeResponseWrite,
	scopeReportsRun,
	scopeKnowledgeWrite,
	scopeWorkflowReplay,
	scopeSourcesPreview,
	scopeConnectorDefinitionsWrite,
	scopeConnectorsWrite,
	scopeJobsWrite,
	scopeSourceRuntimesWrite,
}

var rbacRoleScopes = map[string][]string{
	roleCerebroViewer: {scopeCosmoSecurityRead},
	"viewer":          {scopeCosmoSecurityRead},
	"reader":          {scopeCosmoSecurityRead},
	"read_only":       {scopeCosmoSecurityRead},
	roleCerebroAnalyst: {
		scopeCosmoSecurityRead,
		scopeFindingCandidatePromote,
		scopeFindingLifecycleWrite,
		scopeGRCInventoryWrite,
	},
	"analyst": {
		scopeCosmoSecurityRead,
		scopeFindingCandidatePromote,
		scopeFindingLifecycleWrite,
		scopeGRCInventoryWrite,
	},
	"editor": {
		scopeCosmoSecurityRead,
		scopeFindingCandidatePromote,
		scopeFindingLifecycleWrite,
		scopeGRCInventoryWrite,
	},
	roleCerebroFindingManager: {scopeCosmoSecurityRead, scopeFindingCandidatePromote, scopeFindingLifecycleWrite},
	roleCerebroGRCReviewer:    {scopeCosmoSecurityRead, scopeGRCInventoryWrite},
	roleCerebroConnectorManager: {
		scopeCosmoSecurityRead,
		scopeConnectorCredentialsRead,
		scopeConnectorCredentialsWrite,
		scopeConnectorDefinitionsWrite,
		scopeConnectorsWrite,
	},
	roleCerebroResponder: {scopeCosmoSecurityRead, scopeRuntimeResponseWrite},
	roleCerebroSourceManager: {
		scopeCosmoSecurityRead,
		scopeReportsRun,
		scopeSourcesPreview,
		scopeSourceRuntimesWrite,
	},
	roleCerebroJobManager: {scopeCosmoSecurityRead, scopeJobsWrite},
	roleCerebroAdmin:      allRBACScopes,
	"admin":               allRBACScopes,
	"owner":               allRBACScopes,
}

func rbacScopesForRoles(roles []string) []string {
	var scopes []string
	for _, role := range normalizeAuthList(roles) {
		scopes = append(scopes, rbacRoleScopes[role]...)
	}
	return normalizeAuthList(scopes)
}

func expandedPrincipalScopes(principal authPrincipal) []string {
	return normalizeAuthList(append(cloneAuthValues(principal.Scopes), rbacScopesForRoles(principal.Roles)...))
}

func principalHasRBACRole(principal authPrincipal) bool {
	return len(normalizeAuthList(principal.Roles)) > 0
}
