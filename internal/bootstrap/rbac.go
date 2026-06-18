package bootstrap

import "github.com/writer/cerebro/internal/authz"

const (
	roleCerebroAdmin            = authz.RoleCerebroAdmin
	roleCerebroViewer           = authz.RoleCerebroViewer
	roleCerebroFindingManager   = authz.RoleCerebroFindingManager
	roleCerebroConnectorManager = authz.RoleCerebroConnectorManager
	roleCerebroSourceManager    = authz.RoleCerebroSourceManager
)

func rbacScopesForRoles(roles []string) []string {
	return authz.ScopesForRoles(roles)
}

func expandedPrincipalScopes(principal authPrincipal) []string {
	return authz.ExpandedScopes(principal.Scopes, principal.Roles)
}

func principalHasRBACRole(principal authPrincipal) bool {
	return authz.HasRole(principal.Roles)
}
