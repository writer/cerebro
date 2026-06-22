package authz

import "testing"

func TestAskQueriesWriteScopeRoleExpansion(t *testing.T) {
	for _, role := range []string{
		RoleCerebroAnalyst,
		"analyst",
		"editor",
		RoleCerebroFindingManager,
		RoleCerebroGRCReviewer,
		RoleCerebroAdmin,
	} {
		if !hasScope(ScopesForRoles([]string{role}), ScopeAskQueriesWrite) {
			t.Fatalf("role %q did not expand to %s", role, ScopeAskQueriesWrite)
		}
	}

	for _, role := range []string{
		RoleCerebroViewer,
		"viewer",
		"reader",
		"read_only",
		RoleCerebroConnectorManager,
		RoleCerebroResponder,
		RoleCerebroSourceManager,
		RoleCerebroJobManager,
	} {
		if hasScope(ScopesForRoles([]string{role}), ScopeAskQueriesWrite) {
			t.Fatalf("role %q unexpectedly expanded to %s", role, ScopeAskQueriesWrite)
		}
	}
}

func hasScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}
