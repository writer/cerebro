package authz

import "testing"

func TestAskQueriesWriteScopeRoleExpansion(t *testing.T) {
	assertGRCContentWriteScopeExpansion(t, ScopeAskQueriesWrite)
}

func TestRiskScoringWriteScopeRoleExpansion(t *testing.T) {
	assertGRCContentWriteScopeExpansion(t, ScopeRiskScoringWrite)
}

func assertGRCContentWriteScopeExpansion(t *testing.T, scope string) {
	t.Helper()
	for _, role := range []string{
		RoleCerebroAnalyst,
		"analyst",
		"editor",
		RoleCerebroFindingManager,
		RoleCerebroGRCReviewer,
		RoleCerebroAdmin,
	} {
		if !hasScope(ScopesForRoles([]string{role}), scope) {
			t.Fatalf("role %q did not expand to %s", role, scope)
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
		if hasScope(ScopesForRoles([]string{role}), scope) {
			t.Fatalf("role %q unexpectedly expanded to %s", role, scope)
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
