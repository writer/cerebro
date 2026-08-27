package authz

import (
	"reflect"
	"testing"
)

func TestPrincipalActorIDUsesFirstConcreteAuthenticatedField(t *testing.T) {
	if got := PrincipalActorID(" ", "client-1", "device-1", "credential-1"); got != "client-1" {
		t.Fatalf("PrincipalActorID() = %q, want client-1", got)
	}
	if got := PrincipalActorID("", " "); got != "" {
		t.Fatalf("PrincipalActorID() = %q, want empty", got)
	}
}

func TestAskQueriesWriteScopeRoleExpansion(t *testing.T) {
	assertGRCContentWriteScopeExpansion(t, ScopeAskQueriesWrite)
}

func TestRiskScoringWriteScopeRoleExpansion(t *testing.T) {
	assertGRCContentWriteScopeExpansion(t, ScopeRiskScoringWrite)
}

func TestGRCPolicyLifecycleWriteScopeRoleExpansion(t *testing.T) {
	assertGRCContentWriteScopeExpansion(t, ScopeGRCPolicyLifecycleWrite)
}

func TestUserPreferencesWriteScopeRoleExpansion(t *testing.T) {
	for _, role := range []string{
		RoleCerebroViewer,
		"viewer",
		"reader",
		"read_only",
		RoleCerebroAnalyst,
		RoleCerebroFindingManager,
		RoleCerebroGRCReviewer,
		RoleCerebroConnectorManager,
		RoleCerebroResponder,
		RoleCerebroSourceManager,
		RoleCerebroJobManager,
		RoleCerebroAdmin,
	} {
		if !hasScope(ScopesForRoles([]string{role}), ScopeUserPreferencesWrite) {
			t.Fatalf("role %q did not expand to %s", role, ScopeUserPreferencesWrite)
		}
	}
}

func TestRoleAliasesResolveToCanonicalScopes(t *testing.T) {
	for alias, canonical := range roleAliases {
		canonicalScopes, ok := roleScopes[canonical]
		if !ok {
			t.Errorf("role alias %q targets undefined canonical role %q", alias, canonical)
			continue
		}
		if len(canonicalScopes) == 0 {
			t.Errorf("canonical role %q has no scopes", canonical)
		}
		if _, ok := roleScopes[alias]; ok {
			t.Errorf("role alias %q has its own scope definition", alias)
		}

		got := ScopesForRoles([]string{alias})
		want := ScopesForRoles([]string{canonical})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("role alias %q scopes = %#v, canonical role %q scopes = %#v", alias, got, canonical, want)
		}
	}
}

func TestAdminRoleAliasesPreserveAdminBehavior(t *testing.T) {
	for _, role := range []string{RoleCerebroAdmin, "admin", "owner"} {
		if !HasAdminRole([]string{role}) {
			t.Errorf("role %q was not recognized as an admin role", role)
		}
	}

	for _, role := range []string{RoleCerebroViewer, "viewer", "reader", "read_only", RoleCerebroAnalyst, "analyst", "editor"} {
		if HasAdminRole([]string{role}) {
			t.Errorf("role %q was unexpectedly recognized as an admin role", role)
		}
	}
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
