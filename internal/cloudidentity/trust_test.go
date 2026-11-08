package cloudidentity

import "testing"

// TestGCPWorkloadIdentityUserBindingIsLiveRequiresResolvedRoleCapability
// reproduces review finding #3's repro directly: a resolved custom role
// whose name contains "workloadIdentityUser" but grants no actual
// impersonation permission must never admit. It also reproduces finding
// #5: unlike the conservative gap-scoping gates elsewhere, the live
// can_impersonate EDGE must never be confirmed from a role Definitions
// could not resolve -- the graph must never assert proven access from an
// unknown role, even though a hidden gap elsewhere must stay
// conservative about it.
func TestGCPWorkloadIdentityUserBindingIsLiveRequiresResolvedRoleCapability(t *testing.T) {
	member := "serviceAccount:writer-prod.svc.id.goog[payments/api]"
	base := Evidence{
		Observed: PolicyState{Complete: true, Trust: []Grant{{
			Effect: "Allow", Role: "roles/workloadIdentityUserViewer", Members: []string{member},
		}}},
	}

	t.Run("resolved non-capable role never admits", func(t *testing.T) {
		e := base
		e.Definitions = Definitions{Complete: true, Roles: []RoleDefinition{{
			Name: "roles/workloadIdentityUserViewer", Permissions: []string{"iam.serviceAccounts.get"},
		}}}
		if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a resolved role with no impersonation permission must never admit")
		}
	})

	t.Run("unresolved role never confirms the live edge", func(t *testing.T) {
		e := base
		e.Definitions = Definitions{Complete: true}
		if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("an unresolved role must never confirm the live can_impersonate edge (review finding #5)")
		}
	})

	t.Run("resolved capable role admits", func(t *testing.T) {
		e := base
		e.Definitions = Definitions{Complete: true, Roles: []RoleDefinition{{
			Name: "roles/workloadIdentityUserViewer", Permissions: []string{"iam.serviceAccounts.getAccessToken"},
		}}}
		if !GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a resolved role with an impersonation permission must admit")
		}
	})
}

// TestGCPWorkloadIdentityUserBindingIsLiveRequiresUnconditionalBinding
// reproduces review finding #5: a resolved, impersonation-capable role is
// not enough -- the edge must never be confirmed from a binding whose CEL
// condition is not provably "true" (unresolvable, or any other
// expression such as a literal "false"), since whether that condition
// actually admits this exact subject is unknown and the edge must never
// guess. A binding with no condition, or whose every condition is the
// literal expression "true", still admits.
func TestGCPWorkloadIdentityUserBindingIsLiveRequiresUnconditionalBinding(t *testing.T) {
	member := "serviceAccount:writer-prod.svc.id.goog[payments/api]"
	defs := Definitions{Complete: true, Roles: []RoleDefinition{{
		Name: "roles/iam.workloadIdentityUser", Permissions: []string{"iam.serviceAccounts.getAccessToken"},
	}}}

	t.Run("false condition never admits", func(t *testing.T) {
		e := Evidence{
			Observed: PolicyState{Complete: true, Trust: []Grant{{
				Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{member},
				Conditions: []Condition{{Expression: "false"}},
			}}},
			Definitions: defs,
		}
		if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a binding with a false condition must never confirm the live edge")
		}
	})

	t.Run("unevaluated condition never admits", func(t *testing.T) {
		e := Evidence{
			Observed: PolicyState{Complete: true, Trust: []Grant{{
				Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{member},
				Conditions: []Condition{{Expression: "resource.name.startsWith(\"projects/_/buckets/payments\")"}},
			}}},
			Definitions: defs,
		}
		if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a binding whose condition this package cannot evaluate must never confirm the live edge")
		}
	})

	t.Run("literal true condition still admits", func(t *testing.T) {
		e := Evidence{
			Observed: PolicyState{Complete: true, Trust: []Grant{{
				Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{member},
				Conditions: []Condition{{Expression: "true"}},
			}}},
			Definitions: defs,
		}
		if !GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a binding whose only condition is the literal expression \"true\" must still admit")
		}
	})

	t.Run("no condition still admits", func(t *testing.T) {
		e := Evidence{
			Observed: PolicyState{Complete: true, Trust: []Grant{{
				Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{member},
			}}},
			Definitions: defs,
		}
		if !GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("an unconditional binding must still admit")
		}
	})
}

// TestGCPWorkloadIdentityUserBindingIsLiveNeverAdmitsCustomPoolMember
// reproduces Contract A.4's boundary: a custom (non-GKE) Workload Identity
// Federation pool member must never be admitted by this gate, even with
// an exact-looking namespace/serviceAccount subject and a capable role --
// whether that custom-pool member actually admits is a detection decision
// VulnView makes from GCPWorkloadIdentityProviders, never Cerebro's native
// graph projection.
func TestGCPWorkloadIdentityUserBindingIsLiveNeverAdmitsCustomPoolMember(t *testing.T) {
	customPoolMember := "principal://iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/example-cell-eks/subject/system:serviceaccount:payments:api"
	e := Evidence{
		Observed: PolicyState{Complete: true, Trust: []Grant{{
			Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{customPoolMember},
		}}},
		Definitions: Definitions{Complete: true},
	}
	if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
		t.Fatal("a custom-pool member must never be admitted by this native-graph gate (Contract A.4 is a detector-side decision)")
	}
}

// TestGCPWorkloadIdentityUserBindingIsLiveRequiresMatchingProjectNumber: a
// "principal://.../projects/<number>/..." member must carry the project
// number the live GCP reader resolved for the caller's project
// (ResolvedIdentifiers["gcp_project_number:"+project]); a member minted
// under a different numeric project, or with no collected number, never
// confirms the live can_impersonate edge.
func TestGCPWorkloadIdentityUserBindingIsLiveRequiresMatchingProjectNumber(t *testing.T) {
	member := "principal://iam.googleapis.com/projects/999999999999/locations/global/workloadIdentityPools/writer-prod.svc.id.goog/subject/ns/payments/sa/api"
	defs := Definitions{Complete: true, Roles: []RoleDefinition{{
		Name: "roles/iam.workloadIdentityUser", Permissions: []string{"iam.serviceAccounts.getAccessToken"},
	}}}
	base := Evidence{
		Observed: PolicyState{Complete: true, Trust: []Grant{{
			Effect: "Allow", Role: "roles/iam.workloadIdentityUser", Members: []string{member},
		}}},
		Definitions: defs,
	}

	t.Run("matching project number admits", func(t *testing.T) {
		e := base
		e.ResolvedIdentifiers = map[string]string{"gcp_project_number:writer-prod": "999999999999"}
		if !GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a member whose embedded project number matches the collected caller project number must admit")
		}
	})

	t.Run("mismatched project number never admits", func(t *testing.T) {
		e := base
		e.ResolvedIdentifiers = map[string]string{"gcp_project_number:writer-prod": "111111111111"}
		if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("a member minted under a different numeric project must never confirm the live can_impersonate edge")
		}
	})

	t.Run("unresolved expected project number never admits", func(t *testing.T) {
		e := base
		e.ResolvedIdentifiers = nil
		if GCPWorkloadIdentityUserBindingIsLive(e, "writer-prod", "payments", "api") {
			t.Fatal("an unknown expected project number must never admit: this gate asserts proven access")
		}
	})
}
