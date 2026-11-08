package cloudidentity

import "testing"

const testAssumeRolePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub":"system:serviceaccount:payments:payments-sa"}}}]}`
const testInlinePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::payments-bucket/*"]}]}`

func crossplaneManifest(apiVersion, kind string, spec map[string]any, name string) Manifest {
	return Manifest{
		Object: map[string]any{
			"apiVersion": apiVersion,
			"kind":       kind,
			"metadata":   map[string]any{"name": name},
			"spec":       spec,
		},
		Reference: Reference{Repository: "github.com/example/platform", Revision: "deadbeef", Path: "compositions/xrole.yaml"},
	}
}

func TestDeclarationsFromManifestsAWSRoleTrustAndGrants(t *testing.T) {
	role := crossplaneManifest("iam.aws.upbound.io/v1beta1", "Role", map[string]any{
		"forProvider": map[string]any{"name": "payments-role", "assumeRolePolicy": testAssumeRolePolicy},
	}, "payments-role")
	inline := crossplaneManifest("iam.aws.upbound.io/v1beta1", "RolePolicy", map[string]any{
		"forProvider": map[string]any{"role": "payments-role", "policy": testInlinePolicy},
	}, "payments-role-inline")
	attachment := crossplaneManifest("iam.aws.upbound.io/v1beta1", "RolePolicyAttachment", map[string]any{
		"forProvider": map[string]any{"role": "payments-role", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
	}, "payments-role-attach")

	declarations, gaps := DeclarationsFromManifests([]Manifest{role, inline, attachment}, "123456789012", "")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %d: %+v", len(declarations), declarations)
	}
	d := declarations[0]
	if d.Principal.ID != "arn:aws:iam::123456789012:role/payments-role" {
		t.Fatalf("unexpected principal ID: %s", d.Principal.ID)
	}
	if d.Principal.Provider != AWS || d.Principal.Kind != manifestInventoryKindAWSRole {
		t.Fatalf("unexpected principal: %+v", d.Principal)
	}
	if len(d.Policy.Trust) != 1 {
		t.Fatalf("expected 1 trust grant from assumeRolePolicy, got %+v", d.Policy.Trust)
	}
	if len(d.Policy.Grants) != 2 {
		t.Fatalf("expected 2 grants (inline policy statement + unexpanded managed policy), got %+v", d.Policy.Grants)
	}
	var sawManagedPolicyRef bool
	for _, g := range d.Policy.Grants {
		if g.Role == "arn:aws:iam::aws:policy/ReadOnlyAccess" {
			sawManagedPolicyRef = true
		}
	}
	if !sawManagedPolicyRef {
		t.Fatalf("expected an unexpanded Grant.Role referencing the attached managed policy ARN, got %+v", d.Policy.Grants)
	}
}

func TestDeclarationsFromManifestsAWSUnresolvedAccountGap(t *testing.T) {
	role := crossplaneManifest("iam.aws.upbound.io/v1beta1", "Role", map[string]any{
		"forProvider": map[string]any{"name": "payments-role"},
	}, "payments-role")
	declarations, gaps := DeclarationsFromManifests([]Manifest{role}, "", "")
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration even without account, got %d", len(declarations))
	}
	if declarations[0].Principal.ID != "payments-role" {
		t.Fatalf("expected fallback ID to the bare role name, got %s", declarations[0].Principal.ID)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.crossplane_declaration.unresolved_account" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unresolved_account gap, got %+v", gaps)
	}
}

func TestDeclarationsFromManifestsGCPServiceAccountAndBinding(t *testing.T) {
	sa := crossplaneManifest("iam.cnrm.cloud.google.com/v1beta1", "IAMServiceAccount", map[string]any{
		"forProvider": map[string]any{"accountId": "billing-gsa"},
	}, "billing-gsa")
	binding := crossplaneManifest("iam.cnrm.cloud.google.com/v1beta1", "IAMPolicyMember", map[string]any{
		"role":        "roles/iam.workloadIdentityUser",
		"member":      "serviceAccount:my-project.svc.id.goog[billing/billing-sa]",
		"resourceRef": map[string]any{"name": "billing-gsa"},
	}, "billing-gsa-binding")

	declarations, gaps := DeclarationsFromManifests([]Manifest{sa, binding}, "", "my-project")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %d", len(declarations))
	}
	d := declarations[0]
	if d.Principal.ID != "billing-gsa@my-project.iam.gserviceaccount.com" {
		t.Fatalf("unexpected GSA email: %s", d.Principal.ID)
	}
	if len(d.Policy.Trust) != 1 || d.Policy.Trust[0].Role != "roles/iam.workloadIdentityUser" {
		t.Fatalf("expected 1 trust grant for the workload identity binding, got %+v", d.Policy.Trust)
	}
}

func TestDeclarationsFromManifestsUnsupportedKindGap(t *testing.T) {
	odd := crossplaneManifest("iam.aws.upbound.io/v1beta1", "InstanceProfile", map[string]any{}, "weird")
	declarations, gaps := DeclarationsFromManifests([]Manifest{odd}, "123456789012", "")
	if len(declarations) != 0 {
		t.Fatalf("expected no declarations for an unsupported kind, got %+v", declarations)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.crossplane_declaration.unsupported_kind" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unsupported_kind gap, got %+v", gaps)
	}
}

func TestDeclarationsFromManifestsRoleNotFoundGap(t *testing.T) {
	inline := crossplaneManifest("iam.aws.upbound.io/v1beta1", "RolePolicy", map[string]any{
		"forProvider": map[string]any{"role": "ghost-role", "policy": testInlinePolicy},
	}, "orphan-policy")
	declarations, gaps := DeclarationsFromManifests([]Manifest{inline}, "123456789012", "")
	if len(declarations) != 0 {
		t.Fatalf("expected no declarations, got %+v", declarations)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.crossplane_declaration.role_not_found" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected role_not_found gap, got %+v", gaps)
	}
}

// The following tests use the exact resource shapes a generic Crossplane
// XRole composition chart composes in production: the namespaced
// "iam.aws.m.upbound.io" / "cloudplatform.gcp.m.upbound.io" API groups, AWS
// RolePolicy's forProvider.roleRef.name (not a bare forProvider.role), a
// Role's forProvider.permissionsBoundary, GCP ServiceAccountIAMMember's
// full projects/.../serviceAccounts/<email> serviceAccountId, and
// ProjectIAMMember's own project/role/member fields (no serviceAccountId
// at all).
const testCrossplaneBoundaryARN = "arn:aws:iam::123456789012:policy/app-role-boundary-cluster-aws"

func TestDeclarationsFromManifestsCrossplaneNamespacedAWSRoleRefAndBoundary(t *testing.T) {
	role := crossplaneManifest("iam.aws.m.upbound.io/v1beta1", "Role", map[string]any{
		"forProvider": map[string]any{
			"assumeRolePolicy":    testAssumeRolePolicy,
			"permissionsBoundary": testCrossplaneBoundaryARN,
		},
	}, "app-role-0123456789abcdef0123")
	inline := crossplaneManifest("iam.aws.m.upbound.io/v1beta1", "RolePolicy", map[string]any{
		"forProvider": map[string]any{
			"roleRef": map[string]any{"name": "app-role-0123456789abcdef0123"},
			"policy":  testInlinePolicy,
		},
	}, "app-role-0123456789abcdef0123")

	declarations, gaps := DeclarationsFromManifests([]Manifest{role, inline}, "123456789012", "")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	d := declarations[0]
	if !d.Policy.Complete {
		t.Fatalf("expected a complete policy, got %+v", d.Policy)
	}
	if len(d.Policy.Trust) != 1 {
		t.Fatalf("expected 1 trust grant from assumeRolePolicy, got %+v", d.Policy.Trust)
	}
	if len(d.Policy.Grants) != 1 {
		t.Fatalf("expected 1 grant from the RolePolicy attached via roleRef.name, got %+v", d.Policy.Grants)
	}
	if len(d.Policy.Boundaries) != 1 || len(d.Policy.Boundaries[0]) != 1 || d.Policy.Boundaries[0][0].Role != testCrossplaneBoundaryARN {
		t.Fatalf("expected 1 boundary layer carrying the permissions boundary ARN, got %+v", d.Policy.Boundaries)
	}
}

func TestDeclarationsFromManifestsCrossplaneAWSRoleSelectorUnsupportedGap(t *testing.T) {
	role := crossplaneManifest("iam.aws.m.upbound.io/v1beta1", "Role", map[string]any{
		"forProvider": map[string]any{"assumeRolePolicy": testAssumeRolePolicy},
	}, "app-role-0123456789abcdef0123")
	inline := crossplaneManifest("iam.aws.m.upbound.io/v1beta1", "RolePolicy", map[string]any{
		"forProvider": map[string]any{
			"roleSelector": map[string]any{"matchLabels": map[string]any{"platform.example.com/owner": "platform-team"}},
			"policy":       testInlinePolicy,
		},
	}, "app-role-0123456789abcdef0123")

	declarations, gaps := DeclarationsFromManifests([]Manifest{role, inline}, "123456789012", "")
	if len(declarations) != 1 {
		t.Fatalf("expected the Role declaration with no grant attached, got %+v", declarations)
	}
	if len(declarations[0].Policy.Grants) != 0 {
		t.Fatalf("expected no grants from an unresolvable roleSelector, got %+v", declarations[0].Policy.Grants)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.crossplane_declaration.role_selector_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected role_selector_unsupported gap, got %+v", gaps)
	}
}

func TestDeclarationsFromManifestsCrossplaneNamespacedGCPTrustAndProjectGrant(t *testing.T) {
	const email = "app-role-0123456789abcdef0123@example-project.iam.gserviceaccount.com"
	sa := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ServiceAccount", map[string]any{
		"forProvider": map[string]any{"project": "example-project", "displayName": "payments-api"},
	}, "app-role-0123456789abcdef0123")
	trust := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ServiceAccountIAMMember", map[string]any{
		"forProvider": map[string]any{
			"serviceAccountId": "projects/example-project/serviceAccounts/" + email,
			"role":             "roles/iam.workloadIdentityUser",
			"member":           "serviceAccount:example-project.svc.id.goog[payments/payments-sa]",
		},
	}, "app-role-0123456789abcdef0123-sa-wi")
	grant := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ProjectIAMMember", map[string]any{
		"forProvider": map[string]any{
			"project": "example-project",
			"role":    "roles/storage.objectAdmin",
			"member":  "serviceAccount:" + email,
		},
	}, "app-role-0123456789abcdef0123-role-abcd1234")

	declarations, gaps := DeclarationsFromManifests([]Manifest{sa, trust, grant}, "", "example-project")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	d := declarations[0]
	if d.Principal.ID != email {
		t.Fatalf("expected the GSA email as principal ID, got %s", d.Principal.ID)
	}
	if len(d.Policy.Trust) != 1 || d.Policy.Trust[0].Role != "roles/iam.workloadIdentityUser" {
		t.Fatalf("expected 1 Workload Identity trust grant normalized from the full serviceAccountId path, got %+v", d.Policy.Trust)
	}
	if len(d.Policy.Grants) != 1 {
		t.Fatalf("expected 1 project-resource grant, got %+v", d.Policy.Grants)
	}
	g := d.Policy.Grants[0]
	if g.Role != "roles/storage.objectAdmin" {
		t.Fatalf("unexpected grant role: %+v", g)
	}
	if len(g.Resources) != 1 || g.Resources[0] != "//cloudresourcemanager.googleapis.com/projects/example-project" {
		t.Fatalf("expected a canonical project resource name, got %+v", g.Resources)
	}
}

// TestDeclarationsFromManifestsCrossplaneProjectIAMMemberNeverSilentlySkipped
// reproduces review finding 13: a ProjectIAMMember missing required fields
// (here: project) used to fail crossplaneGCPBindingFields's generic target
// check and the loop silently `continue`d, leaving the service account
// Complete=true with no grant and no gap.
func TestDeclarationsFromManifestsCrossplaneProjectIAMMemberNeverSilentlySkipped(t *testing.T) {
	const email = "app-role-0123456789abcdef0123@example-project.iam.gserviceaccount.com"
	sa := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ServiceAccount", map[string]any{
		"forProvider": map[string]any{"project": "example-project"},
	}, "app-role-0123456789abcdef0123")
	grant := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ProjectIAMMember", map[string]any{
		"forProvider": map[string]any{
			"role":   "roles/storage.objectAdmin",
			"member": "serviceAccount:" + email,
		},
	}, "app-role-0123456789abcdef0123-role-abcd1234")

	declarations, gaps := DeclarationsFromManifests([]Manifest{sa, grant}, "", "example-project")
	if len(declarations) != 1 {
		t.Fatalf("expected the service account declaration, got %+v", declarations)
	}
	if len(declarations[0].Policy.Grants) != 0 {
		t.Fatalf("expected no grant from the unresolvable ProjectIAMMember, got %+v", declarations[0].Policy.Grants)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.crossplane_declaration.binding_unresolved" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected binding_unresolved gap instead of a silent skip, got %+v", gaps)
	}
}

// crossplaneCustomRoleManifest builds a ProjectIAMCustomRole-shaped
// composed resource with the roleId carried on the
// "crossplane.io/external-name" annotation (crossplaneManifest has no
// annotation support), optionally declaring `stage`.
func crossplaneCustomRoleManifest(name, roleID, project, stage string, permissions []string) Manifest {
	permsAny := make([]any, len(permissions))
	for i, p := range permissions {
		permsAny[i] = p
	}
	forProvider := map[string]any{
		"project":     project,
		"permissions": permsAny,
	}
	if stage != "" {
		forProvider["stage"] = stage
	}
	return Manifest{
		Object: map[string]any{
			"apiVersion": "cloudplatform.gcp.m.upbound.io/v1beta1",
			"kind":       "ProjectIAMCustomRole",
			"metadata": map[string]any{
				"name":        name,
				"annotations": map[string]any{"crossplane.io/external-name": roleID},
			},
			"spec": map[string]any{"forProvider": forProvider},
		},
		Reference: Reference{Repository: "github.com/example/platform", Revision: "deadbeef", Path: "compositions/xrole.yaml"},
	}
}

// TestDeclarationsFromManifestsCrossplaneDisabledCustomRoleInert reproduces
// the review finding: a declared ProjectIAMCustomRole with `stage: DISABLED`
// used to be indexed and inlined like any active role, letting a
// ProjectIAMMember binding to it produce a live excess grant for
// permissions IAM would never actually grant through a disabled role.
// Binding semantic 3 requires the binding to be inert: no grant, no gap.
func TestDeclarationsFromManifestsCrossplaneDisabledCustomRoleInert(t *testing.T) {
	const email = "app-role-0123456789abcdef0123@example-project.iam.gserviceaccount.com"
	sa := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ServiceAccount", map[string]any{
		"forProvider": map[string]any{"project": "example-project", "displayName": "payments-api"},
	}, "app-role-0123456789abcdef0123")
	role := crossplaneCustomRoleManifest("app-role-custom", "app_role_custom", "example-project", "DISABLED", []string{"storage.objects.get"})
	grant := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ProjectIAMMember", map[string]any{
		"forProvider": map[string]any{
			"project": "example-project",
			"role":    "projects/example-project/roles/app_role_custom",
			"member":  "serviceAccount:" + email,
		},
	}, "app-role-0123456789abcdef0123-role-abcd1234")

	declarations, gaps := DeclarationsFromManifests([]Manifest{sa, role, grant}, "", "example-project")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps for a binding to a DISABLED custom role, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	if len(declarations[0].Policy.Grants) != 0 {
		t.Fatalf("expected the binding to a DISABLED custom role to be inert (no grant), got %+v", declarations[0].Policy.Grants)
	}
}

// TestDeclarationsFromManifestsCrossplaneActiveCustomRoleStillInlined is the
// control for TestDeclarationsFromManifestsCrossplaneDisabledCustomRoleInert:
// an active (stage: GA) declared custom role must still have its ownbatch
// permissions inlined into the grant exactly as before.
func TestDeclarationsFromManifestsCrossplaneActiveCustomRoleStillInlined(t *testing.T) {
	const email = "app-role-0123456789abcdef0123@example-project.iam.gserviceaccount.com"
	sa := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ServiceAccount", map[string]any{
		"forProvider": map[string]any{"project": "example-project", "displayName": "payments-api"},
	}, "app-role-0123456789abcdef0123")
	role := crossplaneCustomRoleManifest("app-role-custom", "app_role_custom", "example-project", "GA", []string{"storage.objects.get", "storage.objects.list"})
	grant := crossplaneManifest("cloudplatform.gcp.m.upbound.io/v1beta1", "ProjectIAMMember", map[string]any{
		"forProvider": map[string]any{
			"project": "example-project",
			"role":    "projects/example-project/roles/app_role_custom",
			"member":  "serviceAccount:" + email,
		},
	}, "app-role-0123456789abcdef0123-role-abcd1234")

	declarations, gaps := DeclarationsFromManifests([]Manifest{sa, role, grant}, "", "example-project")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	if len(declarations[0].Policy.Grants) != 1 {
		t.Fatalf("expected 1 inlined grant, got %+v", declarations[0].Policy.Grants)
	}
	g := declarations[0].Policy.Grants[0]
	if g.Role != "" {
		t.Fatalf("expected the active custom role grant to be inlined (Role empty), got Role=%q", g.Role)
	}
	if len(g.Actions) != 2 {
		t.Fatalf("expected the declared permissions inlined into Actions, got %+v", g.Actions)
	}
}
