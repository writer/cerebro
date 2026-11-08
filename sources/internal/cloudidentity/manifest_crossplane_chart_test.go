package cloudidentitysource

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// loadChartFiles reads every file under testdata/<dirName> on disk into a
// repository file map keyed "<chart>/<relative path>", matching
// buildInlineRepository's layout. testdata/xrole-composition is a small,
// fully synthetic chart (no real infrastructure identifiers) reproducing
// the shape of a production XRole XRD + per-cloud Composition + capability-
// profile chart: one CompositeResourceDefinition, one Composition per cloud
// (pipeline function-environment-configs -> function-go-templating ->
// function-auto-ready, with the fan-out template body loaded via
// .Files.Get), an EnvironmentConfig, and a GCP ProjectIAMCustomRole minted
// per capability package.
func loadChartFiles(t *testing.T, dirName, chart string) map[string]string {
	t.Helper()
	root := filepath.Join("testdata", dirName)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(p) //nolint:gosec // test-only read of a fixed testdata tree walked above.
		if err != nil {
			return err
		}
		out[chart+"/"+filepath.ToSlash(rel)] = string(content)
		return nil
	})
	if err != nil {
		t.Fatalf("load chart testdata %q: %v", root, err)
	}
	return out
}

// chartXRoleClaim is a documented XRole claim shape: access deliberately
// names one bare capability profile rather than a package, so the composed
// GCP binding count and AWS action list are predictable without needing
// the custom-role-minting path.
func chartXRoleClaim(name, namespace string) ci.Manifest {
	return chartXRoleClaimWithAccess(name, namespace, []string{"object-store"})
}

// chartXRoleClaimWithAccess is chartXRoleClaim with an explicit spec.access
// list, so a test can instead select a capability PACKAGE (e.g. "standard")
// and exercise the GCP custom-role-minting/binding path.
func chartXRoleClaimWithAccess(name, namespace string, access []string) ci.Manifest {
	accessAny := make([]any, len(access))
	for i, a := range access {
		accessAny[i] = a
	}
	return ci.Manifest{Object: map[string]any{
		"apiVersion": "platform.example.com/v1alpha1",
		"kind":       "XRole",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"labels": map[string]any{
				"app.kubernetes.io/managed-by": "crossplane",
				"platform.example.com/owner":   "platform-team",
			},
		},
		"spec": map[string]any{
			"owner":              "platform-team",
			"serviceName":        name,
			"serviceAccountName": name + "-ksa",
			"access":             accessAny,
		},
	}}
}

func newChartCrossplaneRenderer() *manifestRenderer {
	return &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}
}

func renderChartCrossplaneCompositions(t *testing.T, valuesFile string) []ci.Manifest {
	t.Helper()
	files := loadChartFiles(t, "xrole-composition", "xrole-composition")
	repo := buildInlineRepository("github.com/example-org/gitops", "deadbeef", files)
	r := newChartCrossplaneRenderer()
	manifests, gaps, err := r.Render(testContext(), ci.ManifestRequest{
		Repository:  repo,
		Chart:       "xrole-composition",
		Release:     "xrole-composition",
		Namespace:   "crossplane-system",
		ValuesFiles: []string{valuesFile},
	})
	if err != nil {
		t.Fatalf("render xrole-composition chart (%s): %v", valuesFile, err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no render gaps for %s, got %+v", valuesFile, gaps)
	}
	return manifests
}

// TestCrossplaneCompositionAWSRoleAndPolicy renders the synthetic
// xrole-composition chart with its cluster-aws (AWS) host-cluster values,
// composes it against an XRole claim, and asserts Compose yields a Role +
// RolePolicy whose trust/inline-policy/boundary survive into
// DeclarationsFromManifests.
func TestCrossplaneCompositionAWSRoleAndPolicy(t *testing.T) {
	infra := renderChartCrossplaneCompositions(t, "values/host-clusters/cluster-aws.yaml")
	claim := chartXRoleClaim("payments", "payments")

	r := newChartCrossplaneRenderer()
	composed, gaps, err := r.Compose(testContext(), ci.ComposeRequest{
		Manifests:   append(append([]ci.Manifest{}, infra...), claim),
		Environment: "prod",
		Cluster:     "cluster-aws",
	})
	if err != nil {
		t.Fatalf("unexpected Compose error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no Compose gaps, got %+v", gaps)
	}

	var sawRole, sawRolePolicy bool
	for _, m := range composed {
		switch manifestStringField(m.Object, "kind") {
		case "Role":
			sawRole = true
			boundary, _ := manifestNestedString(m.Object, "spec", "forProvider", "permissionsBoundary")
			if boundary != "arn:aws:iam::123456789012:policy/app-role-boundary-cluster-aws" {
				t.Fatalf("expected the composed Role to carry the cluster's permissions boundary ARN, got %q", boundary)
			}
			assumeDoc, _ := manifestNestedString(m.Object, "spec", "forProvider", "assumeRolePolicy")
			if assumeDoc == "" {
				t.Fatalf("expected a non-empty assumeRolePolicy trust document")
			}
		case "RolePolicy":
			sawRolePolicy = true
			roleRef, _ := manifestNestedString(m.Object, "spec", "forProvider", "roleRef", "name")
			if roleRef == "" {
				t.Fatalf("expected the composed RolePolicy to carry roleRef.name")
			}
			policy, _ := manifestNestedString(m.Object, "spec", "forProvider", "policy")
			if policy == "" || !containsSubstring(policy, "s3:") {
				t.Fatalf("expected the inline policy to include the object-store profile's s3:* action, got %q", policy)
			}
		}
	}
	if !sawRole || !sawRolePolicy {
		t.Fatalf("expected a composed Role and RolePolicy, got %+v", composed)
	}

	declarations, declGaps := ci.DeclarationsFromManifests(composed, "123456789012", "")
	if len(declGaps) != 0 {
		t.Fatalf("expected no declaration gaps, got %+v", declGaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 AWS declaration, got %+v", declarations)
	}
	d := declarations[0]
	if d.Principal.Provider != ci.AWS {
		t.Fatalf("expected an AWS principal, got %+v", d.Principal)
	}
	if len(d.Policy.Trust) != 1 {
		t.Fatalf("expected 1 trust grant from the OIDC AssumeRoleWithWebIdentity statement, got %+v", d.Policy.Trust)
	}
	if len(d.Policy.Grants) == 0 {
		t.Fatalf("expected at least 1 grant from the inline RolePolicy, got %+v", d.Policy.Grants)
	}
	if len(d.Policy.Boundaries) != 1 || len(d.Policy.Boundaries[0]) != 1 || d.Policy.Boundaries[0][0].Role != "arn:aws:iam::123456789012:policy/app-role-boundary-cluster-aws" {
		t.Fatalf("expected 1 boundary layer carrying the cluster's boundary ARN, got %+v", d.Policy.Boundaries)
	}
}

// TestCrossplaneCompositionGCPServiceAccountAndBindings renders the
// synthetic chart with its cluster-gcp (GCP) host-cluster values and
// asserts Compose yields a ServiceAccount, a Workload Identity trust
// binding, and a ProjectIAMMember grant that survive into
// DeclarationsFromManifests as trust + a project-resource grant.
func TestCrossplaneCompositionGCPServiceAccountAndBindings(t *testing.T) {
	infra := renderChartCrossplaneCompositions(t, "values/host-clusters/cluster-gcp.yaml")
	claim := chartXRoleClaim("payments", "payments")

	r := newChartCrossplaneRenderer()
	composed, gaps, err := r.Compose(testContext(), ci.ComposeRequest{
		Manifests:   append(append([]ci.Manifest{}, infra...), claim),
		Environment: "dev",
		Cluster:     "cluster-gcp",
	})
	if err != nil {
		t.Fatalf("unexpected Compose error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no Compose gaps, got %+v", gaps)
	}

	var sawSA, sawTrust, sawGrant bool
	for _, m := range composed {
		switch manifestStringField(m.Object, "kind") {
		case "ServiceAccount":
			sawSA = true
		case "ServiceAccountIAMMember":
			sawTrust = true
			role, _ := manifestNestedString(m.Object, "spec", "forProvider", "role")
			if role != "roles/iam.workloadIdentityUser" {
				t.Fatalf("expected the Workload Identity binding role, got %q", role)
			}
		case "ProjectIAMMember":
			sawGrant = true
			project, _ := manifestNestedString(m.Object, "spec", "forProvider", "project")
			if project != "example-project" {
				t.Fatalf("expected the composed project grant to scope to example-project, got %q", project)
			}
		}
	}
	if !sawSA || !sawTrust || !sawGrant {
		t.Fatalf("expected a composed ServiceAccount, ServiceAccountIAMMember and ProjectIAMMember, got %+v", composed)
	}

	declarations, declGaps := ci.DeclarationsFromManifests(composed, "", "example-project")
	if len(declGaps) != 0 {
		t.Fatalf("expected no declaration gaps, got %+v", declGaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 GCP declaration, got %+v", declarations)
	}
	d := declarations[0]
	if d.Principal.Provider != ci.GCP {
		t.Fatalf("expected a GCP principal, got %+v", d.Principal)
	}
	if len(d.Policy.Trust) != 1 || d.Policy.Trust[0].Role != "roles/iam.workloadIdentityUser" {
		t.Fatalf("expected 1 Workload Identity trust grant, got %+v", d.Policy.Trust)
	}
	if len(d.Policy.Grants) != 1 {
		t.Fatalf("expected 1 project-resource grant, got %+v", d.Policy.Grants)
	}
	g := d.Policy.Grants[0]
	if g.Role != "roles/storage.objectAdmin" {
		t.Fatalf("expected the object-store profile's predefined role, got %q", g.Role)
	}
	if len(g.Resources) != 1 || g.Resources[0] != "//cloudresourcemanager.googleapis.com/projects/example-project" {
		t.Fatalf("expected a canonical project resource name, got %+v", g.Resources)
	}
}

// TestCrossplaneComposeUnmatchedClaimGap reproduces the exact defect
// described by the review: an XRole recognized by its
// CompositeResourceDefinition but whose Composition is not among the
// target's aggregated manifests must be a scoped gap, not a silently
// skipped claim.
func TestCrossplaneComposeUnmatchedClaimGap(t *testing.T) {
	infra := renderChartCrossplaneCompositions(t, "values/host-clusters/cluster-aws.yaml")
	var withoutComposition []ci.Manifest
	for _, m := range infra {
		if manifestStringField(m.Object, "kind") == "Composition" {
			continue
		}
		withoutComposition = append(withoutComposition, m)
	}
	claim := chartXRoleClaim("payments", "payments")

	r := newChartCrossplaneRenderer()
	composed, gaps, err := r.Compose(testContext(), ci.ComposeRequest{
		Manifests:   append(append([]ci.Manifest{}, withoutComposition...), claim),
		Environment: "prod",
		Cluster:     "cluster-aws",
	})
	if err != nil {
		t.Fatalf("unexpected Compose error: %v", err)
	}
	if len(composed) != 0 {
		t.Fatalf("expected no composed resources for an unmatched claim, got %+v", composed)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_composition_not_found" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected crossplane_composition_not_found gap, got %+v", gaps)
	}
}

// TestCrossplaneGoTemplatingRandIntRejected proves the deterministic
// function allowlist rejects Sprig's randInt (present in sprig.TxtFuncMap
// but absent from Helm's own nonhermeticFunctions list, so a blocklist
// copied from there misses it) before the template ever executes.
func TestCrossplaneGoTemplatingRandIntRejected(t *testing.T) {
	tmpl := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: roll-{{ randInt 1 100 }}\n"
	comp := xroleComposition([]any{
		map[string]any{"step": "template", "functionRef": map[string]any{"name": "function-go-templating"}, "input": map[string]any{"inline": map[string]any{"template": tmpl}}},
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(composed) != 0 {
		t.Fatalf("expected randInt reference to abort the step before execution, got %+v", composed)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_nondeterministic_template" {
			found = true
			if !containsSubstring(g.Message, "randInt") {
				t.Fatalf("expected the gap message to name randInt, got %q", g.Message)
			}
		}
	}
	if !found {
		t.Fatalf("expected crossplane_nondeterministic_template gap, got %+v", gaps)
	}
}

func containsSubstring(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// TestCrossplaneCompositionGCPCustomRoleDeclaredGrant reproduces the gap
// E2EProof found: selecting a capability PACKAGE (not a bare profile)
// binds a ProjectIAMMember to a cluster-minted ProjectIAMCustomRole
// (templates/gcp-custom-roles.yaml). DeclarationsFromManifests must
// recognize that kind (no unsupported_kind gap) and resolve the
// ProjectIAMMember's grant from the custom role's own declared permissions
// -- inlined into Grant.Actions with Grant.Role left empty, matching how
// expandGrantLayer already treats a Role-less Grant -- rather than leaving
// an unexpanded Grant.Role that would stay stuck on live Definitions.Roles.
func TestCrossplaneCompositionGCPCustomRoleDeclaredGrant(t *testing.T) {
	infra := renderChartCrossplaneCompositions(t, "values/host-clusters/cluster-gcp.yaml")
	claim := chartXRoleClaimWithAccess("payments", "payments", []string{"standard"})

	r := newChartCrossplaneRenderer()
	composed, gaps, err := r.Compose(testContext(), ci.ComposeRequest{
		Manifests:   append(append([]ci.Manifest{}, infra...), claim),
		Environment: "dev",
		Cluster:     "cluster-gcp",
	})
	if err != nil {
		t.Fatalf("unexpected Compose error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no Compose gaps, got %+v", gaps)
	}

	const wantRole = "projects/example-project/roles/app_role_custom_standard_cluster_gcp"
	var sawBinding bool
	for _, m := range composed {
		if manifestStringField(m.Object, "kind") != "ProjectIAMMember" {
			continue
		}
		role, _ := manifestNestedString(m.Object, "spec", "forProvider", "role")
		if role == wantRole {
			sawBinding = true
		}
	}
	if !sawBinding {
		t.Fatalf("expected a ProjectIAMMember bound to the minted custom role %q, got %+v", wantRole, composed)
	}

	declarations, declGaps := ci.DeclarationsFromManifests(append(append([]ci.Manifest{}, infra...), composed...), "", "example-project")
	for _, g := range declGaps {
		if g.Code == "cloud_identity.crossplane_declaration.unsupported_kind" {
			t.Fatalf("ProjectIAMCustomRole must not be an unsupported_kind gap, got %+v", declGaps)
		}
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 GCP declaration, got %+v", declarations)
	}
	d := declarations[0]
	if !d.Policy.Complete {
		t.Fatalf("expected a complete declared policy, got %+v", d.Policy)
	}
	var matched bool
	for _, g := range d.Policy.Grants {
		if len(g.Resources) == 1 && g.Resources[0] == "//cloudresourcemanager.googleapis.com/projects/example-project" {
			matched = true
			if g.Role != "" {
				t.Fatalf("expected the custom role grant to be inlined (Role empty), got Role=%q", g.Role)
			}
			if len(g.Actions) == 0 {
				t.Fatalf("expected the custom role's declared permissions inlined into Actions, got %+v", g)
			}
		}
	}
	if !matched {
		t.Fatalf("expected a project-resource grant among %+v", d.Policy.Grants)
	}
}
