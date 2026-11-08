package cloudidentity

import (
	"testing"
)

// ackManifest builds a rendered ACK object in the "payments" namespace shared by
// every fixture, so a PodIdentityAssociation roleRef without its own namespace
// resolves against fixture Roles.
func ackManifest(apiVersion, kind string, spec map[string]any, name string) Manifest {
	return Manifest{
		Object: map[string]any{
			"apiVersion": apiVersion,
			"kind":       kind,
			"metadata":   map[string]any{"name": name, "namespace": "payments"},
			"spec":       spec,
		},
		Reference: Reference{Repository: "github.com/example/k8s", Revision: "deadbeef", Path: "manifests/example-apps/templates/identity.yaml"},
	}
}

const testACKTrustPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":["sts:AssumeRole","sts:TagSession"]}]}`

func TestDeclarationsFromACKRoleTrustInlineManagedAndBoundary(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name":                     "payments-worker",
		"path":                     "/explicit/",
		"assumeRolePolicyDocument": testACKTrustPolicy,
		"inlinePolicies":           map[string]any{"s3-read": testInlinePolicy},
		"policies":                 []any{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		"permissionsBoundary":      "arn:aws:iam::123456789012:policy/ack-boundary",
	}, "payments-worker")

	declarations, podIdentities, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "123456789012")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(podIdentities) != 0 {
		t.Fatalf("expected no pod identity declarations without a PodIdentityAssociation, got %+v", podIdentities)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %d: %+v", len(declarations), declarations)
	}
	d := declarations[0]
	wantARN := "arn:aws:iam::123456789012:role/explicit/payments-worker"
	if d.Principal.ID != wantARN {
		t.Fatalf("unexpected principal ID: got %s want %s", d.Principal.ID, wantARN)
	}
	if d.Principal.Provider != AWS || d.Principal.Kind != manifestInventoryKindAWSRole {
		t.Fatalf("unexpected principal: %+v", d.Principal)
	}
	if len(d.Policy.Trust) != 1 {
		t.Fatalf("expected 1 trust grant from assumeRolePolicyDocument, got %+v", d.Policy.Trust)
	}
	if len(d.Policy.Grants) != 2 {
		t.Fatalf("expected 2 grants (inline policy statement + unresolved managed policy), got %+v", d.Policy.Grants)
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
	if len(d.Policy.Boundaries) != 1 || d.Policy.Boundaries[0][0].Role != "arn:aws:iam::123456789012:policy/ack-boundary" {
		t.Fatalf("expected 1 unresolved boundary layer, got %+v", d.Policy.Boundaries)
	}
}

// TestDeclarationsFromACKRoleDefaultPath reproduces the ACK IAM Role CRD's
// documented default: when spec.path is unset, AWS (and the IAM Role CRD)
// default it to "/".
func TestDeclarationsFromACKRoleDefaultPath(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name":                     "payments-worker",
		"assumeRolePolicyDocument": testACKTrustPolicy,
	}, "payments-worker")

	declarations, _, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "123456789012")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	wantARN := "arn:aws:iam::123456789012:role/payments-worker"
	if declarations[0].Principal.ID != wantARN {
		t.Fatalf("unexpected principal ID: got %s want %s", declarations[0].Principal.ID, wantARN)
	}
}

// TestDeclarationsFromACKRoleInvalidPathGap reproduces IAM's path syntax
// requirement: a path must start and end with "/".
func TestDeclarationsFromACKRoleInvalidPathGap(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name":                     "payments-worker",
		"path":                     "not-a-path",
		"assumeRolePolicyDocument": testACKTrustPolicy,
	}, "payments-worker")

	declarations, _, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "123456789012")
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration even without a resolvable ARN, got %d", len(declarations))
	}
	if declarations[0].Principal.ID != "payments-worker" {
		t.Fatalf("expected the fallback bare name as ID when the path is invalid, got %s", declarations[0].Principal.ID)
	}
	var sawGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.role_path_invalid" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected a role_path_invalid gap, got %+v", gaps)
	}
}

// TestDeclarationsFromACKRoleSpecNameMissingGap reproduces the required
// ACK IAM Role CRD field: spec.name is mandatory, and its absence must
// never fall back to a guessed name.
func TestDeclarationsFromACKRoleSpecNameMissingGap(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"assumeRolePolicyDocument": testACKTrustPolicy,
	}, "payments-worker")

	declarations, _, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "123456789012")
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration even without spec.name, got %d", len(declarations))
	}
	if declarations[0].Principal.ID != "payments-worker" {
		t.Fatalf("expected the fallback bare metadata.name as ID when spec.name is missing, got %s", declarations[0].Principal.ID)
	}
	var sawGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.role_spec_name_missing" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected a role_spec_name_missing gap, got %+v", gaps)
	}
}

// TestDeclarationsFromACKRoleLongNameVerbatim reproduces IAM's own role
// name length enforcement: this package never truncates or hashes
// spec.name, it takes it verbatim, however long.
func TestDeclarationsFromACKRoleLongNameVerbatim(t *testing.T) {
	longName := "a-very-long-identity-name-that-exceeds-sixty-four-characters-in-total-length"
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name":                     longName,
		"assumeRolePolicyDocument": testACKTrustPolicy,
	}, "payments-worker")

	declarations, _, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "123456789012")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	wantARN := "arn:aws:iam::123456789012:role/" + longName
	if declarations[0].Principal.ID != wantARN {
		t.Fatalf("unexpected principal ID: got %s want %s", declarations[0].Principal.ID, wantARN)
	}
}

// TestDeclarationsFromACKRoleBoundaryUnresolvedMarkerKeepsPolicyIncomplete
// reproduces finding #1's ACK-specific requirement: a permissionsBoundary
// value the manifest renderer bound to an UnresolvedValueMarker (because
// the real value, such as the ACK boundary's AWS-generated ARN, is known
// only to Terraform state this scan never evaluates) must keep the
// declared Role's policy explicitly incomplete -- a scoped gap, never a
// fabricated boundary grant and never a silently unbounded role.
func TestDeclarationsFromACKRoleBoundaryUnresolvedMarkerKeepsPolicyIncomplete(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name":                     "payments-worker",
		"path":                     "/ack/cluster-a/",
		"assumeRolePolicyDocument": testACKTrustPolicy,
		"permissionsBoundary":      UnresolvedValueMarker("ack.permissionsBoundaryArn"),
	}, "payments-worker")

	declarations, _, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "123456789012")
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %d: %+v", len(declarations), declarations)
	}
	d := declarations[0]
	if len(d.Policy.Boundaries) != 0 {
		t.Fatalf("expected no boundary layer fabricated from the unresolved marker, got %+v", d.Policy.Boundaries)
	}
	if d.Policy.Complete {
		t.Fatalf("expected Policy.Complete=false: the boundary is unknown, never silently unbounded")
	}
	var sawDeclGap, sawFunctionGap bool
	for _, g := range d.Policy.Gaps {
		if g.Code == "cloud_identity.ack_declaration.boundary_unresolved" {
			sawDeclGap = true
		}
	}
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.boundary_unresolved" {
			sawFunctionGap = true
		}
	}
	if !sawDeclGap {
		t.Fatalf("expected a boundary_unresolved gap on the declaration's own Policy.Gaps, got %+v", d.Policy.Gaps)
	}
	if !sawFunctionGap {
		t.Fatalf("expected a boundary_unresolved gap among DeclarationsFromACK's returned gaps, got %+v", gaps)
	}
}

// TestUnresolvedValueMarkerKeyRoundTrip pins the marker contract both the
// renderer (manifest_helm.go/manifest_renderer.go) and this package's own
// declaration parsing share: UnresolvedValueMarker produces a value
// UnresolvedValueMarkerKey recovers, including when interpolated inside a
// larger templated string, and an ordinary value never matches.
func TestUnresolvedValueMarkerKeyRoundTrip(t *testing.T) {
	marker := UnresolvedValueMarker("ack.permissionsBoundaryArn")
	key, ok := UnresolvedValueMarkerKey(marker)
	if !ok || key != "ack.permissionsBoundaryArn" {
		t.Fatalf("expected round-trip key %q, got %q ok=%v", "ack.permissionsBoundaryArn", key, ok)
	}
	key, ok = UnresolvedValueMarkerKey("prefix-" + marker + "-suffix")
	if !ok || key != "ack.permissionsBoundaryArn-suffix" {
		t.Fatalf("expected the marker to be found when interpolated in a larger string, got %q ok=%v", key, ok)
	}
	if _, ok := UnresolvedValueMarkerKey("arn:aws:iam::123456789012:policy/ack-boundary"); ok {
		t.Fatalf("expected a real ARN to never be mistaken for an unresolved-value marker")
	}
}

func TestDeclarationsFromACKRoleMissingTrustAndAccountGaps(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name": "payments-worker",
	}, "payments-worker")

	declarations, _, gaps := DeclarationsFromACK([]Manifest{role}, "cluster-a", "")
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration even without account, got %d", len(declarations))
	}
	if declarations[0].Principal.ID != "payments-worker" {
		t.Fatalf("expected the fallback bare name as ID when account is unresolved, got %s", declarations[0].Principal.ID)
	}
	var sawAccountGap, sawTrustGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.unresolved_account" {
			sawAccountGap = true
		}
		if g.Code == "cloud_identity.ack_declaration.trust_missing" {
			sawTrustGap = true
		}
	}
	if !sawAccountGap || !sawTrustGap {
		t.Fatalf("expected unresolved_account and trust_missing gaps, got %+v", gaps)
	}
}

func TestDeclarationsFromACKPodIdentityAssociationExplicitRoleARN(t *testing.T) {
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"clusterName":    "cluster-a",
		"namespace":      "payments",
		"serviceAccount": "worker",
		"roleARN":        "arn:aws:iam::123456789012:role/ack/cluster-a/cluster-a-payments-payments-worker",
	}, "payments-worker-pia")

	declarations, podIdentities, gaps := DeclarationsFromACK([]Manifest{pia}, "cluster-a", "123456789012")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 0 {
		t.Fatalf("expected no Role declarations from a PodIdentityAssociation alone, got %+v", declarations)
	}
	if len(podIdentities) != 1 {
		t.Fatalf("expected 1 pod identity declaration, got %+v", podIdentities)
	}
	pid := podIdentities[0]
	if pid.Cluster != "cluster-a" || pid.Namespace != "payments" || pid.ServiceAccount != "worker" {
		t.Fatalf("unexpected pod identity declaration: %+v", pid)
	}
	if pid.RoleARN != "arn:aws:iam::123456789012:role/ack/cluster-a/cluster-a-payments-payments-worker" {
		t.Fatalf("unexpected RoleARN: %s", pid.RoleARN)
	}
}

func TestDeclarationsFromACKPodIdentityAssociationRoleRefResolvesAgainstCollectedRole(t *testing.T) {
	role := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Role", map[string]any{
		"name":                     "payments-worker",
		"path":                     "/explicit/",
		"assumeRolePolicyDocument": testACKTrustPolicy,
	}, "payments-worker")
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"namespace":      "payments",
		"serviceAccount": "worker",
		"roleRef":        map[string]any{"from": map[string]any{"name": "payments-worker"}},
	}, "payments-worker-pia")

	declarations, podIdentities, gaps := DeclarationsFromACK([]Manifest{role, pia}, "cluster-a", "123456789012")
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 Role declaration, got %+v", declarations)
	}
	wantARN := "arn:aws:iam::123456789012:role/explicit/payments-worker"
	if declarations[0].Principal.ID != wantARN {
		t.Fatalf("unexpected Role ARN: got %s want %s", declarations[0].Principal.ID, wantARN)
	}
	if len(podIdentities) != 1 || podIdentities[0].RoleARN != wantARN {
		t.Fatalf("expected the PodIdentityAssociation's RoleARN to resolve to the collected Role's ARN, got %+v (role %s)", podIdentities, wantARN)
	}
}

// TestDeclarationsFromACKPodIdentityAssociationRoleRefAbsentRoleGap covers
// a roleRef naming an ACK Role that was not rendered in this batch: no
// ARN is synthesized, the association is dropped, and a role_not_found
// gap is reported.
func TestDeclarationsFromACKPodIdentityAssociationRoleRefAbsentRoleGap(t *testing.T) {
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"namespace":      "payments",
		"serviceAccount": "worker",
		"roleRef":        map[string]any{"from": map[string]any{"name": "payments-worker"}},
	}, "payments-worker-pia")

	_, podIdentities, gaps := DeclarationsFromACK([]Manifest{pia}, "cluster-a", "123456789012")
	if len(podIdentities) != 0 {
		t.Fatalf("expected no pod identity declaration when the referenced Role is absent, got %+v", podIdentities)
	}
	var sawGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.role_not_found" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected a role_not_found gap, got %+v", gaps)
	}
}

func TestDeclarationsFromACKPodIdentityAssociationClusterMismatchGap(t *testing.T) {
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"clusterName":    "cluster-b",
		"namespace":      "payments",
		"serviceAccount": "worker",
		"roleARN":        "arn:aws:iam::123456789012:role/ack/cluster-b/cluster-b-payments-payments-worker",
	}, "payments-worker-pia")

	_, podIdentities, gaps := DeclarationsFromACK([]Manifest{pia}, "cluster-a", "123456789012")
	if len(podIdentities) != 1 {
		t.Fatalf("expected the association to still be recorded despite the mismatch, got %+v", podIdentities)
	}
	var sawMismatch bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.pod_identity_cluster_mismatch" {
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Fatalf("expected a pod_identity_cluster_mismatch gap, got %+v", gaps)
	}
}

func TestDeclarationsFromACKPodIdentityAssociationUnresolvedRoleGap(t *testing.T) {
	pia := ackManifest(ackEKSAPIGroup+"/v1alpha1", "PodIdentityAssociation", map[string]any{
		"namespace":      "payments",
		"serviceAccount": "worker",
	}, "payments-worker-pia")

	_, podIdentities, gaps := DeclarationsFromACK([]Manifest{pia}, "cluster-a", "123456789012")
	if len(podIdentities) != 0 {
		t.Fatalf("expected no pod identity declaration without a resolvable role, got %+v", podIdentities)
	}
	var sawGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.pod_identity_role_unresolved" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected a pod_identity_role_unresolved gap, got %+v", gaps)
	}
}

func TestDeclarationsFromACKUnsupportedKindGap(t *testing.T) {
	odd := ackManifest(ackIAMAPIGroup+"/v1alpha1", "Policy", map[string]any{}, "weird")
	declarations, _, gaps := DeclarationsFromACK([]Manifest{odd}, "cluster-a", "123456789012")
	if len(declarations) != 0 {
		t.Fatalf("expected no declarations for an unsupported kind, got %+v", declarations)
	}
	var sawGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.ack_declaration.unsupported_kind" {
			sawGap = true
		}
	}
	if !sawGap {
		t.Fatalf("expected an unsupported_kind gap, got %+v", gaps)
	}
}
