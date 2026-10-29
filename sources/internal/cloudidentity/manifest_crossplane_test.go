package cloudidentitysource

import (
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

const crossplaneAssumeRolePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`

func xroleComposition(steps []any) ci.Manifest {
	return ci.Manifest{
		Object: map[string]any{
			"apiVersion": "apiextensions.crossplane.io/v1",
			"kind":       "Composition",
			"metadata":   map[string]any{"name": "xrole-composition"},
			"spec": map[string]any{
				"mode":             "Pipeline",
				"compositeTypeRef": map[string]any{"apiVersion": "aws.platform.example.com/v1alpha1", "kind": "XRole"},
				"pipeline":         steps,
			},
		},
		Reference: ci.Reference{Repository: "github.com/example/platform", Revision: "deadbeef", Path: "compositions/xrole.yaml"},
	}
}

// xroleXRD is a legacy v1 CompositeResourceDefinition declaring both the
// canonical composite kind (XRole, matching xroleComposition's own
// compositeTypeRef) and a separate legacy claim kind (XRoleClaim) under the
// same group/referenceable version.
func xroleXRD() ci.Manifest {
	return ci.Manifest{Object: map[string]any{
		"apiVersion": "apiextensions.crossplane.io/v1",
		"kind":       "CompositeResourceDefinition",
		"metadata":   map[string]any{"name": "xroles.aws.platform.example.com"},
		"spec": map[string]any{
			"group":      "aws.platform.example.com",
			"names":      map[string]any{"kind": "XRole", "plural": "xroles"},
			"claimNames": map[string]any{"kind": "XRoleClaim", "plural": "xroleclaims"},
			"versions": []any{
				map[string]any{"name": "v1alpha1", "served": true, "referenceable": true},
			},
		},
	}}
}

// xroleClaimInstance is the legacy claim form of xroleInstance: same
// apiVersion/group as the composite but the XRD's claim kind, which a
// Composition's compositeTypeRef never names directly.
func xroleClaimInstance() ci.Manifest {
	return ci.Manifest{Object: map[string]any{
		"apiVersion": "aws.platform.example.com/v1alpha1",
		"kind":       "XRoleClaim",
		"metadata":   map[string]any{"name": "payments-role-claim", "namespace": "payments"},
		"spec":       map[string]any{"parameters": map[string]any{"roleName": "payments-role", "assumeRolePolicy": crossplaneAssumeRolePolicy}},
	}}
}

// TestCrossplaneClaimComposesViaCanonicalCompositeType reproduces the
// review finding: a legacy claim plus its XRD plus a Composition targeting
// the canonical composite kind (never the claim kind) must still compose,
// not report an unmatched-composite gap with zero resources.
func TestCrossplaneClaimComposesViaCanonicalCompositeType(t *testing.T) {
	comp := xroleComposition([]any{
		patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.assumeRolePolicy", "toFieldPath": "spec.forProvider.assumeRolePolicy"},
		}),
	})
	xrd := xroleXRD()
	claim := xroleClaimInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{xrd, comp, claim}, manifestDefaultMaxCrossplaneSteps)
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps composing a legacy claim via its XRD's canonical composite type, got %+v", gaps)
	}
	if len(composed) != 1 {
		t.Fatalf("expected 1 composed resource from the claim, got %+v", composed)
	}
	name, _ := manifestNestedString(composed[0].Object, "spec", "forProvider", "name")
	if name != "payments-role" {
		t.Fatalf("expected patched name payments-role, got %q", name)
	}
}

// TestCrossplaneCanonicalCompositeClaimStillComposes is the control for
// TestCrossplaneClaimComposesViaCanonicalCompositeType: an instance of the
// composite's OWN canonical kind (not the legacy claim kind), alongside the
// same XRD, must still compose exactly as before.
func TestCrossplaneCanonicalCompositeClaimStillComposes(t *testing.T) {
	comp := xroleComposition([]any{
		patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
		}),
	})
	xrd := xroleXRD()
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{xrd, comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(composed) != 1 {
		t.Fatalf("expected 1 composed resource, got %+v", composed)
	}
	name, _ := manifestNestedString(composed[0].Object, "spec", "forProvider", "name")
	if name != "payments-role" {
		t.Fatalf("expected patched name payments-role, got %q", name)
	}
}

func xroleInstance() ci.Manifest {
	return ci.Manifest{Object: map[string]any{
		"apiVersion": "aws.platform.example.com/v1alpha1",
		"kind":       "XRole",
		"metadata":   map[string]any{"name": "payments-role-xr"},
		"spec":       map[string]any{"parameters": map[string]any{"roleName": "payments-role", "assumeRolePolicy": crossplaneAssumeRolePolicy}},
	}}
}

func patchAndTransformStep(patches []any) map[string]any {
	return map[string]any{
		"step":        "compose",
		"functionRef": map[string]any{"name": "function-patch-and-transform"},
		"input": map[string]any{
			"resources": []any{
				map[string]any{
					"name": "role",
					"base": map[string]any{
						"apiVersion": "iam.aws.upbound.io/v1beta1",
						"kind":       "Role",
						"spec":       map[string]any{"forProvider": map[string]any{}},
					},
					"patches": patches,
				},
			},
		},
	}
}

func TestCrossplanePatchAndTransformComposesXRoleParity(t *testing.T) {
	comp := xroleComposition([]any{
		patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.assumeRolePolicy", "toFieldPath": "spec.forProvider.assumeRolePolicy"},
		}),
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(composed) != 1 {
		t.Fatalf("expected 1 composed resource, got %d: %+v", len(composed), composed)
	}
	role := composed[0]
	if manifestStringField(role.Object, "kind") != "Role" {
		t.Fatalf("expected a composed Role, got %+v", role.Object)
	}
	name, _ := manifestNestedString(role.Object, "spec", "forProvider", "name")
	if name != "payments-role" {
		t.Fatalf("expected patched name payments-role, got %q", name)
	}
	assumePolicy, _ := manifestNestedString(role.Object, "spec", "forProvider", "assumeRolePolicy")
	if assumePolicy != crossplaneAssumeRolePolicy {
		t.Fatalf("expected patched assumeRolePolicy to match, got %q", assumePolicy)
	}

	// Parity: the composed resource is itself a declaration-bearing manifest,
	// exercised through the same pure DeclarationsFromManifests path a
	// hand-authored Terraform aws_iam_role resource would be.
	declarations, declGaps := ci.DeclarationsFromManifests(composed, "123456789012", "")
	if len(declGaps) != 0 {
		t.Fatalf("expected no declaration gaps, got %+v", declGaps)
	}
	if len(declarations) != 1 {
		t.Fatalf("expected 1 declaration, got %+v", declarations)
	}
	if declarations[0].Principal.ID != "arn:aws:iam::123456789012:role/payments-role" {
		t.Fatalf("unexpected declared principal: %+v", declarations[0].Principal)
	}
	if len(declarations[0].Policy.Trust) != 1 {
		t.Fatalf("expected 1 trust grant parsed from the composed assumeRolePolicy, got %+v", declarations[0].Policy.Trust)
	}
}

func TestCrossplaneUnsupportedFunctionGapPreservesPriorOutput(t *testing.T) {
	comp := xroleComposition([]any{
		patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
		}),
		map[string]any{"step": "mystery", "functionRef": map[string]any{"name": "function-mystery-transform"}, "input": map[string]any{}},
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(composed) != 1 {
		t.Fatalf("expected the first step's output to be preserved, got %+v", composed)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_function_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected crossplane_function_unsupported gap, got %+v", gaps)
	}
}

func TestCrossplaneUnsupportedPatchTypeGap(t *testing.T) {
	comp := xroleComposition([]any{
		patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
			map[string]any{"type": "CombineFromComposite", "toFieldPath": "spec.forProvider.tags"},
		}),
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(composed) != 1 {
		t.Fatalf("expected the resource to still be produced with supported patches applied, got %+v", composed)
	}
	name, _ := manifestNestedString(composed[0].Object, "spec", "forProvider", "name")
	if name != "payments-role" {
		t.Fatalf("expected the supported patch to still apply, got name=%q", name)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_patch_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected crossplane_patch_unsupported gap, got %+v", gaps)
	}
}

func TestCrossplaneGoTemplatingProducesResource(t *testing.T) {
	tmpl := "apiVersion: iam.cnrm.cloud.google.com/v1beta1\nkind: IAMPolicyMember\nmetadata:\n  name: {{ .observed.composite.resource.metadata.name }}-binding\n  annotations:\n    gotemplating.fn.crossplane.io/composition-resource-name: binding\nrole: roles/iam.workloadIdentityUser\nmember: serviceAccount:example\n"
	comp := xroleComposition([]any{
		map[string]any{"step": "template", "functionRef": map[string]any{"name": "function-go-templating"}, "input": map[string]any{"inline": map[string]any{"template": tmpl}}},
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(composed) != 1 {
		t.Fatalf("expected 1 go-templated resource, got %+v", composed)
	}
	name, _ := manifestNestedString(composed[0].Object, "metadata", "name")
	if name != "payments-role-xr-binding" {
		t.Fatalf("expected templated name from the composite, got %q", name)
	}
}

// TestCrossplaneUnreviewedFunctionNameNotExecuted reproduces the review
// finding that a pipeline step's functionRef name merely containing a
// supported function's name (e.g. "unreviewed-go-templating-controller")
// must never be treated as that supported function via substring matching:
// only an exact functionRef name match is understood, anything else is an
// unsupported-function gap and its step is never executed.
func TestCrossplaneUnreviewedFunctionNameNotExecuted(t *testing.T) {
	tmpl := "apiVersion: iam.cnrm.cloud.google.com/v1beta1\nkind: IAMPolicyMember\nmetadata:\n  name: {{ .observed.composite.resource.metadata.name }}-binding\nrole: roles/iam.workloadIdentityUser\nmember: serviceAccount:example\n"
	comp := xroleComposition([]any{
		map[string]any{"step": "template", "functionRef": map[string]any{"name": "unreviewed-go-templating-controller"}, "input": map[string]any{"inline": map[string]any{"template": tmpl}}},
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(composed) != 0 {
		t.Fatalf("expected the unreviewed function step to produce nothing, got %+v", composed)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_function_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected crossplane_function_unsupported gap for the unreviewed functionRef name, got %+v", gaps)
	}
}

func TestCrossplaneGoTemplatingNondeterministicSkipsStep(t *testing.T) {
	tmpl := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: generated-{{ now | unixEpoch }}\n"
	comp := xroleComposition([]any{
		map[string]any{"step": "template", "functionRef": map[string]any{"name": "function-go-templating"}, "input": map[string]any{"inline": map[string]any{"template": tmpl}}},
	})
	xr := xroleInstance()

	composed, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, manifestDefaultMaxCrossplaneSteps)
	if len(composed) != 0 {
		t.Fatalf("expected the non-deterministic template step to be skipped, got %+v", composed)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_nondeterministic_template" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected crossplane_nondeterministic_template gap, got %+v", gaps)
	}
}

func TestCrossplanePipelineTooLongGap(t *testing.T) {
	var steps []any
	for range 5 {
		steps = append(steps, patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
		}))
	}
	comp := xroleComposition(steps)
	xr := xroleInstance()

	_, gaps := manifestExpandCrossplane([]ci.Manifest{comp, xr}, 2)
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.crossplane_pipeline_too_long" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected crossplane_pipeline_too_long gap, got %+v", gaps)
	}
}
