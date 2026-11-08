package cloudidentitysource

import (
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func TestNewManifestRendererRequiresRepositoryReader(t *testing.T) {
	if _, err := NewManifestRenderer(ManifestRendererOptions{}); err == nil {
		t.Fatalf("expected an error when Repositories is nil")
	}
}

// manifestRequiredBoundaryChartFiles builds a synthetic chart with an ACK
// Role template whose permissionsBoundary calls Sprig's required() on
// .Values.ack.permissionsBoundaryArn, mirroring a real
// library chart's IAM role template contract: a Terraform-contract value
// (the ACK boundary ARN) this scan cannot statically resolve.
func manifestRequiredBoundaryChartFiles() map[string]string {
	files := basicChartFiles()
	files["mychart/templates/role.yaml"] = "apiVersion: iam.services.k8s.aws/v1alpha1\n" +
		"kind: Role\n" +
		"metadata:\n" +
		"  name: payments-worker\n" +
		"  namespace: {{ .Release.Namespace }}\n" +
		"spec:\n" +
		"  permissionsBoundary: {{ required \"boundary is required\" .Values.ack.permissionsBoundaryArn }}\n"
	return files
}

// TestRenderBindsUnresolvedValueMarkerSoRequiredStillRendersAndEmitsScopedGap
// is the required coverage for finding #1: a ManifestInput.UnresolvedValues
// key must not collapse the whole cell root to zero manifests when a
// template required()s it. The renderer binds an unmistakable marker so
// the Role still renders (alongside the chart's other, unrelated
// Deployment), and reports one object-scoped gap naming the field that
// stayed unknown.
func TestRenderBindsUnresolvedValueMarkerSoRequiredStillRendersAndEmitsScopedGap(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo := buildInlineRepository("github.com/example/gitops", "abc123", manifestRequiredBoundaryChartFiles())

	manifests, gaps, err := renderer.Render(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
		UnresolvedValues: []string{"ack.permissionsBoundaryArn"},
	})
	if err != nil {
		t.Fatalf("expected required() to render against the bound unknown marker instead of failing the whole chart, got error: %v", err)
	}
	kinds := map[string]int{}
	var role *ci.Manifest
	for i := range manifests {
		kind := manifestStringField(manifests[i].Object, "kind")
		kinds[kind]++
		if kind == "Role" {
			role = &manifests[i]
		}
	}
	if kinds["Deployment"] != 1 {
		t.Fatalf("expected the chart's unrelated Deployment to still render, got %+v", kinds)
	}
	if role == nil {
		t.Fatalf("expected the Role document to render despite the unresolved boundary value, got %+v", manifests)
	}
	boundary, _ := manifestNestedString(role.Object, "spec", "permissionsBoundary")
	if key, ok := ci.UnresolvedValueMarkerKey(boundary); !ok || key != "ack.permissionsBoundaryArn" {
		t.Fatalf("expected the rendered boundary field to carry the unresolved-value marker for ack.permissionsBoundaryArn, got %q", boundary)
	}
	var sawScopedGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.unresolved_value_in_object" && g.Scope == "iam.services.k8s.aws/v1alpha1|Role|payments|payments-worker" {
			sawScopedGap = true
		}
	}
	if !sawScopedGap {
		t.Fatalf("expected an object-scoped unresolved_value_in_object gap naming the Role, got %+v", gaps)
	}
}

// TestRenderMissingValueNotDeclaredUnresolvedStillFailsRequired is the
// negative control: a required() value that is actually missing, and was
// never named in UnresolvedValues, must still fail the chart render --
// the marker binding only covers keys the plan explicitly declares
// unresolved, never every missing value.
func TestRenderMissingValueNotDeclaredUnresolvedStillFailsRequired(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo := buildInlineRepository("github.com/example/gitops", "abc123", manifestRequiredBoundaryChartFiles())

	_, _, err = renderer.Render(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
	})
	if err == nil {
		t.Fatalf("expected required() to fail for a genuinely missing value not declared in UnresolvedValues")
	}
}

// manifestArrayTypedUnresolvedValueChartFiles builds a synthetic chart
// mirroring a real root chart's
// karpenter.* values.schema.json shape: podSubnetZoneIds is array-typed,
// mapMigrated is union-typed ("string"|"null", exactly as the real schema
// declares it), interruptionQueue is a plain string. All three are
// required() by a template, mirroring the real Terraform-contract
// UnresolvedValues keys that collapsed the whole chart's Helm schema
// validation before manifestUnresolvedValueBinding existed.
func manifestArrayTypedUnresolvedValueChartFiles() map[string]string {
	files := basicChartFiles()
	files["mychart/values.schema.json"] = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "karpenter": {
      "type": "object",
      "properties": {
        "podSubnetZoneIds": {"type": "array", "items": {"type": "string"}},
        "interruptionQueue": {"type": "string"},
        "mapMigrated": {"type": ["string", "null"]}
      }
    }
  }
}
`
	files["mychart/templates/karpenter.yaml"] = "apiVersion: karpenter.k8s.aws/v1\n" +
		"kind: EC2NodeClass\n" +
		"metadata:\n" +
		"  name: default\n" +
		"  namespace: {{ .Release.Namespace }}\n" +
		"spec:\n" +
		"  interruptionQueue: {{ required \"interruptionQueue is required\" .Values.karpenter.interruptionQueue }}\n" +
		"  mapMigrated: {{ required \"mapMigrated is required\" .Values.karpenter.mapMigrated }}\n" +
		"  podSubnetZoneIds:\n" +
		"  {{- range required \"podSubnetZoneIds is required\" .Values.karpenter.podSubnetZoneIds }}\n" +
		"  - {{ . }}\n" +
		"  {{- end }}\n"
	return files
}

// TestRenderBindsArrayTypedUnresolvedValueMarkerAndEmitsScopedGap is the
// required coverage for the schema-typed marker fix: an array-typed
// UnresolvedValues key (karpenter.podSubnetZoneIds in the real pinned
// chart) must bind an array-shaped marker so Helm's own values.schema.json
// validation passes instead of failing the chart's entire render, while a
// union-typed key (mapMigrated) and a plain string-typed key
// (interruptionQueue) in the SAME schema keep the bare string marker.
func TestRenderBindsArrayTypedUnresolvedValueMarkerAndEmitsScopedGap(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo := buildInlineRepository("github.com/example/gitops", "abc123", manifestArrayTypedUnresolvedValueChartFiles())

	manifests, gaps, err := renderer.Render(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "karpenter-system",
		UnresolvedValues: []string{"karpenter.podSubnetZoneIds", "karpenter.interruptionQueue", "karpenter.mapMigrated"},
	})
	if err != nil {
		t.Fatalf("expected the array-typed unresolved key to pass Helm's own values.schema.json validation instead of failing the whole chart, got error: %v", err)
	}
	var nodeClass *ci.Manifest
	for i := range manifests {
		if manifestStringField(manifests[i].Object, "kind") == "EC2NodeClass" {
			nodeClass = &manifests[i]
		}
	}
	if nodeClass == nil {
		t.Fatalf("expected the EC2NodeClass document to render despite the unresolved array/string values, got %+v", manifests)
	}
	zoneIds, ok := manifestNestedSlice(nodeClass.Object, "spec", "podSubnetZoneIds")
	if !ok || len(zoneIds) != 1 {
		t.Fatalf("expected spec.podSubnetZoneIds to carry a single-element array marker, got %+v", zoneIds)
	}
	zoneID, _ := manifestAsString(zoneIds[0])
	if key, ok := ci.UnresolvedValueMarkerKey(zoneID); !ok || key != "karpenter.podSubnetZoneIds" {
		t.Fatalf("expected the array element to carry the unresolved-value marker for karpenter.podSubnetZoneIds, got %q", zoneID)
	}
	interruptionQueue, _ := manifestNestedString(nodeClass.Object, "spec", "interruptionQueue")
	if key, ok := ci.UnresolvedValueMarkerKey(interruptionQueue); !ok || key != "karpenter.interruptionQueue" {
		t.Fatalf("expected spec.interruptionQueue to carry the unresolved-value marker for karpenter.interruptionQueue, got %q", interruptionQueue)
	}
	mapMigrated, _ := manifestNestedString(nodeClass.Object, "spec", "mapMigrated")
	if key, ok := ci.UnresolvedValueMarkerKey(mapMigrated); !ok || key != "karpenter.mapMigrated" {
		t.Fatalf("expected spec.mapMigrated (a union \"string\"|\"null\" schema type) to keep the bare string marker, got %q", mapMigrated)
	}
	var sawScopedGap bool
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.unresolved_value_in_object" && g.Scope == "karpenter.k8s.aws/v1|EC2NodeClass|karpenter-system|default" {
			sawScopedGap = true
		}
	}
	if !sawScopedGap {
		t.Fatalf("expected an object-scoped unresolved_value_in_object gap naming the EC2NodeClass, got %+v", gaps)
	}
}

// TestRenderArrayTypedValueNotDeclaredUnresolvedStillFailsRequired is the
// array-typed counterpart to TestRenderMissingValueNotDeclaredUnresolvedStillFailsRequired:
// a genuinely missing array-typed required() value that was never named in
// UnresolvedValues must still fail the chart render, exactly like the
// pre-existing string-typed case -- the schema-typed marker fix only
// changes what gets bound for an EXPLICITLY declared unresolved key.
func TestRenderArrayTypedValueNotDeclaredUnresolvedStillFailsRequired(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo := buildInlineRepository("github.com/example/gitops", "abc123", manifestArrayTypedUnresolvedValueChartFiles())

	_, _, err = renderer.Render(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "karpenter-system",
	})
	if err == nil {
		t.Fatalf("expected required() to fail for a genuinely missing array-typed value not declared in UnresolvedValues")
	}
}

// manifestExplicitStringSchemaChartFiles mirrors
// manifestRequiredBoundaryChartFiles but adds a values.schema.json that
// explicitly declares ack.permissionsBoundaryArn as "type": "string" -- the
// schema-present-but-non-array branch of manifestSchemaTypeAtPath -- to
// prove the fix only special-cases "array", not "a schema is present at
// all".
func manifestExplicitStringSchemaChartFiles() map[string]string {
	files := manifestRequiredBoundaryChartFiles()
	files["mychart/values.schema.json"] = `{"type":"object","properties":{"ack":{"type":"object","properties":{"permissionsBoundaryArn":{"type":"string"}}}}}`
	return files
}

// TestRenderExplicitStringTypedUnresolvedValueUnchanged covers the
// schema-present, non-array branch: an UnresolvedValues key whose own
// values.schema.json explicitly declares "type": "string" must still bind
// the bare marker string unchanged, not something schema-shape-dependent.
func TestRenderExplicitStringTypedUnresolvedValueUnchanged(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo := buildInlineRepository("github.com/example/gitops", "abc123", manifestExplicitStringSchemaChartFiles())

	manifests, _, err := renderer.Render(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
		UnresolvedValues: []string{"ack.permissionsBoundaryArn"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var role *ci.Manifest
	for i := range manifests {
		if manifestStringField(manifests[i].Object, "kind") == "Role" {
			role = &manifests[i]
		}
	}
	if role == nil {
		t.Fatalf("expected the Role document to render, got %+v", manifests)
	}
	boundary, _ := manifestNestedString(role.Object, "spec", "permissionsBoundary")
	if boundary != ci.UnresolvedValueMarker("ack.permissionsBoundaryArn") {
		t.Fatalf("expected the explicit string-typed schema's boundary field to still carry the bare marker string, got %q", boundary)
	}
}

func TestRenderCombinesRawPathsHelmAndArgoRecursion(t *testing.T) {
	repos := newFakeRepositoryReader()
	leafPin := ci.SourcePin{Repository: "github.com/example/leaf", Revision: "main", Root: ""}
	repos.register(leafPin, map[string]string{"app.yaml": rawDeploymentYAML("leaf-app", "payments")})
	leafApp := argoApplication("leaf", "github.com/example/leaf", "", "payments")
	leafYAML, err := marshalApplicationForTest(leafApp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	files := basicChartFiles()
	files["raw/app-of-apps.yaml"] = leafYAML
	repo := buildInlineRepository("github.com/example/root", "main", files)

	manifests, gaps, err := renderer.Render(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Paths: []string{"raw/app-of-apps.yaml"}, Release: "myapp", Namespace: "payments",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	kinds := map[string]int{}
	for _, m := range manifests {
		kinds[manifestStringField(m.Object, "kind")]++
	}
	if kinds["Deployment"] != 2 {
		t.Fatalf("expected 2 Deployments (1 helm-rendered + 1 argo-recursed leaf), got %+v", kinds)
	}
}

func TestRenderReturnsCrossplaneCompositesUnexpanded(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	compYAML, err := manifestMarshalYAMLForTest(xroleComposition([]any{
		patchAndTransformStep([]any{
			map[string]any{"type": "FromCompositeFieldPath", "fromFieldPath": "spec.parameters.roleName", "toFieldPath": "spec.forProvider.name"},
		}),
	}).Object)
	if err != nil {
		t.Fatalf("marshal composition: %v", err)
	}
	xrYAML, err := manifestMarshalYAMLForTest(xroleInstance().Object)
	if err != nil {
		t.Fatalf("marshal xr: %v", err)
	}
	repo := buildInlineRepository("github.com/example/platform", "main", map[string]string{
		"compositions/xrole.yaml": compYAML,
		"instances/xr.yaml":       xrYAML,
	})

	// Render no longer expands Crossplane composites/claims -- Compose
	// does, over every target's aggregated manifests, once per target.
	// Render must still decode and return the raw Composition/XR
	// documents, just unexpanded.
	manifests, gaps, err := renderer.Render(testContext(), ci.ManifestRequest{Repository: repo, Paths: []string{"compositions/xrole.yaml", "instances/xr.yaml"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	kinds := map[string]int{}
	for _, m := range manifests {
		kinds[manifestStringField(m.Object, "kind")]++
	}
	if kinds["Composition"] != 1 || kinds["XRole"] != 1 {
		t.Fatalf("expected the raw Composition and XRole documents to pass through Render unexpanded, got %+v", kinds)
	}
	if kinds["Role"] != 0 {
		t.Fatalf("expected no composed Role among Render's own output (that is Compose's job), got %+v", kinds)
	}
}

func TestRenderTooManyDocumentsBound(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos, MaxDocuments: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	files := map[string]string{
		"raw/a.yaml": rawDeploymentYAML("a", "ns"),
		"raw/b.yaml": rawDeploymentYAML("b", "ns"),
	}
	repo := buildInlineRepository("github.com/example/many", "main", files)
	manifests, gaps, err := renderer.Render(testContext(), ci.ManifestRequest{Repository: repo, Paths: []string{"raw"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected the output truncated to the configured document bound, got %d", len(manifests))
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.too_many_documents" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected too_many_documents gap, got %+v", gaps)
	}
}

func TestRenderPathUnreadableGap(t *testing.T) {
	repos := newFakeRepositoryReader()
	renderer, err := NewManifestRenderer(ManifestRendererOptions{Repositories: repos})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	repo := buildInlineRepository("github.com/example/empty", "main", map[string]string{})
	manifests, gaps, err := renderer.Render(testContext(), ci.ManifestRequest{Repository: repo, Paths: []string{"does/not/exist.yaml"}})
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	if len(manifests) != 0 {
		t.Fatalf("expected no manifests, got %+v", manifests)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.path_unreadable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected path_unreadable gap, got %+v", gaps)
	}
}
