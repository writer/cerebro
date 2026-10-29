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
