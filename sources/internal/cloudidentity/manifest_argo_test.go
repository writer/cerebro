package cloudidentitysource

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func argoApplication(name, repoURL, srcPath, destNamespace string) ci.Manifest {
	return ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"source":      map[string]any{"repoURL": repoURL, "targetRevision": "main", "path": srcPath},
			"destination": map[string]any{"namespace": destNamespace},
		},
	}}
}

func newTestRenderer(repos *fakeRepositoryReader) *manifestRenderer {
	return &manifestRenderer{
		repositories:       repos,
		maxArgoDepth:       manifestDefaultMaxArgoDepth,
		maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps,
		maxDocuments:       manifestDefaultMaxDocuments,
	}
}

func rawDeploymentYAML(name, namespace string) string {
	return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: " + name + "\n  namespace: " + namespace + "\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: img:v1\n"
}

func TestExpandApplicationRawYAMLSource(t *testing.T) {
	repos := newFakeRepositoryReader()
	pin := ci.SourcePin{Repository: "github.com/example/apps", Revision: "main", Root: ""}
	repos.register(pin, map[string]string{"app.yaml": rawDeploymentYAML("app", "payments")})
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := argoApplication("payments-app", "github.com/example/apps", "", "payments")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 1 || manifestStringField(out[0].Object, "kind") != "Deployment" {
		t.Fatalf("expected 1 rendered Deployment, got %+v", out)
	}
}

func TestExpandApplicationHelmChartSource(t *testing.T) {
	repos := newFakeRepositoryReader()
	files := map[string]string{}
	for p, c := range basicChartFiles() {
		files["charts/web/"+p[len("mychart/"):]] = c
	}
	pin := ci.SourcePin{Repository: "github.com/example/helm-apps", Revision: "main", Root: "charts/web"}
	repos.register(pin, files)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := argoApplication("web-app", "github.com/example/helm-apps", "charts/web", "web")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 1 || manifestStringField(out[0].Object, "kind") != "Deployment" {
		t.Fatalf("expected 1 rendered Deployment from the helm source, got %+v", out)
	}
}

func TestExpandApplicationAppOfApps(t *testing.T) {
	repos := newFakeRepositoryReader()
	rootPin := ci.SourcePin{Repository: "github.com/example/root-apps", Revision: "main", Root: ""}
	leafPin := ci.SourcePin{Repository: "github.com/example/leaf-apps", Revision: "main", Root: ""}

	leafApp := argoApplication("leaf", "github.com/example/leaf-apps", "", "payments")
	leafYAML, err := marshalApplicationForTest(leafApp)
	if err != nil {
		t.Fatalf("marshal leaf app: %v", err)
	}
	repos.register(rootPin, map[string]string{"apps/leaf-app.yaml": leafYAML})
	repos.register(leafPin, map[string]string{"app.yaml": rawDeploymentYAML("app", "payments")})

	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	root := argoApplication("root", "github.com/example/root-apps", "", "argocd")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{root}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 1 || manifestStringField(out[0].Object, "kind") != "Deployment" {
		t.Fatalf("expected the app-of-apps leaf to recursively render a Deployment, got %+v", out)
	}
}

func TestExpandApplicationCycleDetected(t *testing.T) {
	repos := newFakeRepositoryReader()
	pin := ci.SourcePin{Repository: "github.com/example/self", Revision: "main", Root: ""}
	selfApp := argoApplication("self", "github.com/example/self", "", "ns")
	selfYAML, err := marshalApplicationForTest(selfApp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	repos.register(pin, map[string]string{"self.yaml": selfYAML})

	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	out, gaps, err := s.expand(testContext(), []ci.Manifest{selfApp}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no manifests from an unresolved cycle, got %+v", out)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.argo_cycle_detected" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected argo_cycle_detected gap, got %+v", gaps)
	}
}

func TestExpandApplicationDepthBound(t *testing.T) {
	repos := newFakeRepositoryReader()
	rootPin := ci.SourcePin{Repository: "github.com/example/root2", Revision: "main", Root: ""}
	leafPin := ci.SourcePin{Repository: "github.com/example/leaf2", Revision: "main", Root: ""}
	leafApp := argoApplication("leaf2", "github.com/example/leaf2", "", "ns")
	leafYAML, _ := marshalApplicationForTest(leafApp)
	repos.register(rootPin, map[string]string{"leaf.yaml": leafYAML})
	repos.register(leafPin, map[string]string{"app.yaml": rawDeploymentYAML("app", "ns")})

	r := newTestRenderer(repos)
	r.maxArgoDepth = 1
	s := newManifestRenderState(r)
	root := argoApplication("root2", "github.com/example/root2", "", "argocd")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{root}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected recursion bound to stop expansion, got %+v", out)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.argo_recursion_bound" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected argo_recursion_bound gap, got %+v", gaps)
	}
}

func TestExpandApplicationKustomizeUnsupported(t *testing.T) {
	repos := newFakeRepositoryReader()
	pin := ci.SourcePin{Repository: "github.com/example/kustomize", Revision: "main", Root: "overlay"}
	repos.register(pin, map[string]string{"overlay/kustomization.yaml": "resources:\n- deployment.yaml\n", "overlay/deployment.yaml": rawDeploymentYAML("app", "ns")})
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	app := argoApplication("kust-app", "github.com/example/kustomize", "overlay", "ns")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no manifests for an unsupported Kustomize overlay, got %+v", out)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.argo_kustomize_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected argo_kustomize_unsupported gap, got %+v", gaps)
	}
}

func TestExpandApplicationChartSourceWithoutChartReaderGaps(t *testing.T) {
	r := newTestRenderer(newFakeRepositoryReader())
	s := newManifestRenderState(r)
	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "chart-app"},
		"spec": map[string]any{
			"source": map[string]any{"repoURL": "https://charts.example.com", "targetRevision": "1.2.3", "chart": "redis"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no manifests without a configured ChartReader, got %+v", out)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.chart_reader_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected chart_reader_unavailable gap, got %+v", gaps)
	}
}

func TestExpandApplicationChartSourceResolvedViaChartReader(t *testing.T) {
	pkg := buildTarGz(map[string]string{
		"redis/Chart.yaml":                 "apiVersion: v2\nname: redis\nversion: 1.2.3\n",
		"redis/templates/statefulset.yaml": "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: redis\n  namespace: {{ .Release.Namespace }}\nspec:\n  template:\n    spec:\n      containers:\n      - name: redis\n        image: redis:{{ .Values.tag }}\n",
	})
	digest := sha256Hex(pkg)
	mux := http.NewServeMux()
	mux.HandleFunc("/index.yaml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "entries:\n  redis:\n  - name: redis\n    version: 1.2.3\n    digest: %s\n    urls:\n    - redis-1.2.3.tgz\n", digest)
	})
	mux.HandleFunc("/redis-1.2.3.tgz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(pkg) })
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	charts, err := NewChartReader(ChartReaderOptions{AllowedRepositories: []string{server.URL}, AllowLoopback: true, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := newTestRenderer(newFakeRepositoryReader())
	r.charts = charts
	r.allowedChartRepositories = []string{server.URL}
	s := newManifestRenderState(r)

	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "chart-app"},
		"spec": map[string]any{
			"source": map[string]any{
				"repoURL": server.URL, "targetRevision": "1.2.3", "chart": "redis",
				"helm": map[string]any{"parameters": []any{map[string]any{"name": "tag", "value": "7.2"}}},
			},
			"destination": map[string]any{"namespace": "cache"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 1 || manifestStringField(out[0].Object, "kind") != "StatefulSet" {
		t.Fatalf("expected the ChartReader-resolved chart to render 1 StatefulSet, got %+v", out)
	}
	containers, _ := manifestNestedSlice(out[0].Object, "spec", "template", "spec", "containers")
	c, _ := manifestAsMap(containers[0])
	if c["image"] != "redis:7.2" {
		t.Fatalf("expected the Argo helm.parameters override applied, got %v", c["image"])
	}
}

func TestExpandApplicationSetListGenerator(t *testing.T) {
	repos := newFakeRepositoryReader()
	for _, env := range []string{"dev", "prod"} {
		pin := ci.SourcePin{Repository: "github.com/example/multi", Revision: "main", Root: env}
		repos.register(pin, map[string]string{env + "/app.yaml": rawDeploymentYAML("app", env)})
	}
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	appSet := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "ApplicationSet",
		"metadata":   map[string]any{"name": "fleet"},
		"spec": map[string]any{
			"generators": []any{
				map[string]any{"list": map[string]any{"elements": []any{
					map[string]any{"env": "dev"},
					map[string]any{"env": "prod"},
				}}},
			},
			"template": map[string]any{
				"metadata": map[string]any{"name": "{{.env}}-app"},
				"spec": map[string]any{
					"source":      map[string]any{"repoURL": "github.com/example/multi", "targetRevision": "main", "path": "{{.env}}"},
					"destination": map[string]any{"namespace": "{{.env}}"},
				},
			},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{appSet}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 rendered deployments (one per list element), got %d: %+v", len(out), out)
	}
}

func TestExpandApplicationSetUnsupportedGenerator(t *testing.T) {
	r := newTestRenderer(newFakeRepositoryReader())
	s := newManifestRenderState(r)
	appSet := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "ApplicationSet",
		"metadata":   map[string]any{"name": "fleet"},
		"spec": map[string]any{
			"generators": []any{map[string]any{"git": map[string]any{"repoURL": "github.com/example/multi", "directories": []any{map[string]any{"path": "apps/*"}}}}},
			"template":   map[string]any{"metadata": map[string]any{"name": "app"}, "spec": map[string]any{}},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{appSet}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no manifests for an unsupported generator, got %+v", out)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.argo_applicationset_generator_unsupported" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected argo_applicationset_generator_unsupported gap, got %+v", gaps)
	}
}

func TestExpandApplicationMultiSourceRefValues(t *testing.T) {
	repos := newFakeRepositoryReader()
	chartFiles := map[string]string{}
	for p, c := range basicChartFiles() {
		chartFiles["chart/"+p[len("mychart/"):]] = c
	}
	repos.register(ci.SourcePin{Repository: "github.com/example/chart-repo", Revision: "main", Root: "chart"}, chartFiles)
	repos.register(ci.SourcePin{Repository: "github.com/example/values-repo", Revision: "main", Root: ""}, map[string]string{
		"env/prod.yaml": "image:\n  tag: fromref\n",
	})

	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "multi"},
		"spec": map[string]any{
			"sources": []any{
				map[string]any{
					"repoURL": "github.com/example/chart-repo", "targetRevision": "main", "path": "chart",
					"helm": map[string]any{"valueFiles": []any{"$values/env/prod.yaml"}},
				},
				map[string]any{"repoURL": "github.com/example/values-repo", "targetRevision": "main", "ref": "values"},
			},
			"destination": map[string]any{"namespace": "payments"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 rendered Deployment (the ref-only values source contributes no manifests of its own), got %+v", out)
	}
	containers, _ := manifestNestedSlice(out[0].Object, "spec", "template", "spec", "containers")
	c, _ := manifestAsMap(containers[0])
	if c["image"] != "example/app:fromref" {
		t.Fatalf("expected the $values-ref value file's tag override applied, got %v", c["image"])
	}
}

func TestExpandApplicationsFilterDropsUnlistedWithoutGap(t *testing.T) {
	repos := newFakeRepositoryReader()
	wantedPin := ci.SourcePin{Repository: "github.com/example/apps", Revision: "main", Root: ""}
	repos.register(wantedPin, map[string]string{"app.yaml": rawDeploymentYAML("app", "payments")})

	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	wanted := argoApplication("writerai", "github.com/example/apps", "", "payments")
	unwanted := argoApplication("unrelated-app", "github.com/example/apps", "", "payments")
	req := ci.ManifestRequest{Applications: []string{"writerai"}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{wanted, unwanted}, req, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps for an out-of-plan Application, got %+v", gaps)
	}
	if len(out) != 1 || manifestStringField(out[0].Object, "kind") != "Deployment" {
		t.Fatalf("expected only the listed Application to expand, got %+v", out)
	}
}

func TestExpandApplicationsFilterPropagatesThroughAppOfApps(t *testing.T) {
	repos := newFakeRepositoryReader()
	rootPin := ci.SourcePin{Repository: "github.com/example/root-filter", Revision: "main", Root: ""}
	leafPin := ci.SourcePin{Repository: "github.com/example/leaf-filter", Revision: "main", Root: ""}

	// "other" is never named in the Applications filter; if the filter list
	// were lost on recursion into the "writerai" app-of-apps (instead of
	// propagated via subReq.Applications), it would wrongly expand.
	unwantedLeaf := argoApplication("other", "github.com/example/leaf-filter", "", "payments")
	unwantedYAML, err := marshalApplicationForTest(unwantedLeaf)
	if err != nil {
		t.Fatalf("marshal unwanted leaf: %v", err)
	}
	repos.register(rootPin, map[string]string{"apps/unwanted.yaml": unwantedYAML})
	repos.register(leafPin, map[string]string{"app.yaml": rawDeploymentYAML("app", "payments")})

	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	root := argoApplication("writerai", "github.com/example/root-filter", "", "argocd")
	req := ci.ManifestRequest{Applications: []string{"writerai"}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{root}, req, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps for an out-of-plan nested Application, got %+v", gaps)
	}
	if len(out) != 0 {
		t.Fatalf("expected the unlisted nested Application to stay dropped, got %+v", out)
	}
}

func TestExpandApplicationHelmValueFilesRelativeToSourcePath(t *testing.T) {
	repos := newFakeRepositoryReader()
	files := map[string]string{}
	for p, c := range basicChartFiles() {
		files["charts/writerai/"+p[len("mychart/"):]] = c
	}
	files["charts/writerai/values/global.yaml"] = "image:\n  tag: fromvaluesdir\n"
	pin := ci.SourcePin{Repository: "github.com/example/writer-apps", Revision: "main", Root: "charts/writerai"}
	repos.register(pin, files)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "writerai"},
		"spec": map[string]any{
			"source": map[string]any{
				"repoURL": "github.com/example/writer-apps", "targetRevision": "main", "path": "charts/writerai",
				"helm": map[string]any{"valueFiles": []any{"values/global.yaml"}},
			},
			"destination": map[string]any{"namespace": "payments"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps (the plain value file resolves relative to spec.source.path), got %+v", gaps)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 rendered Deployment, got %+v", out)
	}
	containers, _ := manifestNestedSlice(out[0].Object, "spec", "template", "spec", "containers")
	c, _ := manifestAsMap(containers[0])
	if c["image"] != "example/app:fromvaluesdir" {
		t.Fatalf("expected the source-path-relative value file's tag override applied, got %v", c["image"])
	}
}

func TestExpandApplicationHelmValuesObjectPrecedence(t *testing.T) {
	repos := newFakeRepositoryReader()
	pin := ci.SourcePin{Repository: "github.com/example/valuesobject-apps", Revision: "main", Root: "chart"}
	files := map[string]string{}
	for p, c := range basicChartFiles() {
		files["chart/"+p[len("mychart/"):]] = c
	}
	repos.register(pin, files)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "app"},
		"spec": map[string]any{
			"source": map[string]any{
				"repoURL": "github.com/example/valuesobject-apps", "targetRevision": "main", "path": "chart",
				"helm": map[string]any{
					"values":       "image:\n  tag: fromvalues\n",
					"valuesObject": map[string]any{"image": map[string]any{"tag": "fromvaluesobject"}},
				},
			},
			"destination": map[string]any{"namespace": "payments"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	containers, _ := manifestNestedSlice(out[0].Object, "spec", "template", "spec", "containers")
	c, _ := manifestAsMap(containers[0])
	if c["image"] != "example/app:fromvaluesobject" {
		t.Fatalf("expected valuesObject to win over inline values, got %v", c["image"])
	}

	// parameters outrank valuesObject (a fresh render state: the first
	// call's visited-source bookkeeping must not treat this as a cycle).
	appWithParam, _ := manifestNestedMap(app.Object, "spec", "source")
	helmBlock, _ := manifestAsMap(appWithParam["helm"])
	helmBlock["parameters"] = []any{map[string]any{"name": "image.tag", "value": "fromparam"}}
	s2 := newManifestRenderState(r)
	out2, gaps2, err := s2.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps2) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps2)
	}
	containers2, _ := manifestNestedSlice(out2[0].Object, "spec", "template", "spec", "containers")
	c2, _ := manifestAsMap(containers2[0])
	if c2["image"] != "example/app:fromparam" {
		t.Fatalf("expected parameters to win over valuesObject, got %v", c2["image"])
	}
}

func TestExpandApplicationHonorsReleaseNameAndDestinationNamespace(t *testing.T) {
	repos := newFakeRepositoryReader()
	pin := ci.SourcePin{Repository: "github.com/example/release-apps", Revision: "main", Root: "chart"}
	files := map[string]string{}
	for p, c := range basicChartFiles() {
		files["chart/"+p[len("mychart/"):]] = c
	}
	repos.register(pin, files)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "app"},
		"spec": map[string]any{
			"source": map[string]any{
				"repoURL": "github.com/example/release-apps", "targetRevision": "main", "path": "chart",
				"helm": map[string]any{"releaseName": "custom-release"},
			},
			"destination": map[string]any{"namespace": "custom-namespace"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 rendered Deployment, got %+v", out)
	}
	gotName, _ := manifestNestedString(out[0].Object, "metadata", "name")
	gotNamespace, _ := manifestNestedString(out[0].Object, "metadata", "namespace")
	if gotName != "custom-release" {
		t.Fatalf("expected helm.releaseName honored as the release name, got %q", gotName)
	}
	if gotNamespace != "custom-namespace" {
		t.Fatalf("expected spec.destination.namespace honored, got %q", gotNamespace)
	}
}

func TestExpandApplicationFileDependencyMaterializesParentDir(t *testing.T) {
	repos := newFakeRepositoryReader()
	narrow := ci.SourcePin{Repository: "github.com/example/monorepo", Revision: "main", Root: "charts/app"}
	wide := ci.SourcePin{Repository: "github.com/example/monorepo", Revision: "main", Root: "charts"}
	appOnly := fileDepRepoFiles("")
	// The narrow, source-path-scoped fetch sees only its own chart (no
	// sibling "charts/common"); only the widened "charts" root has it.
	repos.register(narrow, map[string]string{
		"charts/app/Chart.yaml":  appOnly["charts/app/Chart.yaml"],
		"charts/app/values.yaml": appOnly["charts/app/values.yaml"],
	})
	repos.register(wide, appOnly)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := argoApplication("app", "github.com/example/monorepo", "charts/app", "payments")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if strings.Contains(g.Code, "dependency") {
			t.Fatalf("file:// sibling dependency should resolve via the widened parent-dir fetch with no dependency gap, got %+v", gaps)
		}
	}
	found := false
	for _, m := range out {
		if manifestStringField(m.Object, "kind") == "ConfigMap" {
			if name, _ := manifestNestedString(m.Object, "metadata", "name"); name == "common-cm" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected the file:// sibling chart's ConfigMap to render via the widened fetch, got %+v", out)
	}
}

// marshalApplicationForTest renders a Manifest's Object back to YAML text so
// it can be registered as repository file content for recursive expansion
// tests (the renderer always decodes repository bytes, never Go values
// directly).
func marshalApplicationForTest(m ci.Manifest) (string, error) {
	return manifestMarshalYAMLForTest(m.Object)
}

func TestExpandApplicationSiblingsSameSourceDifferentNamespaceReleaseBothRender(t *testing.T) {
	// R12: two sibling Applications sharing source coordinates
	// (repoURL/revision/srcPath) but differing in destination namespace
	// and release name are legitimately independent renders, not a
	// cycle. The old key (coordinates only, release always "") collapsed
	// them onto the same visited entry and dropped the second as a false
	// cycle.
	repos := newFakeRepositoryReader()
	rootPin := ci.SourcePin{Repository: "github.com/example/root-siblings", Revision: "main", Root: ""}
	chartPin := ci.SourcePin{Repository: "github.com/example/shared-chart", Revision: "main", Root: ""}

	appA := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "tenant-a"},
		"spec": map[string]any{
			"source":      map[string]any{"repoURL": "github.com/example/shared-chart", "targetRevision": "main", "helm": map[string]any{"releaseName": "tenant-a"}},
			"destination": map[string]any{"namespace": "tenant-a"},
		},
	}}
	appB := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "tenant-b"},
		"spec": map[string]any{
			"source":      map[string]any{"repoURL": "github.com/example/shared-chart", "targetRevision": "main", "helm": map[string]any{"releaseName": "tenant-b"}},
			"destination": map[string]any{"namespace": "tenant-b"},
		},
	}}
	aYAML, err := marshalApplicationForTest(appA)
	if err != nil {
		t.Fatalf("marshal appA: %v", err)
	}
	bYAML, err := marshalApplicationForTest(appB)
	if err != nil {
		t.Fatalf("marshal appB: %v", err)
	}
	repos.register(rootPin, map[string]string{"apps/a.yaml": aYAML, "apps/b.yaml": bYAML})
	chartFiles := map[string]string{}
	for p, c := range basicChartFiles() {
		chartFiles[p[len("mychart/"):]] = c
	}
	repos.register(chartPin, chartFiles)

	r := newTestRenderer(repos)
	s := newManifestRenderState(r)
	root := argoApplication("root", "github.com/example/root-siblings", "", "argocd")
	out, gaps, err := s.expand(testContext(), []ci.Manifest{root}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.argo_cycle_detected" {
			t.Fatalf("siblings sharing source coordinates but differing in namespace/release must not be treated as a cycle, got %+v", gaps)
		}
	}
	byKey := map[string]bool{}
	for _, m := range out {
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		namespace, _ := manifestNestedString(m.Object, "metadata", "namespace")
		byKey[namespace+"/"+name] = true
	}
	if !byKey["tenant-a/tenant-a"] || !byKey["tenant-b/tenant-b"] {
		t.Fatalf("expected both sibling Applications to render their own Deployment, got %+v", out)
	}
}

func TestExpandApplicationHelmParameterFalseStringProperlyTyped(t *testing.T) {
	// R12: an Argo CD helm.parameters value of "false" must follow Helm
	// --set typing (a real boolean), not become a non-empty, always-truthy
	// Go template string -- otherwise a chart's `{{ if not .Values.x }}`
	// inversion silently omits a resource the parameter was meant to
	// enable.
	repos := newFakeRepositoryReader()
	files := map[string]string{
		"Chart.yaml":                    "apiVersion: v2\nname: mychart\nversion: 1.0.0\n",
		"values.yaml":                   "disableServiceAccount: true\n",
		"templates/serviceaccount.yaml": "{{- if not .Values.disableServiceAccount }}\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: app-sa\n  namespace: {{ .Release.Namespace }}\n{{- end }}\n",
	}
	pin := ci.SourcePin{Repository: "github.com/example/typed-params", Revision: "main", Root: ""}
	repos.register(pin, files)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "app"},
		"spec": map[string]any{
			"source": map[string]any{
				"repoURL": "github.com/example/typed-params", "targetRevision": "main",
				"helm": map[string]any{"parameters": []any{map[string]any{"name": "disableServiceAccount", "value": "false"}}},
			},
			"destination": map[string]any{"namespace": "payments"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	found := false
	for _, m := range out {
		if manifestStringField(m.Object, "kind") == "ServiceAccount" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm.parameters value \"false\" typed as a real boolean (not an always-truthy string) to enable the ServiceAccount, got %+v", out)
	}
}

func TestExpandApplicationHelmParameterTypedBooleanAndNumericControl(t *testing.T) {
	// Control: "true" and "1" (Helm --set's own boolean/int typing) both
	// enable a `{{ if .Values.x }}`-gated resource, exactly as a real
	// `helm template --set` invocation would.
	files := map[string]string{
		"Chart.yaml":                    "apiVersion: v2\nname: mychart\nversion: 1.0.0\n",
		"values.yaml":                   "enableServiceAccount: false\n",
		"templates/serviceaccount.yaml": "{{- if .Values.enableServiceAccount }}\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: app-sa\n  namespace: {{ .Release.Namespace }}\n{{- end }}\n",
	}
	for _, val := range []string{"true", "1"} {
		val := val
		t.Run(val, func(t *testing.T) {
			repos := newFakeRepositoryReader()
			pin := ci.SourcePin{Repository: "github.com/example/typed-params-" + val, Revision: "main", Root: ""}
			repos.register(pin, files)
			r := newTestRenderer(repos)
			s := newManifestRenderState(r)

			app := ci.Manifest{Object: map[string]any{
				"apiVersion": "argoproj.io/v1alpha1",
				"kind":       "Application",
				"metadata":   map[string]any{"name": "app"},
				"spec": map[string]any{
					"source": map[string]any{
						"repoURL": "github.com/example/typed-params-" + val, "targetRevision": "main",
						"helm": map[string]any{"parameters": []any{map[string]any{"name": "enableServiceAccount", "value": val}}},
					},
					"destination": map[string]any{"namespace": "payments"},
				},
			}}
			out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(gaps) != 0 {
				t.Fatalf("expected no gaps, got %+v", gaps)
			}
			found := false
			for _, m := range out {
				if manifestStringField(m.Object, "kind") == "ServiceAccount" {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected helm.parameters value %q typed like Helm --set to enable the ServiceAccount, got %+v", val, out)
			}
		})
	}
}

func TestExpandApplicationMalformedInlineHelmValuesGap(t *testing.T) {
	// R12: malformed inline helm.values must produce a scoped gap rather
	// than being silently dropped, while the chart still renders using
	// whatever other values it does have (its own defaults here).
	repos := newFakeRepositoryReader()
	files := map[string]string{}
	for p, c := range basicChartFiles() {
		files[p[len("mychart/"):]] = c
	}
	pin := ci.SourcePin{Repository: "github.com/example/malformed-values", Revision: "main", Root: ""}
	repos.register(pin, files)
	r := newTestRenderer(repos)
	s := newManifestRenderState(r)

	app := ci.Manifest{Object: map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata":   map[string]any{"name": "app"},
		"spec": map[string]any{
			"source": map[string]any{
				"repoURL": "github.com/example/malformed-values", "targetRevision": "main",
				"helm": map[string]any{"values": "image:\n  tag: [unterminated\n"},
			},
			"destination": map[string]any{"namespace": "payments"},
		},
	}}
	out, gaps, err := s.expand(testContext(), []ci.Manifest{app}, ci.ManifestRequest{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.argo_helm_values_invalid" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected argo_helm_values_invalid gap for malformed inline helm.values, got %+v", gaps)
	}
	if len(out) != 1 || manifestStringField(out[0].Object, "kind") != "Deployment" {
		t.Fatalf("expected the chart to still render using its defaults despite the malformed inline values gap, got %+v", out)
	}
}
