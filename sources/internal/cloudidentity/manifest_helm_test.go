package cloudidentitysource

import (
	"strings"
	"testing"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func basicChartFiles() map[string]string {
	return map[string]string{
		"mychart/Chart.yaml":                "apiVersion: v2\nname: mychart\nversion: 1.0.0\n",
		"mychart/values.yaml":               "image:\n  repository: example/app\n  tag: v1\n",
		"mychart/templates/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  namespace: {{ .Release.Namespace }}\nspec:\n  template:\n    spec:\n      serviceAccountName: app-sa\n      containers:\n      - name: app\n        image: \"{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n",
	}
}

func TestRenderHelmBasicValuesOverride(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", basicChartFiles())
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
		Values: map[string]any{"image": map[string]any{"tag": "v2"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %+v", gaps)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 rendered document, got %d", len(manifests))
	}
	containers, _ := manifestNestedSlice(manifests[0].Object, "spec", "template", "spec", "containers")
	c, _ := manifestAsMap(containers[0])
	if c["image"] != "example/app:v2" {
		t.Fatalf("expected override tag v2 applied, got %v", c["image"])
	}
}

func TestRenderHelmVendoredTgzSubchartDependency(t *testing.T) {
	files := basicChartFiles()
	files["mychart/Chart.yaml"] = "apiVersion: v2\nname: mychart\nversion: 1.0.0\ndependencies:\n- name: sub\n  version: 1.0.0\n  repository: https://charts.example.com\n"
	files["mychart/charts/sub-1.0.0.tgz"] = string(buildTarGz(map[string]string{
		"sub/Chart.yaml":               "apiVersion: v2\nname: sub\nversion: 1.0.0\n",
		"sub/templates/configmap.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: sub-cm\n  namespace: {{ .Release.Namespace }}\ndata:\n  k: v\n",
	}))
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if strings.Contains(g.Code, "dependency") {
			t.Fatalf("vendored tgz dependency should load with no dependency gap, got %+v", g)
		}
	}
	foundSubConfigMap := false
	for _, m := range manifests {
		if manifestStringField(m.Object, "kind") == "ConfigMap" {
			if name, _ := manifestNestedString(m.Object, "metadata", "name"); name == "sub-cm" {
				foundSubConfigMap = true
			}
		}
	}
	if !foundSubConfigMap {
		t.Fatalf("expected the vendored subchart's ConfigMap to be rendered, got %+v", manifests)
	}
}

func TestRenderHelmDependencyMissingUnpinnedGap(t *testing.T) {
	files := basicChartFiles()
	files["mychart/Chart.yaml"] = "apiVersion: v2\nname: mychart\nversion: 1.0.0\ndependencies:\n- name: sub\n  version: \">=1.0.0\"\n  repository: https://charts.example.com\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	_, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_dependency_unpinned" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_dependency_unpinned gap for a version-range dependency with no lock, got %+v", gaps)
	}
}

func TestRenderHelmNondeterministicSecretRendersWithoutIdentityImpact(t *testing.T) {
	// genCA-generated Secret content is non-identity (cert bytes); the
	// workload/ServiceAccount shape is stable (basicChartFiles' literal
	// "app-sa"/".Release.Name"). The chart must render once (via the
	// render-twice-and-compare path) with no gap at all.
	files := basicChartFiles()
	files["mychart/templates/secret.yaml"] = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: generated\n  namespace: {{ .Release.Namespace }}\nstringData:\n  ca.crt: {{ (genCA \"myapp\" 365).Cert | quote }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps: genCA output is non-identity and workloads/SAs are stable, got %+v", gaps)
	}
	kinds := map[string]int{}
	for _, m := range manifests {
		kinds[manifestStringField(m.Object, "kind")]++
	}
	if kinds["Deployment"] != 1 || kinds["Secret"] != 1 {
		t.Fatalf("expected both the Deployment and the generated Secret rendered, got %+v", kinds)
	}
}

func TestRenderHelmLookupOnlyChartRendersWithoutGap(t *testing.T) {
	// lookup is always the harmless empty-map placeholder with our
	// zero-value engine (no clientProvider): it must not even trigger the
	// render-twice comparison, let alone a refusal.
	files := basicChartFiles()
	files["mychart/templates/configmap.yaml"] = "{{- $existing := lookup \"v1\" \"ConfigMap\" .Release.Namespace \"preexisting\" }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: generated\n  namespace: {{ .Release.Namespace }}\ndata:\n  found: {{ (not (not $existing)) | quote }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps for a lookup-only chart (always the empty-map placeholder), got %+v", gaps)
	}
	kinds := map[string]int{}
	for _, m := range manifests {
		kinds[manifestStringField(m.Object, "kind")]++
	}
	if kinds["Deployment"] != 1 || kinds["ConfigMap"] != 1 {
		t.Fatalf("expected both the Deployment and the lookup-using ConfigMap rendered, got %+v", kinds)
	}
	for _, m := range manifests {
		if manifestStringField(m.Object, "kind") != "ConfigMap" {
			continue
		}
		data, _ := manifestNestedMap(m.Object, "data")
		if data["found"] != "false" {
			t.Fatalf("expected lookup to resolve as the empty-map placeholder (found=false), got %v", data["found"])
		}
	}
}

func TestRenderHelmIgnoresReleaseNotes(t *testing.T) {
	// Real dependency charts (e.g. Kong) ship prose templates/NOTES.txt;
	// Helm never treats it as a manifest, so neither may we.
	files := basicChartFiles()
	files["mychart/templates/NOTES.txt"] = "Thank you for installing {{ .Chart.Name }}.\n\nYour release is named {{ .Release.Name }}.\nTo learn more: helm status {{ .Release.Name }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected release notes to be ignored without a gap, got %+v", gaps)
	}
	if len(manifests) == 0 {
		t.Fatal("expected the chart's real manifests to render")
	}
}

func TestRenderHelmValuesFileMissingGap(t *testing.T) {
	repo := buildInlineRepository("github.com/example/gitops", "abc123", basicChartFiles())
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	_, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
		ValuesFiles: []string{"values/prod.yaml"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_values_file_missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_values_file_missing gap, got %+v", gaps)
	}
}

func fileDepRepoFiles(condition string) map[string]string {
	files := map[string]string{
		"charts/app/Chart.yaml":                  "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: common\n  version: 1.0.0\n  repository: file://../common\n",
		"charts/app/values.yaml":                 "common:\n  enabled: true\n",
		"charts/common/Chart.yaml":               "apiVersion: v2\nname: common\nversion: 1.0.0\n",
		"charts/common/templates/configmap.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: common-cm\n  namespace: {{ .Release.Namespace }}\ndata:\n  k: v\n",
	}
	if condition != "" {
		files["charts/app/Chart.yaml"] = "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: common\n  version: 1.0.0\n  repository: file://../common\n  condition: " + condition + "\n"
	}
	return files
}

func TestRenderHelmFileDependencySiblingResolved(t *testing.T) {
	repo := buildInlineRepository("github.com/example/platform", "abc123", fileDepRepoFiles(""))
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "charts/app", Release: "app", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if strings.Contains(g.Code, "dependency") {
			t.Fatalf("file:// sibling dependency should resolve with no dependency gap, got %+v", g)
		}
	}
	found := false
	for _, m := range manifests {
		if manifestStringField(m.Object, "kind") == "ConfigMap" {
			if name, _ := manifestNestedString(m.Object, "metadata", "name"); name == "common-cm" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected the file:// sibling chart's ConfigMap to be rendered, got %+v", manifests)
	}
}

func TestRenderHelmConditionDisablesSubchart(t *testing.T) {
	files := fileDepRepoFiles("common.enabled")
	files["charts/common/templates/deployment.yaml"] = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: common\n  namespace: {{ .Release.Namespace }}\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: img:v1\n"
	repo := buildInlineRepository("github.com/example/platform", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	disabled, _, err := r.renderHelm(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "charts/app", Release: "app", Namespace: "payments",
		Values: map[string]any{"common": map[string]any{"enabled": false}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, m := range disabled {
		if manifestStringField(m.Object, "kind") == "Deployment" {
			t.Fatalf("expected the condition-disabled subchart's Deployment to be excluded, got %+v", disabled)
		}
	}

	enabled, _, err := r.renderHelm(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "charts/app", Release: "app", Namespace: "payments",
		Values: map[string]any{"common": map[string]any{"enabled": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, m := range enabled {
		if manifestStringField(m.Object, "kind") == "Deployment" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the condition-enabled subchart's Deployment to render, got %+v", enabled)
	}
}

func TestRenderHelmDisabledConditionRemoteDependencySkipsFetchAndGap(t *testing.T) {
	files := basicChartFiles()
	files["mychart/Chart.yaml"] = "apiVersion: v2\nname: mychart\nversion: 1.0.0\ndependencies:\n- name: sub\n  version: \"^1.0.0-beta.26\"\n  repository: https://charts.example.com\n  condition: sub.enabled\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	chartReader := &fakeChartReader{}
	r := &manifestRenderer{
		repositories: newFakeRepositoryReader(), charts: chartReader, allowedChartRepositories: []string{"https://charts.example.com"},
		maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments,
	}

	_, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
		Values: map[string]any{"sub": map[string]any{"enabled": false}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if strings.Contains(g.Code, "dependency") || strings.Contains(g.Code, "chart_reader") {
			t.Fatalf("a disabled ranged/unpinned dependency must cause neither a fetch nor a gap, got %+v", gaps)
		}
	}
	if len(chartReader.calls) != 0 {
		t.Fatalf("disabled dependency must never be fetched, got calls %+v", chartReader.calls)
	}
}

func TestRenderHelmDisabledByChartDefaultRemoteDependencySkipsFetchAndGap(t *testing.T) {
	files := basicChartFiles()
	files["mychart/Chart.yaml"] = "apiVersion: v2\nname: mychart\nversion: 1.0.0\ndependencies:\n- name: sub\n  version: \"^1.0.0-beta.26\"\n  repository: https://charts.example.com\n  condition: sub.enabled\n"
	files["mychart/values.yaml"] = "image:\n  repository: example/app\n  tag: v1\nsub:\n  enabled: false\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	chartReader := &fakeChartReader{}
	r := &manifestRenderer{
		repositories: newFakeRepositoryReader(), charts: chartReader, allowedChartRepositories: []string{"https://charts.example.com"},
		maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments,
	}

	// No override in req.Values: the dependency is disabled purely by the
	// chart's own default values.yaml, exactly like writerai's "replicated"
	// dependency being enabled by default and only ever disabled by a
	// values overlay -- the evaluator must see chart defaults, not just the
	// composed request values, to get either direction right.
	_, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if strings.Contains(g.Code, "dependency") || strings.Contains(g.Code, "chart_reader") {
			t.Fatalf("a dependency disabled by the chart's own default values.yaml must cause neither a fetch nor a gap, got %+v", gaps)
		}
	}
	if len(chartReader.calls) != 0 {
		t.Fatalf("dependency disabled by chart defaults must never be fetched, got calls %+v", chartReader.calls)
	}
}

func TestRenderHelmEnabledUnpinnedRemoteDependencyStillGapsAndFetches(t *testing.T) {
	files := basicChartFiles()
	files["mychart/Chart.yaml"] = "apiVersion: v2\nname: mychart\nversion: 1.0.0\ndependencies:\n- name: sub\n  version: \">=1.0.0\"\n  repository: https://charts.example.com\n  condition: sub.enabled\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	_, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{
		Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments",
		Values: map[string]any{"sub": map[string]any{"enabled": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_dependency_unpinned" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_dependency_unpinned gap for an enabled version-range dependency, got %+v", gaps)
	}
}

func TestRenderHelmTplExecutedFileScannedButNonIdentityRendersWithoutGap(t *testing.T) {
	// files/unsafe.tpl is tpl-executed into a ConfigMap data value (not
	// referenced by any container): finding 9's conservative file scan
	// must still detect randAlphaNum there (feeding the render-twice path),
	// but since the only variance lands in non-identity ConfigMap content,
	// the chart renders successfully with no gap.
	files := basicChartFiles()
	files["mychart/files/unsafe.tpl"] = "{{ randAlphaNum 20 }}\n"
	files["mychart/templates/configmap.yaml"] = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: generated\n  namespace: {{ .Release.Namespace }}\ndata:\n  token: {{ tpl (.Files.Get \"files/unsafe.tpl\") . | quote }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps: the random token is non-identity ConfigMap content unreferenced by any container, got %+v", gaps)
	}
	kinds := map[string]int{}
	for _, m := range manifests {
		kinds[manifestStringField(m.Object, "kind")]++
	}
	if kinds["Deployment"] != 1 || kinds["ConfigMap"] != 1 {
		t.Fatalf("expected both the Deployment and the tpl-executed-file ConfigMap rendered, got %+v", kinds)
	}
}

func TestRenderHelmRandomServiceAccountNameProducesIdentityGap(t *testing.T) {
	// The ServiceAccount's own name is derived from randAlphaNum via a
	// tpl-executed chart file (exercising finding 9's conservative scan
	// too): two renders produce two different names, an identity-relevant
	// difference that must surface as a gap, not a silent pick of one.
	files := basicChartFiles()
	files["mychart/files/sa-suffix.tpl"] = "{{ randAlphaNum 6 }}"
	files["mychart/templates/serviceaccount.yaml"] = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ printf \"app-sa-%s\" (tpl (.Files.Get \"files/sa-suffix.tpl\") .) }}\n  namespace: {{ .Release.Namespace }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatalf("expected the first render's manifests returned alongside the gap, got none")
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_nondeterministic_identity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_nondeterministic_identity gap for a randomly-named ServiceAccount, got %+v", gaps)
	}
}

func TestRenderHelmFileScanIgnoresUnsafeWordInsideStringLiteral(t *testing.T) {
	files := basicChartFiles()
	files["mychart/files/notes.gotmpl"] = "{{- fail (printf \"catalog now resolves to something else\") -}}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_nondeterministic_chart" {
			t.Fatalf("English prose inside a quoted string literal must not be mistaken for a call to %q, got %+v", "now", gaps)
		}
	}
	if len(manifests) != 1 {
		t.Fatalf("expected the chart to still render, got %+v", manifests)
	}
}

func TestRenderHelmCustomResourceRandomSpecFieldProducesIdentityGap(t *testing.T) {
	// "widgets.example.com" is neither a Kubernetes built-in group nor a
	// Crossplane provider/apiextensions group: it falls through to the
	// generic custom-resource rule, which compares the full document
	// (minus annotations/labels/status/pod-template metadata). A spec
	// field derived from randAlphaNum must therefore surface as an
	// identity gap, exactly like a built-in ServiceAccount name would.
	files := basicChartFiles()
	files["mychart/templates/widget.yaml"] = "apiVersion: widgets.example.com/v1alpha1\nkind: Widget\nmetadata:\n  name: my-widget\n  namespace: {{ .Release.Namespace }}\nspec:\n  token: {{ randAlphaNum 10 | quote }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatalf("expected the first render's manifests returned alongside the gap, got none")
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_nondeterministic_identity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_nondeterministic_identity gap for a custom resource whose spec embeds randAlphaNum, got %+v", gaps)
	}
}

func TestRenderHelmCustomResourceAnnotationChurnProducesIdentityGap(t *testing.T) {
	// R07: a Crossplane composite's own apiVersion group is neither a
	// Kubernetes built-in nor a Crossplane provider/apiextensions group,
	// so it falls through to the generic custom-resource rule. A
	// Composition may read ANY composite field -- including
	// metadata.annotations -- via a FromCompositeFieldPath patch and
	// derive identity-relevant content (for example a downstream IAM role
	// ARN) from it, so the custom-resource projection must no longer
	// strip annotations/labels: random annotation content must surface as
	// a gap exactly like a random spec field would.
	files := basicChartFiles()
	files["mychart/templates/widget.yaml"] = "apiVersion: widgets.example.com/v1alpha1\nkind: Widget\nmetadata:\n  name: my-widget\n  namespace: {{ .Release.Namespace }}\n  annotations:\n    checksum: {{ randAlphaNum 10 | quote }}\n  labels:\n    build: {{ randAlphaNum 10 | quote }}\nspec:\n  foo: bar\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatalf("expected the first render's manifests returned alongside the gap, got none")
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_nondeterministic_identity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_nondeterministic_identity gap for a composite whose annotations/labels embed randAlphaNum, got %+v", gaps)
	}
}

func TestRenderHelmCustomResourceServerManagedMetadataOnlyDiffRendersWithoutGap(t *testing.T) {
	// Unlike annotations/labels, server-managed ObjectMeta bookkeeping
	// (manifestServerManagedMetadataFields) is still stripped: a
	// composite's identity-irrelevant resourceVersion churn alone must
	// not surface a gap.
	files := basicChartFiles()
	files["mychart/templates/widget.yaml"] = "apiVersion: widgets.example.com/v1alpha1\nkind: Widget\nmetadata:\n  name: my-widget\n  namespace: {{ .Release.Namespace }}\n  resourceVersion: {{ randAlphaNum 10 | quote }}\nspec:\n  foo: bar\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps: the composite differs only in stripped server-managed metadata, got %+v", gaps)
	}
	found := false
	for _, m := range manifests {
		if manifestStringField(m.Object, "kind") == "Widget" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the Widget custom resource rendered, got %+v", manifests)
	}
}

func TestRenderHelmBuiltinWorkloadAnnotationOnlyChurnRendersWithoutGap(t *testing.T) {
	// Control: a built-in workload's pod-template projection
	// (manifestHelmPodProjection) is built purely from podSpec -- it never
	// includes any ObjectMeta field at all, built-in or embedded pod
	// template -- so random annotations on a Deployment or its pod
	// template never surface a gap, unlike the composite case above.
	files := basicChartFiles()
	files["mychart/templates/deployment.yaml"] = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n  namespace: {{ .Release.Namespace }}\n  annotations:\n    checksum: {{ randAlphaNum 10 | quote }}\nspec:\n  template:\n    metadata:\n      annotations:\n        build: {{ randAlphaNum 10 | quote }}\n    spec:\n      serviceAccountName: app-sa\n      containers:\n      - name: app\n        image: \"{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps: a builtin workload's own/pod-template annotations are never part of its identity projection, got %+v", gaps)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 rendered Deployment, got %+v", manifests)
	}
}

func TestRenderHelmChartDefaultValueRandomServiceAccountNameProducesIdentityGap(t *testing.T) {
	// R07: a chart's own values.yaml DEFAULT (never overridden by the
	// request) referencing a nondeterministic function, consumed through
	// `tpl`, must still be scanned: only scanning the composed request
	// values (manifestHelmComposeValues(req)) misses this entirely, since
	// the chart's default never appears there -- it only appears once
	// coalesced the way Helm's own chartutil.CoalesceValues would.
	files := basicChartFiles()
	files["mychart/values.yaml"] = "image:\n  repository: example/app\n  tag: v1\nserviceAccountSuffix: \"{{ randAlphaNum 12 }}\"\n"
	files["mychart/templates/serviceaccount.yaml"] = "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: {{ printf \"app-sa-%s\" (tpl .Values.serviceAccountSuffix .) }}\n  namespace: {{ .Release.Namespace }}\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	// Request supplies no values of its own: req.Values never overrides
	// serviceAccountSuffix, so only the chart's own default carries it.
	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatalf("expected the first render's manifests returned alongside the gap, got none")
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_nondeterministic_identity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_nondeterministic_identity gap for a ServiceAccount name derived from a chart-default value, got %+v", gaps)
	}
}

func TestRenderHelmArgoRolloutWorkloadProjection(t *testing.T) {
	// R07: Argo Rollouts (argoproj.io/Rollout) are workloads, not
	// composites -- a nondeterministic value confined to a Rollout's
	// spec.strategy (non-podSpec content the targeted workload projection
	// never looks at) must render without a gap, exactly like an
	// equivalent Deployment field would.
	files := basicChartFiles()
	files["mychart/templates/rollout.yaml"] = "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: {{ .Release.Name }}\n  namespace: {{ .Release.Namespace }}\nspec:\n  strategy:\n    canary:\n      canaryService: {{ randAlphaNum 10 | quote }}\n  template:\n    spec:\n      serviceAccountName: app-sa\n      containers:\n      - name: app\n        image: \"{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps: a Rollout's non-podSpec field is outside the workload projection, got %+v", gaps)
	}
	found := false
	for _, m := range manifests {
		if manifestStringField(m.Object, "kind") == "Rollout" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the Rollout rendered, got %+v", manifests)
	}
}

func TestRenderHelmArgoRolloutServiceAccountChurnProducesIdentityGap(t *testing.T) {
	// R07: confirms the Rollout's workload projection is actually
	// targeted at the pod template (not the full-document custom-resource
	// rule, which would also catch this but for the wrong reason/scope):
	// a serviceAccountName derived from randAlphaNum must still surface a
	// gap.
	files := basicChartFiles()
	files["mychart/templates/rollout.yaml"] = "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: {{ .Release.Name }}\n  namespace: {{ .Release.Namespace }}\nspec:\n  template:\n    spec:\n      serviceAccountName: {{ printf \"app-sa-%s\" (randAlphaNum 6) }}\n      containers:\n      - name: app\n        image: \"{{ .Values.image.repository }}:{{ .Values.image.tag }}\"\n"
	repo := buildInlineRepository("github.com/example/gitops", "abc123", files)
	r := &manifestRenderer{repositories: newFakeRepositoryReader(), maxArgoDepth: manifestDefaultMaxArgoDepth, maxCrossplaneSteps: manifestDefaultMaxCrossplaneSteps, maxDocuments: manifestDefaultMaxDocuments}

	manifests, gaps, err := r.renderHelm(testContext(), ci.ManifestRequest{Repository: repo, Chart: "mychart", Release: "myapp", Namespace: "payments"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) == 0 {
		t.Fatalf("expected the first render's manifests returned alongside the gap, got none")
	}
	found := false
	for _, g := range gaps {
		if g.Code == "cloud_identity.manifest.helm_nondeterministic_identity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected helm_nondeterministic_identity gap for a Rollout whose pod template serviceAccountName embeds randAlphaNum, got %+v", gaps)
	}
}
