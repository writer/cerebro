package cloudidentitysource

import (
	"context"
	"fmt"
	"path"
	"strings"
	"text/template"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"helm.sh/helm/v3/pkg/strvals"
	k8syaml "sigs.k8s.io/yaml"
)

const manifestArgoAPIGroupPrefix = "argoproj.io/"

// manifestRenderState tracks recursion bookkeeping (visited sources, for
// cycle detection) across one top-level Render call.
type manifestRenderState struct {
	renderer *manifestRenderer
	visited  map[string]bool
}

func newManifestRenderState(r *manifestRenderer) *manifestRenderState {
	return &manifestRenderState{renderer: r, visited: map[string]bool{}}
}

// expand walks docs, recursively expanding any Argo CD Application/
// ApplicationSet document via the renderer's injected RepositoryReader, up
// to the configured depth bound. Every other document passes through
// unchanged; Crossplane composites are expanded per target by Compose.
func (s *manifestRenderState) expand(ctx context.Context, docs []ci.Manifest, req ci.ManifestRequest, depth int) ([]ci.Manifest, []ci.Gap, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	var gaps []ci.Gap

	var out []ci.Manifest
	for _, m := range docs {
		if err := ctx.Err(); err != nil {
			return out, gaps, err
		}
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		if !strings.HasPrefix(apiVersion, manifestArgoAPIGroupPrefix) {
			out = append(out, m)
			continue
		}
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		if (kind == "Application" || kind == "ApplicationSet") && len(req.Applications) > 0 && !manifestApplicationAllowed(req.Applications, name) {
			// Out of this plan's scope: dropped without a gap, per the
			// ManifestInput.Applications contract.
			continue
		}
		if depth >= s.renderer.maxArgoDepth {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_recursion_bound", Scope: name, Message: "app-of-apps recursion exceeded the configured depth bound"})
			continue
		}
		switch kind {
		case "Application":
			expanded, g, err := s.expandApplication(ctx, m, req, depth)
			gaps = append(gaps, g...)
			if err != nil {
				return out, gaps, err
			}
			out = append(out, expanded...)
		case "ApplicationSet":
			expanded, g, err := s.expandApplicationSet(ctx, m, req, depth)
			gaps = append(gaps, g...)
			if err != nil {
				return out, gaps, err
			}
			out = append(out, expanded...)
		default:
			out = append(out, m)
		}
	}
	return out, gaps, nil
}

// manifestApplicationAllowed reports whether name is one of the configured
// ManifestRequest.Applications; an empty allowed list means unrestricted.
func manifestApplicationAllowed(allowed []string, name string) bool {
	for _, a := range allowed {
		if a == name {
			return true
		}
	}
	return false
}

// manifestVisitKey identifies one expanded Argo CD source for cycle
// detection: source coordinates (repoURL/revision/srcPath) PLUS
// namespace/release/values, since two Applications sharing the same
// repoURL/revision/srcPath but differing in destination namespace,
// release name, or Helm values are legitimately different renders, not a
// cycle. values is formatted with "%v", which (like encoding/json) prints
// map keys in sorted order, so the key is deterministic regardless of Go
// map iteration order.
func manifestVisitKey(repoURL, revision, srcPath, namespace, release string, values map[string]any) string {
	return repoURL + "@" + revision + ":" + srcPath + "|" + namespace + "#" + release + "=" + fmt.Sprintf("%v", values)
}

// expandApplication recursively fetches and renders every git source of one
// Argo CD Application. A "chart" source naming a non-git Helm repository or
// OCI registry is an explicit gap: RepositoryReader only resolves git-shaped
// pins, and there is no other pinned-bytes port for Helm-repository charts.
func (s *manifestRenderState) expandApplication(ctx context.Context, app ci.Manifest, parentReq ci.ManifestRequest, depth int) ([]ci.Manifest, []ci.Gap, error) {
	name, _ := manifestNestedString(app.Object, "metadata", "name")
	sources := manifestArgoSources(app.Object)
	if len(sources) == 0 {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.argo_source_missing", Scope: name, Message: "Application has no spec.source or spec.sources", References: []ci.Reference{app.Reference}}}, nil
	}
	namespace, _ := manifestNestedString(app.Object, "spec", "destination", "namespace")
	if namespace == "" {
		namespace = parentReq.Namespace
	}

	var out []ci.Manifest
	var gaps []ci.Gap
	refRepos := map[string]ci.Repository{}
	for _, src := range sources {
		repoURL := manifestStringField(src, "repoURL")
		targetRevision := manifestStringField(src, "targetRevision")
		srcPath := manifestStringField(src, "path")
		chartName := manifestStringField(src, "chart")

		// A source that only declares "ref" (no path/chart) exists purely to
		// make its repository available to other sources' "$<ref>/..."
		// value file references; it renders nothing on its own.
		if manifestStringField(src, "ref") != "" && srcPath == "" && chartName == "" {
			continue
		}

		if chartName != "" {
			rendered, g := s.renderArgoChartSource(ctx, src, sources, name, namespace, parentReq, refRepos)
			gaps = append(gaps, g...)
			if rendered == nil {
				continue
			}
			subReq := ci.ManifestRequest{Namespace: namespace, Environment: parentReq.Environment, Cluster: parentReq.Cluster, Applications: parentReq.Applications}
			expanded, g2, err := s.expand(ctx, rendered, subReq, depth+1)
			gaps = append(gaps, g2...)
			if err != nil {
				return out, gaps, err
			}
			out = append(out, expanded...)
			continue
		}
		if repoURL == "" {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_source_missing", Scope: name, Message: "Application source has no repoURL"})
			continue
		}

		repo, err := s.renderer.repositories.ReadRepository(ctx, ci.SourcePin{Repository: repoURL, Revision: targetRevision, Root: srcPath})
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.repository_fetch_failed", Scope: repoURL, Message: err.Error()})
			continue
		}
		gaps = append(gaps, repo.Gaps...)

		var rendered []ci.Manifest
		var release string
		var sourceValues map[string]any
		if _, isChart := manifestFindFile(repo, path.Join(srcPath, "Chart.yaml")); isChart {
			// A chart whose Chart.yaml declares a "file://../sibling"
			// dependency needs its sibling's files too, which live outside
			// the narrow srcPath root this source was just fetched with;
			// re-fetch (reusing the already-cached archive -- no extra
			// download) scoped to the chart's parent directory instead of
			// materializing the whole repository.
			if parent, needsWider := manifestHelmFileDependencyParent(repo, srcPath); needsWider {
				wider, werr := s.renderer.repositories.ReadRepository(ctx, ci.SourcePin{Repository: repoURL, Revision: targetRevision, Root: parent})
				if werr != nil {
					gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.repository_fetch_failed", Scope: repoURL, Message: werr.Error()})
				} else {
					gaps = append(gaps, wider.Gaps...)
					repo = wider
				}
			}
			values, g := s.resolveArgoValues(ctx, src, sources, repo, true, srcPath, refRepos)
			gaps = append(gaps, g...)
			sourceValues = values
			release = manifestStringField(firstHelmMap(src), "releaseName")
			if release == "" {
				release = name
			}
			subReq := ci.ManifestRequest{Repository: repo, Chart: srcPath, Values: values, Release: release, Namespace: namespace, Environment: parentReq.Environment, Cluster: parentReq.Cluster}
			r, g2, err := s.renderer.renderHelm(ctx, subReq)
			gaps = append(gaps, g2...)
			if err != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_render_failed", Scope: name, Message: err.Error()})
				continue
			}
			rendered = r
		} else if _, isKustomize := manifestFindFile(repo, path.Join(srcPath, "kustomization.yaml")); isKustomize {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_kustomize_unsupported", Scope: name, Message: "Application source " + srcPath + " is a Kustomize overlay, which is not rendered"})
			continue
		} else if _, isKustomizeYml := manifestFindFile(repo, path.Join(srcPath, "kustomization.yml")); isKustomizeYml {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_kustomize_unsupported", Scope: name, Message: "Application source " + srcPath + " is a Kustomize overlay, which is not rendered"})
			continue
		} else {
			r, g, err := manifestDecodeRawPath(repo, srcPath, namespace)
			gaps = append(gaps, g...)
			if err != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.path_unreadable", Scope: srcPath, Message: err.Error()})
				continue
			}
			rendered = r
		}

		// Cycle detection guards only the ACTIVE recursion stack (push
		// right before recursing, pop right after): two sibling or
		// diamond-shaped sources sharing the same repoURL/revision/srcPath
		// are a legitimate re-render, not a cycle, once the first one's
		// recursive expand call has returned -- only a source that is its
		// own (possibly indirect) ancestor is one. Keying on
		// namespace/release/values too means two sibling Applications that
		// share coordinates but differ in destination namespace, release
		// name, or Helm values are never conflated into a false cycle
		// either.
		visitKey := manifestVisitKey(repoURL, targetRevision, srcPath, namespace, release, sourceValues)
		if s.visited[visitKey] {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_cycle_detected", Scope: name, Message: "app-of-apps cycle detected for " + visitKey})
			continue
		}
		s.visited[visitKey] = true
		subReq := ci.ManifestRequest{Repository: repo, Namespace: namespace, Environment: parentReq.Environment, Cluster: parentReq.Cluster, Applications: parentReq.Applications}
		expanded, g, err := s.expand(ctx, rendered, subReq, depth+1)
		delete(s.visited, visitKey)
		gaps = append(gaps, g...)
		if err != nil {
			return out, gaps, err
		}
		out = append(out, expanded...)
	}
	return out, gaps, nil
}

// manifestHelmFileDependencyParent reports whether chrt (loaded from repo
// at chartPath) declares a Chart.yaml "file://../sibling" dependency whose
// target escapes chartPath, and if so the parent directory to re-fetch as
// root to cover it (one level up -- the common monorepo layout where every
// chart under one shared directory, e.g. "charts/", references its
// siblings this way). A dependency escaping even that widened root remains
// an explicit "file:// dependency ... not found" gap from
// resolveHelmDependencies rather than a silent whole-repository fetch.
func manifestHelmFileDependencyParent(repo ci.Repository, chartPath string) (string, bool) {
	file, ok := manifestFindFile(repo, path.Join(chartPath, "Chart.yaml"))
	if !ok {
		return "", false
	}
	var meta struct {
		Dependencies []struct {
			Repository string `yaml:"repository"`
		} `yaml:"dependencies"`
	}
	if err := k8syaml.Unmarshal(file.Content, &meta); err != nil {
		return "", false
	}
	escapes := false
	for _, dep := range meta.Dependencies {
		if !strings.HasPrefix(dep.Repository, "file://") {
			continue
		}
		relative := strings.TrimPrefix(dep.Repository, "file://")
		target := path.Clean(path.Join(chartPath, relative))
		if target != chartPath && !strings.HasPrefix(target, chartPath+"/") {
			escapes = true
			break
		}
	}
	if !escapes {
		return "", false
	}
	parent := path.Dir(chartPath)
	if parent == "." || parent == chartPath {
		return "", false
	}
	return parent, true
}

// renderArgoChartSource resolves a source's "chart" field (a Helm-repository
// or OCI chart reference, as opposed to a git path) through the renderer's
// ChartReader. It is only attempted when a ChartReader is configured, the
// source repository is allowlisted, and targetRevision is an exact pinned
// version; otherwise it returns a scoped gap and nil manifests rather than a
// silent guess at a floating version.
func (s *manifestRenderState) renderArgoChartSource(ctx context.Context, src map[string]any, sources []map[string]any, appName, namespace string, parentReq ci.ManifestRequest, refRepos map[string]ci.Repository) ([]ci.Manifest, []ci.Gap) {
	repoURL := manifestStringField(src, "repoURL")
	chartName := manifestStringField(src, "chart")
	version := manifestStringField(src, "targetRevision")
	if s.renderer.charts == nil {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.chart_reader_unavailable", Scope: appName, Message: "Application source references chart \"" + chartName + "\" but no ChartReader is configured"}}
	}
	if !s.renderer.chartRepositoryAllowed(repoURL) {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.chart_dependency_unapproved", Scope: repoURL, Message: "Argo chart source repository is not allowlisted"}}
	}
	if !manifestIsExactSemver(version) {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.helm_dependency_unpinned", Scope: appName, Message: "Argo chart source has no exact pinned targetRevision"}}
	}
	fetched, err := s.renderer.charts.ReadChart(ctx, ci.ChartReference{Repository: repoURL, Name: chartName, Version: version})
	if err != nil {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.chart_dependency_fetch_failed", Scope: repoURL + "/" + chartName, Message: err.Error()}}
	}
	values, gaps := s.resolveArgoValues(ctx, src, sources, fetched, true, "", refRepos)
	release := manifestStringField(firstHelmMap(src), "releaseName")
	if release == "" {
		release = chartName
	}
	rendered, g, err := s.renderer.renderHelm(ctx, ci.ManifestRequest{Repository: fetched, Chart: "", Values: values, Release: release, Namespace: namespace, Environment: parentReq.Environment, Cluster: parentReq.Cluster})
	gaps = append(gaps, g...)
	if err != nil {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_render_failed", Scope: appName, Message: err.Error()})
		return nil, gaps
	}
	return rendered, gaps
}

func firstHelmMap(src map[string]any) map[string]any {
	helm, _ := manifestAsMap(src["helm"])
	return helm
}

// expandApplicationSet supports only a "list" generator with static,
// literal elements -- the one case that is deterministically resolvable
// without calling an external generator (SCM provider, cluster, git
// directory/file, matrix, pull request, ...). Any other generator is an
// explicit, scoped gap; the ApplicationSet contributes no manifests.
func (s *manifestRenderState) expandApplicationSet(ctx context.Context, appSet ci.Manifest, parentReq ci.ManifestRequest, depth int) ([]ci.Manifest, []ci.Gap, error) {
	name, _ := manifestNestedString(appSet.Object, "metadata", "name")
	generators, _ := manifestNestedSlice(appSet.Object, "spec", "generators")
	tmpl, ok := manifestNestedMap(appSet.Object, "spec", "template")
	if !ok {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.argo_applicationset_template_missing", Scope: name, Message: "ApplicationSet has no spec.template"}}, nil
	}

	var elements []map[string]any
	var gaps []ci.Gap
	for _, g := range generators {
		gm, ok := manifestAsMap(g)
		if !ok {
			continue
		}
		list, isList := manifestAsMap(gm["list"])
		if !isList || len(gm) != 1 {
			generatorKind := "unknown"
			for k := range gm {
				generatorKind = k
				break
			}
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_applicationset_generator_unsupported", Scope: name, Message: "generator \"" + generatorKind + "\" is not statically resolvable"})
			continue
		}
		if _, hasTemplate := list["template"]; hasTemplate {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_applicationset_generator_unsupported", Scope: name, Message: "list generator per-element template override is not supported"})
			continue
		}
		rawElements, _ := manifestAsSlice(list["elements"])
		if rawElements == nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_applicationset_generator_unsupported", Scope: name, Message: "list generator has no static elements (elementsYaml/dynamic sources are not supported)"})
			continue
		}
		for _, e := range rawElements {
			em, ok := manifestAsMap(e)
			if ok {
				elements = append(elements, em)
			}
		}
	}

	var out []ci.Manifest
	for i, elem := range elements {
		rendered, err := manifestApplyApplicationSetTemplate(tmpl, elem)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_applicationset_template_invalid", Scope: fmt.Sprintf("%s[%d]", name, i), Message: err.Error()})
			continue
		}
		rendered["apiVersion"] = manifestStringField(appSet.Object, "apiVersion")
		rendered["kind"] = "Application"
		app := ci.Manifest{Object: rendered, Reference: appSet.Reference}
		expanded, g, err := s.expandApplication(ctx, app, parentReq, depth)
		gaps = append(gaps, g...)
		if err != nil {
			return out, gaps, err
		}
		out = append(out, expanded...)
	}
	return out, gaps, nil
}

// manifestApplyApplicationSetTemplate substitutes "{{.field}}" placeholders
// (the List generator's exposed element fields) throughout the
// ApplicationSet's spec.template using Go's text/template against the
// element map, then returns the resulting Application object (apiVersion,
// metadata, spec).
func manifestApplyApplicationSetTemplate(tmpl map[string]any, element map[string]any) (map[string]any, error) {
	raw, err := k8syaml.Marshal(tmpl)
	if err != nil {
		return nil, fmt.Errorf("marshal applicationset template: %w", err)
	}
	t, err := template.New("appset").Option("missingkey=zero").Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse applicationset template: %w", err)
	}
	var buf strings.Builder
	if err := t.Execute(&buf, element); err != nil {
		return nil, fmt.Errorf("execute applicationset template: %w", err)
	}
	var obj map[string]any
	if err := k8syaml.Unmarshal([]byte(buf.String()), &obj); err != nil {
		return nil, fmt.Errorf("decode rendered applicationset template: %w", err)
	}
	if obj == nil {
		obj = map[string]any{}
	}
	return obj, nil
}

// manifestArgoSources normalizes spec.source/spec.sources (newer Argo CD
// multi-source Applications) into one slice.
func manifestArgoSources(obj map[string]any) []map[string]any {
	if sources, ok := manifestNestedSlice(obj, "spec", "sources"); ok {
		var out []map[string]any
		for _, s := range sources {
			if m, ok := manifestAsMap(s); ok {
				out = append(out, m)
			}
		}
		return out
	}
	if source, ok := manifestNestedMap(obj, "spec", "source"); ok {
		return []map[string]any{source}
	}
	return nil
}

// resolveArgoValues builds the merged values map for one Application
// source's spec.source.helm block, in Argo CD's own layering: valueFiles
// (lowest), inline helm.values, helm.valuesObject, then helm.parameters
// (highest). Plain valueFiles entries resolve relative to srcPath (the
// chart's own repository-relative directory, matching Argo CD's documented
// behavior for a Helm chart source); a "$<ref>/<path>" entry is resolved
// instead, repository-relative, against whichever OTHER source in the same
// Application declares ref == <ref>, per Argo CD's multi-source convention
// -- a source that exists only to supply shared values files typically has
// no path/chart of its own. srcPath is "" for a chart-field (Helm
// repository/OCI) source, whose fetched repository is already scoped to
// the chart root.
func (s *manifestRenderState) resolveArgoValues(ctx context.Context, src map[string]any, sources []map[string]any, primaryRepo ci.Repository, primaryHasRepo bool, srcPath string, refRepos map[string]ci.Repository) (map[string]any, []ci.Gap) {
	values := map[string]any{}
	helm, ok := manifestAsMap(src["helm"])
	if !ok {
		return values, nil
	}
	var gaps []ci.Gap
	if vf, ok := manifestAsSlice(helm["valueFiles"]); ok {
		for _, v := range vf {
			entry, ok := manifestAsString(v)
			if !ok || entry == "" {
				continue
			}
			var repo ci.Repository
			filePath := entry
			if strings.HasPrefix(entry, "$") {
				parts := strings.SplitN(entry[1:], "/", 2)
				if len(parts) < 2 {
					gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_values_ref_invalid", Scope: entry, Message: "\"$ref/path\" value file reference has no path component"})
					continue
				}
				refRepo, ok, g := s.resolveArgoRef(ctx, sources, parts[0], refRepos)
				gaps = append(gaps, g...)
				if !ok {
					continue
				}
				repo, filePath = refRepo, parts[1]
			} else if primaryHasRepo {
				repo = primaryRepo
				if srcPath != "" {
					filePath = path.Join(srcPath, entry)
				}
			} else {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_values_ref_invalid", Scope: entry, Message: "value file reference has no repository context"})
				continue
			}
			file, ok := manifestFindFile(repo, filePath)
			if !ok {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_values_file_missing", Scope: entry, Message: "referenced values file was not found in the pinned repository"})
				continue
			}
			var parsed map[string]any
			if err := k8syaml.Unmarshal(file.Content, &parsed); err != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_values_file_invalid", Scope: entry, Message: err.Error()})
				continue
			}
			values = manifestDeepMergeValues(values, parsed)
		}
	}
	if inline, ok := manifestAsString(helm["values"]); ok && inline != "" {
		var parsed map[string]any
		if err := k8syaml.Unmarshal([]byte(inline), &parsed); err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_helm_values_invalid", Scope: "inline helm.values", Message: err.Error()})
		} else {
			values = manifestDeepMergeValues(values, parsed)
		}
	}
	if valuesObject, ok := manifestAsMap(helm["valuesObject"]); ok {
		values = manifestDeepMergeValues(values, valuesObject)
	}
	if params, ok := manifestAsSlice(helm["parameters"]); ok {
		for _, p := range params {
			pm, ok := manifestAsMap(p)
			if !ok {
				continue
			}
			paramName := manifestStringField(pm, "name")
			if paramName == "" {
				continue
			}
			paramValue, _ := manifestAsString(pm["value"])
			forceString, _ := pm["forceString"].(bool)
			setExpr := paramName + "=" + manifestCleanArgoSetParameterValue(paramValue)
			var perr error
			if forceString {
				perr = strvals.ParseIntoString(setExpr, values)
			} else {
				perr = strvals.ParseInto(setExpr, values)
			}
			if perr != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.argo_helm_parameter_invalid", Scope: paramName, Message: perr.Error()})
			}
		}
	}
	return values, gaps
}

// manifestCleanArgoSetParameterValue escapes a comma inside val the same
// way Argo CD's own repo-server does before handing a helm.parameters
// entry's value to Helm's --set/--set-string machinery
// (helm.sh/helm/v3/pkg/strvals): strvals treats an unescaped "," as a
// key=value pair separator, so a scalar value containing a literal comma
// (anything not already a Helm "{a,b,c}" list literal) must be escaped to
// survive as one value rather than being split.
func manifestCleanArgoSetParameterValue(val string) string {
	if strings.HasPrefix(val, "{") && strings.HasSuffix(val, "}") {
		return val
	}
	return strings.ReplaceAll(val, ",", `\,`)
}

// resolveArgoRef fetches (once, cached in refRepos) the repository of
// whichever source in sources declares ref == refName.
func (s *manifestRenderState) resolveArgoRef(ctx context.Context, sources []map[string]any, refName string, refRepos map[string]ci.Repository) (ci.Repository, bool, []ci.Gap) {
	if repo, ok := refRepos[refName]; ok {
		return repo, true, nil
	}
	for _, src := range sources {
		if manifestStringField(src, "ref") != refName {
			continue
		}
		repoURL := manifestStringField(src, "repoURL")
		if repoURL == "" {
			return ci.Repository{}, false, []ci.Gap{{Code: "cloud_identity.manifest.argo_values_ref_invalid", Scope: refName, Message: "referenced source has no repoURL"}}
		}
		repo, err := s.renderer.repositories.ReadRepository(ctx, ci.SourcePin{Repository: repoURL, Revision: manifestStringField(src, "targetRevision")})
		if err != nil {
			return ci.Repository{}, false, []ci.Gap{{Code: "cloud_identity.manifest.repository_fetch_failed", Scope: repoURL, Message: err.Error()}}
		}
		refRepos[refName] = repo
		return repo, true, nil
	}
	return ci.Repository{}, false, []ci.Gap{{Code: "cloud_identity.manifest.argo_values_ref_invalid", Scope: refName, Message: "no source in this Application declares ref \"" + refName + "\""}}
}
