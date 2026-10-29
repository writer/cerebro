package cloudidentitysource

import (
	"context"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/engine"
	k8syaml "sigs.k8s.io/yaml"
)

// manifestNondeterministicFunctionNames enumerates every Sprig/Helm
// template function whose output can vary across otherwise-identical
// renders: randomness, generated key material, and the current time.
// Referencing one does not refuse the chart outright -- Helm's zero-value
// engine.Engine (no clientProvider, EnableDNS=false, which is exactly what
// engine.Render below always constructs) never performs I/O for any Helm
// template function, so there is nothing unsafe about evaluating them. The
// real risk is that their non-identity byte output (cert PEM bytes,
// generated secrets, timestamps) differs from what a real install would
// produce; renderHelm instead renders twice and compares the
// identity-relevant projection of both outputs (see
// manifestHelmIdentityDiff): identical projections return the first render
// with no gap, differing ones (for example a ServiceAccount name itself
// derived from randAlphaNum) return cloud_identity.manifest.
// helm_nondeterministic_identity instead.
//
// "lookup" is deliberately NOT here: with no clientProvider it is always
// the harmless, identical-every-call placeholder returning an empty map
// (see funcMap()/Render() in helm.sh/helm/v3/pkg/engine) -- not
// nondeterministic, so it needs no special handling. "env"/"expandenv"
// need none either: Helm's engine strips them from the FuncMap entirely,
// so calling them is a template execution error, never an I/O call.
// "getHostByName" is Sprig's only template function capable of real DNS
// I/O; Helm's engine (EnableDNS defaults to false, which the zero-value
// Engine engine.Render always uses) overrides it to unconditionally
// return "", so it performs no I/O through this renderer either.
var manifestNondeterministicFunctionNames = []string{
	"now", "randAlphaNum", "randAlpha", "randNumeric", "randAscii", "randBytes", "randInt",
	"shuffle", "uuidv4", "genPrivateKey", "genCA", "genCAWithKey", "genSelfSignedCert",
	"genSignedCert", "genSignedCertWithKey", "derivePassword", "htpasswd",
}

var manifestTemplateActionPattern = regexp.MustCompile(`(?s)\{\{.*?\}\}`)

var manifestNondeterministicFunctionPatterns = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(manifestNondeterministicFunctionNames))
	for _, name := range manifestNondeterministicFunctionNames {
		m[name] = regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	}
	return m
}()

var manifestExactSemverPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// manifestScanNondeterministicFunctions returns the distinct
// nondeterministic function names referenced inside any `{{ ... }}` action
// in source. Quoted/backtick string-literal content is stripped from each
// action before matching, so a function's name appearing only as English
// prose inside a fail()/printf() message argument (for example
// "...catalog now resolves to...") is never mistaken for an actual call to
// that function; a bare call like `{{ now }}` is untouched by the
// stripping and still matches.
func manifestScanNondeterministicFunctions(source string) []string {
	seen := map[string]bool{}
	var found []string
	actions := manifestTemplateActionPattern.FindAllString(source, -1)
	for i, action := range actions {
		actions[i] = manifestStripTemplateStringLiterals(action)
	}
	for _, name := range manifestNondeterministicFunctionNames {
		pattern := manifestNondeterministicFunctionPatterns[name]
		for _, action := range actions {
			if pattern.MatchString(action) {
				if !seen[name] {
					seen[name] = true
					found = append(found, name)
				}
				break
			}
		}
	}
	return found
}

// manifestStripTemplateStringLiterals blanks the content of every
// double-quoted or backtick-quoted Go template string literal in action,
// preserving everything else (so delimiters/operators/identifiers keep
// their positions and real function calls are unaffected).
func manifestStripTemplateStringLiterals(action string) string {
	var out strings.Builder
	out.Grow(len(action))
	inDouble, inBacktick, escaped := false, false, false
	for _, r := range action {
		switch {
		case inDouble:
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inDouble = false
			}
			continue
		case inBacktick:
			if r == '`' {
				inBacktick = false
			}
			continue
		case r == '"':
			inDouble = true
			continue
		case r == '`':
			inBacktick = true
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

func manifestIsExactSemver(v string) bool {
	return manifestExactSemverPattern.MatchString(strings.TrimSpace(v))
}

// renderHelm loads the chart at req.Chart from the pinned repository, resolves
// any chart dependency that is not already vendored under charts/ via the
// renderer's ChartReader (when configured and allowlisted), composes values
// from req.ValuesFiles then req.Values (highest precedence), and renders
// through Helm's own zero-value engine (no clientProvider, no DNS -- see
// manifestNondeterministicFunctionNames), which never performs I/O for any
// template function it exposes.
//
// Templates/tpl-reachable files referencing a nondeterministic function
// (randomness, generated key material, the current time) do not refuse
// the chart: renderHelm renders twice and compares the identity-relevant
// projection of both outputs (manifestHelmIdentityDiff). Identical
// projections mean the variance is confined to non-identity data (cert
// PEM bytes, generated secrets, timestamps) and the first render is
// returned with no gap; a difference in identity-relevant content (for
// example a ServiceAccount name itself derived from randAlphaNum) returns
// the first render's manifests plus a target-scoped
// cloud_identity.manifest.helm_nondeterministic_identity gap naming the
// differing documents, rather than a guess at which render is "real".
func (r *manifestRenderer) renderHelm(ctx context.Context, req ci.ManifestRequest) ([]ci.Manifest, []ci.Gap, error) {
	files := manifestHelmBufferedFiles(req.Repository, req.Chart)
	if len(files) == 0 {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.helm_chart_missing", Scope: req.Chart, Message: "no files found under the configured chart path"}},
			fmt.Errorf("helm chart %q not found in pinned repository", req.Chart)
	}
	chrt, err := loader.LoadFiles(files)
	if err != nil {
		return nil, []ci.Gap{{Code: "cloud_identity.manifest.helm_chart_malformed", Scope: req.Chart, Message: err.Error()}},
			fmt.Errorf("load helm chart: %w", err)
	}
	var gaps []ci.Gap
	values, valueGaps := manifestHelmComposeValues(req)
	gaps = append(gaps, valueGaps...)

	// Dependency conditions/tags are evaluated against these composed
	// values BEFORE any pin validation or fetch: a dependency Helm would
	// disable for this release must cause neither a fetch nor a gap, not
	// even when it has no exact pinned version.
	gaps = append(gaps, r.resolveHelmDependencies(ctx, chrt, req.Repository, req.Chart, manifestDeepMergeValues(chrt.Values, values), "")...)

	// ProcessDependenciesWithMerge must run after every dependency (vendored,
	// file://, or ChartReader-fetched) is attached: it recursively disables
	// subcharts per their condition/tags against these composed values,
	// resolves aliases, and merges import-values -- skipping it would render
	// (and inventory) subcharts that are actually disabled for this release.
	if err := chartutil.ProcessDependenciesWithMerge(chrt, values); err != nil {
		return nil, append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_values_invalid", Scope: req.Chart, Message: err.Error()}),
			fmt.Errorf("process helm chart dependencies: %w", err)
	}

	nondeterministic := manifestHelmNondeterministicFunctions(chrt)

	release := req.Release
	if release == "" {
		release = chrt.Name()
	}
	renderVals, err := chartutil.ToRenderValues(chrt, values, chartutil.ReleaseOptions{Name: release, Namespace: req.Namespace, IsInstall: true}, chartutil.DefaultCapabilities)
	if err != nil {
		return nil, append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_values_invalid", Scope: req.Chart, Message: err.Error()}),
			fmt.Errorf("compose helm values: %w", err)
	}
	// Scan the fully coalesced values -- req.Values merged over every
	// chart's and subchart's own default values.yaml, exactly as Helm's
	// own chartutil.CoalesceValues (which ToRenderValues just called to
	// build renderVals["Values"]) composes them -- not just the request's
	// own composed values: a chart's default values.yaml referencing a
	// nondeterministic function (e.g. a ServiceAccount name default of
	// `{{ randAlphaNum 12 }}`, later consumed through `tpl`) would
	// otherwise never be scanned unless a caller happened to override it.
	if coalesced, ok := renderVals["Values"].(chartutil.Values); ok {
		nondeterministic = append(nondeterministic, manifestValuesNondeterministicFunctions(coalesced)...)
	}

	rendered, err := engine.Render(chrt, renderVals)
	if err != nil {
		return nil, append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_render_failed", Scope: req.Chart, Message: err.Error()}),
			fmt.Errorf("render helm chart: %w", err)
	}
	manifests, decodeGaps := manifestDecodeHelmOutput(rendered, req)
	gaps = append(gaps, decodeGaps...)

	if len(nondeterministic) > 0 {
		rendered2, err2 := engine.Render(chrt, renderVals)
		if err2 != nil {
			gaps = append(gaps, ci.Gap{
				Code:    "cloud_identity.manifest.helm_nondeterministic_unverified",
				Scope:   req.Chart,
				Message: "chart references non-deterministic function(s) (" + strings.Join(manifestDedupeStrings(nondeterministic), ", ") + ") but the second render used to check their identity impact failed: " + err2.Error(),
			})
		} else {
			manifests2, _ := manifestDecodeHelmOutput(rendered2, req)
			if diffs := manifestHelmIdentityDiff(manifests, manifests2); len(diffs) > 0 {
				gaps = append(gaps, ci.Gap{
					Code:  "cloud_identity.manifest.helm_nondeterministic_identity",
					Scope: req.Chart,
					Message: "chart templates or composed values reference non-deterministic function(s) (" + strings.Join(manifestDedupeStrings(nondeterministic), ", ") +
						") whose output changed identity-relevant content across two renders: " + strings.Join(diffs, ", "),
				})
			}
			// Residual limitation: a time-derived value that happens to be
			// identical across both renders within the same process tick
			// (for example `now` truncated to a coarse unit) is
			// indistinguishable from a genuinely stable value by this
			// check and passes through undetected. No additional
			// machinery (delays, clock injection) is added to narrow this.
		}
	}
	return manifests, gaps, nil
}

// manifestDecodeHelmOutput splits and decodes one engine.Render result into
// Manifests, exactly as renderHelm did inline before the render-twice
// comparison needed to call it for two separate render outputs. Like Helm's
// own install/template actions, rendered NOTES.txt files are release notes,
// not manifests, and are never decoded.
func manifestDecodeHelmOutput(rendered map[string]string, req ci.ManifestRequest) ([]ci.Manifest, []ci.Gap) {
	var manifests []ci.Manifest
	var gaps []ci.Gap
	for filename, content := range rendered {
		if strings.HasSuffix(filename, "NOTES.txt") {
			continue
		}
		docs, err := manifestSplitYAMLDocuments([]byte(content))
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.document_malformed", Scope: filename, Message: err.Error()})
			continue
		}
		for i, doc := range docs {
			ref := ci.Reference{Repository: req.Repository.Pin.Repository, Revision: req.Repository.Pin.Revision, Path: filename}
			if len(docs) > 1 {
				ref.Path = fmt.Sprintf("%s#%d", filename, i)
			}
			m, ok, err := manifestDecodeDocument(doc, ref, req.Namespace)
			if err != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.document_malformed", Scope: ref.Path, Message: err.Error()})
				continue
			}
			if !ok {
				continue
			}
			manifests = append(manifests, m)
		}
	}
	return manifests, gaps
}

// manifestIdentityBearingAPIGroupSuffixes identify Crossplane provider
// (managed-resource) and apiextensions.crossplane.io (composite-resource
// machinery) API groups whose entire document is identity-relevant
// (grants, trust, bindings), not just a documented subset of fields.
var manifestIdentityBearingAPIGroupSuffixes = []string{".upbound.io", "iam.cnrm.cloud.google.com", "apiextensions.crossplane.io"}

// manifestBuiltinAPIGroups are the core Kubernetes API groups (alongside
// any group equal to or ending in "k8s.io", see manifestIsBuiltinAPIGroup)
// whose identity-relevant content is well-understood, bounded schema
// captured by the targeted per-kind projection below
// (manifestHelmPodProjection et al.) rather than the whole document.
var manifestBuiltinAPIGroups = map[string]bool{
	"":            true, // core group ("v1", no group segment in apiVersion)
	"apps":        true,
	"batch":       true,
	"policy":      true,
	"autoscaling": true,
}

// manifestAPIGroup returns the API group segment of apiVersion ("" for the
// core group, whose apiVersion is a bare version like "v1" with no "/").
func manifestAPIGroup(apiVersion string) string {
	if idx := strings.IndexByte(apiVersion, '/'); idx >= 0 {
		return apiVersion[:idx]
	}
	return ""
}

// manifestIsBuiltinAPIGroup reports whether group is a core Kubernetes API
// group (manifestBuiltinAPIGroups) or any group equal to or ending in
// "k8s.io" (networking.k8s.io, rbac.authorization.k8s.io, ...).
func manifestIsBuiltinAPIGroup(group string) bool {
	if manifestBuiltinAPIGroups[group] {
		return true
	}
	return group == "k8s.io" || strings.HasSuffix(group, ".k8s.io")
}

func manifestIsIdentityBearingAPIVersion(apiVersion string) bool {
	group := manifestAPIGroup(apiVersion)
	for _, suffix := range manifestIdentityBearingAPIGroupSuffixes {
		if strings.HasSuffix(group, suffix) {
			return true
		}
	}
	return false
}

var manifestWorkloadPodKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true, "Pod": true}

// manifestHelmIdentityDiff compares the identity-relevant projection
// (manifestHelmIdentityProjection) of two renders of the same chart and
// returns the sorted "apiVersion|kind|namespace|name" keys of every
// document whose identity-relevant content differs (added, removed, or
// changed) between them. An empty result means every difference between
// the two renders is confined to non-identity data.
func manifestHelmIdentityDiff(a, b []ci.Manifest) []string {
	projA := manifestHelmIdentityProjection(a)
	projB := manifestHelmIdentityProjection(b)
	seen := make(map[string]bool, len(projA))
	var diffs []string
	for key, va := range projA {
		seen[key] = true
		if vb, ok := projB[key]; !ok || !reflect.DeepEqual(va, vb) {
			diffs = append(diffs, key)
		}
	}
	for key := range projB {
		if !seen[key] {
			diffs = append(diffs, key)
		}
	}
	sort.Strings(diffs)
	return diffs
}

// manifestHelmIdentityProjection builds the comparable, identity-relevant
// subset of manifests that downstream identity collection actually
// consumes, routed by each document's API group
// (manifestIsBuiltinAPIGroup/manifestIsIdentityBearingAPIVersion):
//
//   - Kubernetes built-in groups (core, apps, batch, policy, autoscaling,
//     and any group equal to or ending in "k8s.io") get the targeted,
//     well-understood projection: apiVersion/kind/metadata.name/
//     metadata.namespace for every kind; for ServiceAccount, its
//     annotations and automount flag; for workload kinds
//     (Deployment/StatefulSet/DaemonSet/Job/CronJob/Pod), the pod
//     template's serviceAccountName plus each container/initContainer's
//     name/image/env/envFrom and the .data of any ConfigMap those
//     env/envFrom entries reference. Non-identity fields (replica counts,
//     resource limits, probes, labels, Secret data, ...) are never
//     included, so a chart varying only those across renders is never
//     flagged.
//   - Argo Rollouts (argoproj.io Rollout, see manifestIsArgoRolloutWorkload)
//     are workloads, not composites: they get the identical targeted
//     pod-template projection as a built-in Deployment/StatefulSet
//     (spec.template.spec's serviceAccountName/containers), not the
//     full-document custom-resource rule below.
//   - Crossplane provider and apiextensions.crossplane.io groups
//     (manifestIsIdentityBearingAPIVersion) get the full document: every
//     field is identity-relevant (grants, trust, bindings).
//   - Every other group -- any custom resource, including a Crossplane
//     composite/claim of any name defined by a cluster's own XRDs (which
//     may be vendored from a different chart than the Composition that
//     patches them) -- gets the full document minus status and
//     server-managed metadata (manifestHelmCustomResourceProjection):
//     metadata.annotations/labels/name/namespace are KEPT, since a
//     Composition may read any composite field -- including annotations
//     -- via a FromCompositeFieldPath patch and derive identity-relevant
//     content (for example a downstream IAM role ARN) from it.
func manifestHelmIdentityProjection(manifests []ci.Manifest) map[string]any {
	configMapData := map[string]map[string]any{}
	for _, m := range manifests {
		if manifestStringField(m.Object, "kind") != "ConfigMap" {
			continue
		}
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		namespace, _ := manifestNestedString(m.Object, "metadata", "namespace")
		data, _ := manifestNestedMap(m.Object, "data")
		configMapData[namespace+"/"+name] = data
	}

	proj := make(map[string]any, len(manifests))
	for _, m := range manifests {
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		namespace, _ := manifestNestedString(m.Object, "metadata", "namespace")
		key := apiVersion + "|" + kind + "|" + namespace + "|" + name

		switch {
		case manifestIsIdentityBearingAPIVersion(apiVersion):
			proj[key] = m.Object
		case manifestIsBuiltinAPIGroup(manifestAPIGroup(apiVersion)):
			switch {
			case kind == "ServiceAccount":
				annotations, _ := manifestNestedMap(m.Object, "metadata", "annotations")
				proj[key] = map[string]any{"annotations": annotations, "automountServiceAccountToken": m.Object["automountServiceAccountToken"]}
			case kind == "CronJob":
				podSpec, _ := manifestNestedMap(m.Object, "spec", "jobTemplate", "spec", "template", "spec")
				proj[key] = manifestHelmPodProjection(podSpec, namespace, configMapData)
			case manifestWorkloadPodKinds[kind]:
				var podSpec map[string]any
				if kind == "Pod" {
					podSpec, _ = manifestNestedMap(m.Object, "spec")
				} else {
					podSpec, _ = manifestNestedMap(m.Object, "spec", "template", "spec")
				}
				proj[key] = manifestHelmPodProjection(podSpec, namespace, configMapData)
			default:
				proj[key] = nil
			}
		case manifestIsArgoRolloutWorkload(apiVersion, kind):
			podSpec, _ := manifestNestedMap(m.Object, "spec", "template", "spec")
			proj[key] = manifestHelmPodProjection(podSpec, namespace, configMapData)
		default:
			proj[key] = manifestHelmCustomResourceProjection(m.Object)
		}
	}
	return proj
}

// manifestIsArgoRolloutWorkload reports whether apiVersion/kind is an Argo
// Rollouts (argoproj.io) Rollout: a workload resource (its spec.template is
// an ordinary corev1.PodTemplateSpec, exactly like Deployment's), not a
// Crossplane-style composite, so it gets the same targeted pod-template
// projection as a built-in workload kind rather than the full-document
// custom-resource rule.
func manifestIsArgoRolloutWorkload(apiVersion, kind string) bool {
	return kind == "Rollout" && manifestAPIGroup(apiVersion) == "argoproj.io"
}

// manifestServerManagedMetadataFields are the ObjectMeta fields Kubernetes
// itself populates/mutates server-side (never something a chart author's
// template meaningfully varies to express identity): stripping these from
// a custom resource's metadata mirrors the volatile bookkeeping every
// built-in kind already excludes, without discarding
// name/namespace/annotations/labels, which a composite's own schema is
// free to carry identity-relevant data in.
var manifestServerManagedMetadataFields = []string{
	"creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp",
	"generation", "managedFields", "resourceVersion", "selfLink", "uid",
}

// manifestHelmCustomResourceProjection returns a deep copy of obj (a
// non-built-in, non-Crossplane-provider, non-Argo-Rollout custom resource
// document) with status and server-managed metadata
// (manifestServerManagedMetadataFields) removed, plus metadata removed
// from any embedded pod template found anywhere in the document at a
// spec.template.metadata path (manifestStripPodTemplateMetadata) -- the
// same volatile bookkeeping Kubernetes itself treats as non-identity on
// every built-in kind. metadata.annotations, metadata.labels,
// metadata.name, and metadata.namespace are deliberately KEPT: a
// Crossplane composite's schema is unknown ahead of time and a Composition
// may read any of its fields -- including annotations/labels -- via a
// FromCompositeFieldPath patch, so the remainder of an unknown custom
// resource's schema is compared wholesale rather than guessed at.
func manifestHelmCustomResourceProjection(obj map[string]any) map[string]any {
	cp := manifestDeepCopyMap(obj)
	if metadata, ok := manifestAsMap(cp["metadata"]); ok {
		for _, field := range manifestServerManagedMetadataFields {
			delete(metadata, field)
		}
	}
	delete(cp, "status")
	manifestStripPodTemplateMetadata(cp)
	return cp
}

// manifestStripPodTemplateMetadata recursively removes metadata from
// every "spec"."template" sub-map found anywhere within node (maps and
// slices), so an embedded PodTemplateSpec's own volatile
// annotations/labels never cause a false identity gap while its
// serviceAccountName/containers (the rest of spec.template) remain
// comparable.
func manifestStripPodTemplateMetadata(node any) {
	switch v := node.(type) {
	case map[string]any:
		if spec, ok := manifestAsMap(v["spec"]); ok {
			if tmpl, ok := manifestAsMap(spec["template"]); ok {
				delete(tmpl, "metadata")
			}
		}
		for _, child := range v {
			manifestStripPodTemplateMetadata(child)
		}
	case []any:
		for _, child := range v {
			manifestStripPodTemplateMetadata(child)
		}
	}
}

func manifestHelmPodProjection(podSpec map[string]any, namespace string, configMapData map[string]map[string]any) map[string]any {
	return map[string]any{
		"serviceAccountName": podSpec["serviceAccountName"],
		"containers":         manifestHelmContainersProjection(podSpec["containers"], namespace, configMapData),
		"initContainers":     manifestHelmContainersProjection(podSpec["initContainers"], namespace, configMapData),
	}
}

func manifestHelmContainersProjection(raw any, namespace string, configMapData map[string]map[string]any) []map[string]any {
	slice, _ := manifestAsSlice(raw)
	out := make([]map[string]any, 0, len(slice))
	for _, c := range slice {
		cm, ok := manifestAsMap(c)
		if !ok {
			continue
		}
		entry := map[string]any{"name": cm["name"], "image": cm["image"], "env": cm["env"], "envFrom": cm["envFrom"]}
		referenced := map[string]any{}
		for _, cmName := range manifestHelmReferencedConfigMapNames(cm) {
			if data, ok := configMapData[namespace+"/"+cmName]; ok {
				referenced[cmName] = data
			}
		}
		if len(referenced) > 0 {
			entry["referencedConfigMapData"] = referenced
		}
		out = append(out, entry)
	}
	return out
}

// manifestHelmReferencedConfigMapNames returns the sorted, deduped names of
// every ConfigMap container references via envFrom.configMapRef or
// env[].valueFrom.configMapKeyRef.
func manifestHelmReferencedConfigMapNames(container map[string]any) []string {
	names := map[string]bool{}
	if envFrom, ok := manifestAsSlice(container["envFrom"]); ok {
		for _, ef := range envFrom {
			efm, ok := manifestAsMap(ef)
			if !ok {
				continue
			}
			if ref, ok := manifestAsMap(efm["configMapRef"]); ok {
				if n, ok := manifestAsString(ref["name"]); ok {
					names[n] = true
				}
			}
		}
	}
	if env, ok := manifestAsSlice(container["env"]); ok {
		for _, e := range env {
			em, ok := manifestAsMap(e)
			if !ok {
				continue
			}
			if vf, ok := manifestAsMap(em["valueFrom"]); ok {
				if ref, ok := manifestAsMap(vf["configMapKeyRef"]); ok {
					if n, ok := manifestAsString(ref["name"]); ok {
						names[n] = true
					}
				}
			}
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func manifestHelmBufferedFiles(repo ci.Repository, chartRoot string) []*loader.BufferedFile {
	var out []*loader.BufferedFile
	for _, f := range manifestFilesUnderRoot(repo, chartRoot) {
		rel, ok := manifestSafeRelative(chartRoot, f.Path)
		if !ok || rel == "" {
			continue
		}
		out = append(out, &loader.BufferedFile{Name: rel, Data: f.Content})
	}
	return out
}

// resolveHelmDependencies attaches every Chart.yaml-declared dependency that
// is not already vendored under charts/ (which loader.LoadFiles already
// resolved purely in-memory from the pinned repository bytes, including
// charts/*.tgz). repo is the repository chrt's own files were loaded from
// (the originally pinned repository, or a ChartReader-fetched one when
// recursing into a remote dependency); chartDir is chrt's own repository-
// relative directory within repo ("" when repo is already scoped to the
// chart root, as a ChartReader-fetched repository is). evalValues is the
// best-available approximation of Helm's own chartutil.CoalesceValues
// result (the composed request values with each already-known chart's own
// default values.yaml merged in under its namespace, override values
// winning) and valuesPath is the dot-path prefix ("" at the chart root,
// "<name>." under a parent dependency) at which chrt's own
// condition/tags keys are looked up within evalValues -- together they let
// a not-yet-attached dependency's Helm condition/tags be evaluated BEFORE
// any pin validation or fetch happens.
//
// "file://<relative>" dependencies are ordinary Helm local-sibling
// references resolved purely within the already-pinned repository tree --
// relative to the declaring chart's own directory, not the request's chart
// root -- so private bundled charts with many such siblings work exactly
// like real `helm dependency update` output, no remote fetch involved.
// Every other dependency is only fetched when it has an exact pinned
// version (from Chart.lock, or a plain semver with no range operator) and
// its repository is allowlisted; otherwise it becomes a scoped gap rather
// than a silent guess. Resolution recurses into each attached subchart so
// nested dependencies (a sibling chart that itself has further file:// or
// remote dependencies) resolve too, not just the root chart's own list.
//
// A dependency Helm's own condition/tags evaluation would disable for this
// release is skipped entirely before any of that: no fetch, no pin check,
// no gap -- matching ProcessDependenciesWithMerge's later authoritative
// disable, which still runs over whatever actually got attached.
func (r *manifestRenderer) resolveHelmDependencies(ctx context.Context, chrt *chart.Chart, repo ci.Repository, chartDir string, evalValues map[string]any, valuesPath string) []ci.Gap {
	if chrt.Metadata == nil {
		return nil
	}
	loaded := make(map[string]bool, len(chrt.Dependencies()))
	for _, d := range chrt.Dependencies() {
		loaded[d.Name()] = true
	}
	lockVersions := map[string]string{}
	if chrt.Lock != nil {
		for _, d := range chrt.Lock.Dependencies {
			if d != nil {
				lockVersions[d.Name] = d.Version
			}
		}
	}

	var gaps []ci.Gap
	for _, dep := range chrt.Metadata.Dependencies {
		if dep == nil || dep.Name == "" || loaded[dep.Name] {
			continue
		}
		scope := chrt.Name() + "/" + dep.Name
		if !manifestDependencyEnabled(dep, evalValues, valuesPath) {
			continue
		}

		if strings.HasPrefix(dep.Repository, "file://") {
			relative := strings.TrimPrefix(dep.Repository, "file://")
			targetDir := path.Clean(path.Join(chartDir, relative))
			files := manifestHelmBufferedFiles(repo, targetDir)
			if len(files) == 0 {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_dependency_missing", Scope: scope, Message: "file:// dependency path \"" + targetDir + "\" was not found in the pinned repository"})
				continue
			}
			sub, err := loader.LoadFiles(files)
			if err != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_chart_malformed", Scope: scope, Message: err.Error()})
				continue
			}
			subPath := valuesPath + dep.Name + "."
			subEval := manifestDeepMergeValues(manifestValuesDefaultsAtPath(subPath, sub.Values), evalValues)
			gaps = append(gaps, r.resolveHelmDependencies(ctx, sub, repo, targetDir, subEval, subPath)...)
			chrt.AddDependency(sub)
			continue
		}
		if dep.Repository == "" {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_dependency_missing", Scope: scope, Message: "chart dependency is not vendored under charts/ and has no fetchable repository"})
			continue
		}

		version := dep.Version
		if v, ok := lockVersions[dep.Name]; ok && v != "" {
			version = v
		}
		if !manifestIsExactSemver(version) {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_dependency_unpinned", Scope: scope, Message: "chart dependency has no exact pinned version (Chart.lock missing or version is a range)"})
			continue
		}
		if r.charts == nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.chart_reader_unavailable", Scope: scope, Message: "no ChartReader configured to fetch a missing vendored dependency"})
			continue
		}
		if !r.chartRepositoryAllowed(dep.Repository) {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.chart_dependency_unapproved", Scope: dep.Repository, Message: "chart dependency repository is not allowlisted"})
			continue
		}
		fetched, err := r.charts.ReadChart(ctx, ci.ChartReference{Repository: dep.Repository, Name: dep.Name, Version: version})
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.chart_dependency_fetch_failed", Scope: dep.Repository + "/" + dep.Name, Message: err.Error()})
			continue
		}
		subFiles := make([]*loader.BufferedFile, 0, len(fetched.Files))
		for _, f := range fetched.Files {
			subFiles = append(subFiles, &loader.BufferedFile{Name: f.Path, Data: f.Content})
		}
		sub, err := loader.LoadFiles(subFiles)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_chart_malformed", Scope: dep.Name, Message: err.Error()})
			continue
		}
		subPath := valuesPath + dep.Name + "."
		subEval := manifestDeepMergeValues(manifestValuesDefaultsAtPath(subPath, sub.Values), evalValues)
		gaps = append(gaps, r.resolveHelmDependencies(ctx, sub, fetched, "", subEval, subPath)...)
		chrt.AddDependency(sub)
	}
	return gaps
}

// manifestDependencyEnabled mirrors Helm's own chartutil condition/tags
// enable-disable resolution (tags first, condition taking final
// precedence, defaulting to enabled) closely enough to decide, from
// evalValues, whether a not-yet-attached dependency would end up enabled --
// without pulling in Helm's own unexported CoalesceValues machinery.
func manifestDependencyEnabled(dep *chart.Dependency, evalValues map[string]any, valuesPath string) bool {
	enabled := true
	if tags, ok := manifestGetFieldPath(evalValues, valuesPath+"tags"); ok {
		if tagMap, ok := tags.(map[string]any); ok {
			var hasTrue, hasFalse bool
			for _, tag := range dep.Tags {
				v, ok := tagMap[tag]
				if !ok {
					continue
				}
				if b, ok := v.(bool); ok {
					if b {
						hasTrue = true
					} else {
						hasFalse = true
					}
				}
			}
			if !hasTrue && hasFalse {
				enabled = false
			} else if hasTrue || (!hasTrue && !hasFalse) {
				enabled = true
			}
		}
	}
	for _, c := range strings.Split(strings.TrimSpace(dep.Condition), ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if v, ok := manifestGetFieldPath(evalValues, valuesPath+c); ok {
			if b, ok := v.(bool); ok {
				enabled = b
				break
			}
		}
	}
	return enabled
}

// manifestValuesDefaultsAtPath wraps defaults under path's dot-separated
// segments ("a.b." -> {"a":{"b": defaults}}), so a chart's own default
// values.yaml can be merged into the running top-level evalValues map at
// the namespace Helm itself would coalesce it under. path=="" returns
// defaults unwrapped.
func manifestValuesDefaultsAtPath(path string, defaults map[string]any) map[string]any {
	trimmed := strings.TrimSuffix(path, ".")
	if trimmed == "" {
		return defaults
	}
	segments := strings.Split(trimmed, ".")
	wrapped := defaults
	for i := len(segments) - 1; i >= 0; i-- {
		wrapped = map[string]any{segments[i]: wrapped}
	}
	return wrapped
}

func (r *manifestRenderer) chartRepositoryAllowed(repository string) bool {
	if len(r.allowedChartRepositories) == 0 {
		return false
	}
	for _, a := range r.allowedChartRepositories {
		if a == repository {
			return true
		}
	}
	return false
}

// manifestHelmComposeValues merges req.ValuesFiles (resolved against the
// chart root, then the repository root, in order) and finally req.Values
// (highest precedence) into one values map. It never reads live cluster
// state; every file comes from the already-pinned Repository.
func manifestHelmComposeValues(req ci.ManifestRequest) (map[string]any, []ci.Gap) {
	values := map[string]any{}
	var gaps []ci.Gap
	for _, vf := range req.ValuesFiles {
		file, ok := manifestFindFile(req.Repository, vf)
		if !ok && req.Chart != "" {
			file, ok = manifestFindFile(req.Repository, path.Join(req.Chart, vf))
		}
		if !ok {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_values_file_missing", Scope: vf, Message: "referenced values file was not found in the pinned repository"})
			continue
		}
		var parsed map[string]any
		if err := k8syaml.Unmarshal(file.Content, &parsed); err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.helm_values_file_invalid", Scope: vf, Message: err.Error()})
			continue
		}
		values = manifestDeepMergeValues(values, parsed)
	}
	if req.Values != nil {
		values = manifestDeepMergeValues(values, req.Values)
	}
	return values, gaps
}

func manifestDeepMergeValues(dst, src map[string]any) map[string]any {
	out := make(map[string]any, len(dst)+len(src))
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := out[k].(map[string]any); ok {
				out[k] = manifestDeepMergeValues(dv, sv)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// manifestHelmNondeterministicFunctions recurses the loaded chart tree
// (root plus every dependency, vendored or fetched) and returns every
// distinct nondeterministic function name referenced anywhere in any
// template -- directly rendered or helper.
//
// Every other chart file (c.Files: anything not under templates/) is
// scanned too, conservatively, whenever it contains a `{{ ... }}` action:
// `.Files.Get "path" | tpl .` is a standard Helm pattern for executing
// arbitrary chart file content through the same template engine, and
// statically proving a given file is never reached that way would require
// tracing every template's data flow -- even though most chart files
// containing `{{ }}` (for example Crossplane pipeline step bodies read
// verbatim via .Files.Get and never passed through `tpl`, or an Argo CD
// values overlay later rendered by a *different* chart's own `tpl` call)
// are never actually executed by this chart's own Helm render.
func manifestHelmNondeterministicFunctions(root *chart.Chart) []string {
	var found []string
	var walk func(c *chart.Chart)
	walk = func(c *chart.Chart) {
		for _, t := range c.Templates {
			if t == nil {
				continue
			}
			found = append(found, manifestScanNondeterministicFunctions(string(t.Data))...)
		}
		for _, f := range c.Files {
			if f == nil || !manifestTemplateActionPattern.MatchString(string(f.Data)) {
				continue
			}
			found = append(found, manifestScanNondeterministicFunctions(string(f.Data))...)
		}
		for _, d := range c.Dependencies() {
			walk(d)
		}
	}
	walk(root)
	return found
}

// manifestValuesNondeterministicFunctions recursively scans every string
// leaf in a composed values map for a template action referencing a
// nondeterministic function (such a string may later be passed through the
// `tpl` function by any number of templates, so its effect can never be
// isolated to one output).
func manifestValuesNondeterministicFunctions(values map[string]any) []string {
	var found []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, vv := range x {
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		case string:
			if strings.Contains(x, "{{") {
				found = append(found, manifestScanNondeterministicFunctions(x)...)
			}
		}
	}
	walk(values)
	return found
}

func manifestDedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
