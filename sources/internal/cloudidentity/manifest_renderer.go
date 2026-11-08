package cloudidentitysource

import (
	"context"
	"fmt"
	"sort"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// Bound defaults protect against runaway recursion/expansion of untrusted,
// already-pinned repository content. Callers may widen them through
// ManifestRendererOptions.
const (
	manifestDefaultMaxArgoDepth       = 8
	manifestDefaultMaxCrossplaneSteps = 32
	manifestDefaultMaxDocuments       = 4096
)

// ManifestRendererOptions configures NewManifestRenderer. Repositories is
// required; it resolves pinned repository/revision references encountered
// while recursively expanding Argo CD Application/app-of-apps sources.
// Charts and AllowedChartRepositories are optional: without them, a chart
// dependency that is not already vendored under charts/ in the pinned
// repository becomes an explicit gap instead of a silent guess.
type ManifestRendererOptions struct {
	// Repositories resolves additional pinned SourcePin references
	// encountered during Argo CD Application/app-of-apps recursion.
	Repositories ci.RepositoryReader
	// Charts fetches an allowlisted, exact-version Helm chart dependency
	// that is not already vendored under the pinned repository's charts/
	// directory. Optional.
	Charts ci.ChartReader
	// AllowedChartRepositories mirrors the ChartReader's own allowlist so
	// the renderer can report a precise "not approved" gap itself before
	// ever calling Charts.ReadChart.
	AllowedChartRepositories []string
	// MaxArgoDepth bounds Argo CD app-of-apps recursion. Zero uses the
	// package default.
	MaxArgoDepth int
	// MaxCrossplaneSteps bounds the Crossplane composition pipeline
	// function steps expanded per composite instance. Zero uses the
	// package default.
	MaxCrossplaneSteps int
	// MaxDocuments bounds the number of rendered Kubernetes documents
	// returned by one Render call. Zero uses the package default.
	MaxDocuments int
}

type manifestRenderer struct {
	repositories             ci.RepositoryReader
	charts                   ci.ChartReader
	allowedChartRepositories []string
	maxArgoDepth             int
	maxCrossplaneSteps       int
	maxDocuments             int
}

// NewManifestRenderer builds a ci.ManifestRenderer that deterministically
// renders raw YAML, Helm charts/values, Argo CD Application (including
// app-of-apps) sources, and Crossplane Composition pipelines from pinned,
// already-materialized repository bytes. It never shells out to an external
// binary, never downloads or executes a Crossplane/Argo function image, and
// its only network-shaped dependency is the injected RepositoryReader/
// ChartReader -- both already reviewed, bounded Source CDK ports.
func NewManifestRenderer(options ManifestRendererOptions) (ci.ManifestRenderer, error) {
	if options.Repositories == nil {
		return nil, fmt.Errorf("cloudidentitysource: manifest renderer requires a RepositoryReader")
	}
	r := &manifestRenderer{
		repositories:             options.Repositories,
		charts:                   options.Charts,
		allowedChartRepositories: append([]string(nil), options.AllowedChartRepositories...),
		maxArgoDepth:             options.MaxArgoDepth,
		maxCrossplaneSteps:       options.MaxCrossplaneSteps,
		maxDocuments:             options.MaxDocuments,
	}
	if r.maxArgoDepth <= 0 {
		r.maxArgoDepth = manifestDefaultMaxArgoDepth
	}
	if r.maxCrossplaneSteps <= 0 {
		r.maxCrossplaneSteps = manifestDefaultMaxCrossplaneSteps
	}
	if r.maxDocuments <= 0 {
		r.maxDocuments = manifestDefaultMaxDocuments
	}
	return r, nil
}

// Render renders req.Chart (when set) via Helm, decodes req.Paths as raw
// YAML, then recursively expands any Argo CD Application/ApplicationSet
// document found among the result. Crossplane composites are left for
// Compose, which sees every manifest rendered for the target.
func (r *manifestRenderer) Render(ctx context.Context, req ci.ManifestRequest) ([]ci.Manifest, []ci.Gap, error) {
	var manifests []ci.Manifest
	var gaps []ci.Gap

	if req.Chart != "" {
		rendered, g, err := r.renderHelm(ctx, req)
		manifests = append(manifests, rendered...)
		gaps = append(gaps, g...)
		if err != nil {
			return manifests, gaps, err
		}
	}
	for _, p := range req.Paths {
		rendered, g, err := manifestDecodeRawPath(req.Repository, p, req.Namespace)
		gaps = append(gaps, g...)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.path_unreadable", Scope: p, Message: err.Error()})
			continue
		}
		manifests = append(manifests, rendered...)
	}

	state := newManifestRenderState(r)
	expanded, expGaps, err := state.expand(ctx, manifests, req, 0)
	gaps = append(gaps, expGaps...)
	if err != nil {
		return expanded, gaps, err
	}

	if len(expanded) > r.maxDocuments {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.too_many_documents", Scope: req.Chart, Message: fmt.Sprintf("rendered document count %d exceeded the configured %d document bound", len(expanded), r.maxDocuments)})
		expanded = expanded[:r.maxDocuments]
	}
	gaps = append(gaps, manifestUnresolvedValueMarkerGaps(expanded, req.UnresolvedValues)...)
	return expanded, gaps, nil
}

// manifestUnresolvedValueMarkerGaps reports, for every rendered object that
// contains at least one ci.UnresolvedValueMarker, a single
// cloud_identity.manifest.unresolved_value_in_object gap scoped to that
// object (apiVersion|kind|namespace|name, matching
// manifestHelmIdentityProjection's key convention) naming every
// req.UnresolvedValues key reached. manifestHelmComposeValues binds the
// marker so required(...) still renders; this is the other half of finding
// #1's contract -- every rendered field a marker reaches is traceable back
// to an explicit, object-scoped gap instead of silently looking like a
// real ARN/name to a declaration parser (see ack_declarations.go's
// boundary handling for the ACK-specific consumer of this same marker).
func manifestUnresolvedValueMarkerGaps(manifests []ci.Manifest, unresolvedValues []string) []ci.Gap {
	if len(unresolvedValues) == 0 {
		return nil
	}
	markers := make(map[string]string, len(unresolvedValues))
	for _, key := range unresolvedValues {
		markers[ci.UnresolvedValueMarker(key)] = key
	}
	var gaps []ci.Gap
	for _, m := range manifests {
		keys := manifestUnresolvedValueMarkerKeysIn(m.Object, markers)
		if len(keys) == 0 {
			continue
		}
		sort.Strings(keys)
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		namespace, _ := manifestNestedString(m.Object, "metadata", "namespace")
		scope := apiVersion + "|" + kind + "|" + namespace + "|" + name
		gaps = append(gaps, ci.Gap{
			Code:       "cloud_identity.manifest.unresolved_value_in_object",
			Scope:      scope,
			Message:    "rendered object carries the unresolved Terraform-contract value marker for " + strings.Join(keys, ", ") + "; any field derived from it is unknown, never a real identifier",
			References: []ci.Reference{m.Reference},
		})
	}
	return gaps
}

// manifestUnresolvedValueMarkerKeysIn returns the distinct unresolved-value
// keys (markers' values in the markers map) found anywhere within node.
func manifestUnresolvedValueMarkerKeysIn(node any, markers map[string]string) []string {
	found := map[string]bool{}
	manifestWalkUnresolvedValueMarkers(node, markers, found)
	if len(found) == 0 {
		return nil
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	return keys
}

func manifestWalkUnresolvedValueMarkers(node any, markers map[string]string, found map[string]bool) {
	switch v := node.(type) {
	case map[string]any:
		for _, val := range v {
			manifestWalkUnresolvedValueMarkers(val, markers, found)
		}
	case []any:
		for _, val := range v {
			manifestWalkUnresolvedValueMarkers(val, markers, found)
		}
	case string:
		for marker, key := range markers {
			if strings.Contains(v, marker) {
				found[key] = true
			}
		}
	}
}
