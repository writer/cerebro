package cloudidentitysource

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	ci "github.com/writer/cerebro/internal/cloudidentity"
	k8syaml "sigs.k8s.io/yaml"
)

const manifestCrossplaneAPIPrefix = "apiextensions.crossplane.io/"

// Compose expands Crossplane composites/claims among one target's
// aggregated manifests and returns only the composed resources.
func (r *manifestRenderer) Compose(ctx context.Context, req ci.ComposeRequest) ([]ci.Manifest, []ci.Gap, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	composed, gaps := manifestExpandCrossplane(req.Manifests, r.maxCrossplaneSteps)
	return composed, gaps, nil
}

type manifestCrossplaneComposition struct {
	manifest         ci.Manifest
	compositeTypeRef string
	pipeline         []map[string]any
}

// manifestCrossplaneXRD is a CompositeResourceDefinition's identity surface:
// which apiVersion/kind pairs it makes claimable (the composite kind itself,
// and for scope: Namespaced v1 XRDs the separate legacy claim kind), and
// which Composition it pins every instance to via enforcedCompositionRef
// (the confused-deputy fence the deployed XRole XRD uses).
type manifestCrossplaneXRD struct {
	manifest            ci.Manifest
	enforcedComposition string
	// compositeKey is the XRD's own canonical composite apiVersion/kind
	// (spec.names.kind under spec.group/<served version>), independent of
	// which key (composite or legacy claim) this XRD was looked up under.
	// Compositions are indexed/matched by this canonical type only: a
	// claim instance's own apiVersion/kind is the claim kind, never the
	// composite kind, so matching candidates/compositionRef type by the
	// claim's own key would silently find nothing for every claim.
	compositeKey string
}

// manifestExpandCrossplane pairs every Crossplane composite/claim instance
// among docs with the Composition (mode: Pipeline) that actually composes
// it -- respecting an instance's own spec.compositionRef.name or its XRD's
// spec.enforcedCompositionRef.name when present, otherwise matching by
// compositeTypeRef alone -- and runs that Composition's pipeline to produce
// composed (desired) resources. CompositeResourceDefinitions found among
// docs are used to recognize composite/claim kinds: an instance of a
// recognized kind that cannot be paired with exactly one usable Composition
// is a scoped gap rather than passing through unexpanded and unnoticed.
// Pure, no I/O, no execution of arbitrary downloaded function binaries: only
// function-environment-configs (static Reference resolution),
// function-patch-and-transform (FromCompositeFieldPath patches),
// function-go-templating (a pinned inline Go template, deterministic
// functions only) and function-auto-ready (output-neutral) are understood.
// Any other pipeline step is a scoped gap for that composite instance;
// whatever the pipeline produced up to that point is still returned, never
// discarded.
func manifestExpandCrossplane(docs []ci.Manifest, maxSteps int) ([]ci.Manifest, []ci.Gap) {
	compByName, compByType := manifestCrossplaneCompositions(docs)
	xrds := manifestCrossplaneXRDs(docs)
	environments := manifestCrossplaneEnvironmentConfigs(docs)
	if len(compByName) == 0 && len(xrds) == 0 {
		return nil, nil
	}
	var out []ci.Manifest
	var gaps []ci.Gap
	for _, m := range docs {
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		if apiVersion == "" || kind == "" {
			continue
		}
		if strings.HasPrefix(apiVersion, manifestCrossplaneAPIPrefix) &&
			(kind == "Composition" || kind == "CompositeResourceDefinition" || kind == "EnvironmentConfig") {
			continue
		}
		key := apiVersion + "/" + kind
		xrd := xrds[key]
		// typeKey is the composite type Compositions/compositionRef are
		// matched against: for a legacy claim instance this is the XRD's
		// own canonical composite GVK (never the claim's own GVK, which a
		// Composition's compositeTypeRef never references).
		typeKey := key
		if xrd != nil && xrd.compositeKey != "" {
			typeKey = xrd.compositeKey
		}
		candidates := compByType[typeKey]
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		scope := key
		if name != "" {
			scope = key + "/" + name
		}

		var compName string
		if ref, ok := manifestNestedString(m.Object, "spec", "compositionRef", "name"); ok && ref != "" {
			compName = ref
		} else if xrd != nil && xrd.enforcedComposition != "" {
			compName = xrd.enforcedComposition
		}

		var comp manifestCrossplaneComposition
		switch {
		case compName != "":
			c, ok := compByName[compName]
			if !ok {
				if xrd != nil || len(candidates) > 0 {
					gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_composition_not_found", Scope: scope, Message: "referenced Composition \"" + compName + "\" was not found among the target's aggregated manifests"})
				}
				continue
			}
			if c.compositeTypeRef != typeKey {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_composition_type_mismatch", Scope: scope, Message: "referenced Composition \"" + compName + "\" does not compose this composite/claim's type"})
				continue
			}
			comp = c
		case len(candidates) == 1:
			comp = candidates[0]
		case len(candidates) > 1:
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_composition_ambiguous", Scope: scope, Message: fmt.Sprintf("%d Compositions match this composite/claim's type with no compositionRef/enforcedCompositionRef to disambiguate", len(candidates))})
			continue
		default:
			if xrd != nil {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_composite_unmatched", Scope: scope, Message: "composite/claim kind is recognized by a CompositeResourceDefinition but no Composition composes it"})
			}
			continue
		}

		resources, g := manifestRunCrossplanePipeline(m, comp, maxSteps, environments)
		for i := range resources {
			ref := comp.manifest.Reference
			ref.Path = ref.Path + "#" + name
			resources[i].Reference = ref
		}
		out = append(out, resources...)
		gaps = append(gaps, g...)
	}
	return out, gaps
}

// manifestCrossplaneCompositions indexes every Composition (mode: Pipeline)
// among docs both by its own metadata.name (for compositionRef/
// enforcedCompositionRef lookups) and by its spec.compositeTypeRef
// apiVersion/kind (to find candidates when nothing selects a Composition
// explicitly; more than one candidate is ambiguous, never silently
// resolved by map-overwrite).
func manifestCrossplaneCompositions(docs []ci.Manifest) (byName map[string]manifestCrossplaneComposition, byType map[string][]manifestCrossplaneComposition) {
	byName = map[string]manifestCrossplaneComposition{}
	byType = map[string][]manifestCrossplaneComposition{}
	for _, m := range docs {
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		if !strings.HasPrefix(apiVersion, manifestCrossplaneAPIPrefix) || kind != "Composition" {
			continue
		}
		if mode, _ := manifestNestedString(m.Object, "spec", "mode"); mode != "Pipeline" {
			continue
		}
		typeRef, ok := manifestNestedMap(m.Object, "spec", "compositeTypeRef")
		if !ok {
			continue
		}
		typeAPIVersion := manifestStringField(typeRef, "apiVersion")
		typeKind := manifestStringField(typeRef, "kind")
		if typeAPIVersion == "" || typeKind == "" {
			continue
		}
		pipelineRaw, _ := manifestNestedSlice(m.Object, "spec", "pipeline")
		var pipeline []map[string]any
		for _, p := range pipelineRaw {
			if pm, ok := manifestAsMap(p); ok {
				pipeline = append(pipeline, pm)
			}
		}
		key := typeAPIVersion + "/" + typeKind
		comp := manifestCrossplaneComposition{manifest: m, compositeTypeRef: key, pipeline: pipeline}
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		if name != "" {
			byName[name] = comp
		}
		byType[key] = append(byType[key], comp)
	}
	return byName, byType
}

// manifestCrossplaneXRDs indexes every CompositeResourceDefinition among
// docs by each served version's composite apiVersion/kind (and, for XRDs
// that still declare claimNames, the legacy claim kind under the same
// group/version), so a composite/claim instance that matches no Composition
// can still be recognized as an incomplete Crossplane identity surface
// rather than an ordinary, irrelevant manifest.
func manifestCrossplaneXRDs(docs []ci.Manifest) map[string]*manifestCrossplaneXRD {
	out := map[string]*manifestCrossplaneXRD{}
	for _, m := range docs {
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		if !strings.HasPrefix(apiVersion, manifestCrossplaneAPIPrefix) || kind != "CompositeResourceDefinition" {
			continue
		}
		group, _ := manifestNestedString(m.Object, "spec", "group")
		compositeKind, _ := manifestNestedString(m.Object, "spec", "names", "kind")
		if group == "" || compositeKind == "" {
			continue
		}
		claimKind, _ := manifestNestedString(m.Object, "spec", "claimNames", "kind")
		enforced, _ := manifestNestedString(m.Object, "spec", "enforcedCompositionRef", "name")
		xrd := &manifestCrossplaneXRD{manifest: m, enforcedComposition: enforced}
		versions, _ := manifestNestedSlice(m.Object, "spec", "versions")
		// referenceableVersion is the single XRD version a Composition's
		// spec.compositeTypeRef.apiVersion must use (Crossplane allows
		// exactly one version marked `referenceable: true`); Compositions
		// are indexed/matched against this canonical composite type only.
		var referenceableVersion string
		for _, v := range versions {
			vm, ok := manifestAsMap(v)
			if !ok {
				continue
			}
			if ref, ok2 := vm["referenceable"].(bool); ok2 && ref {
				referenceableVersion = manifestStringField(vm, "name")
				break
			}
		}
		if referenceableVersion != "" {
			xrd.compositeKey = group + "/" + referenceableVersion + "/" + compositeKind
		}
		for _, v := range versions {
			vm, ok := manifestAsMap(v)
			if !ok {
				continue
			}
			if served, ok2 := vm["served"].(bool); ok2 && !served {
				continue
			}
			vname := manifestStringField(vm, "name")
			if vname == "" {
				continue
			}
			apiver := group + "/" + vname
			out[apiver+"/"+compositeKind] = xrd
			if claimKind != "" {
				out[apiver+"/"+claimKind] = xrd
			}
		}
	}
	return out
}

// manifestCrossplaneEnvironmentConfigs indexes every EnvironmentConfig among
// docs by metadata.name, for function-environment-configs Reference
// resolution.
func manifestCrossplaneEnvironmentConfigs(docs []ci.Manifest) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, m := range docs {
		apiVersion := manifestStringField(m.Object, "apiVersion")
		kind := manifestStringField(m.Object, "kind")
		if !strings.HasPrefix(apiVersion, manifestCrossplaneAPIPrefix) || kind != "EnvironmentConfig" {
			continue
		}
		name, _ := manifestNestedString(m.Object, "metadata", "name")
		if name == "" {
			continue
		}
		data, _ := manifestNestedMap(m.Object, "data")
		out[name] = data
	}
	return out
}

func manifestRunCrossplanePipeline(xr ci.Manifest, comp manifestCrossplaneComposition, maxSteps int, environments map[string]map[string]any) ([]ci.Manifest, []ci.Gap) {
	compName, _ := manifestNestedString(comp.manifest.Object, "metadata", "name")
	xrName, _ := manifestNestedString(xr.Object, "metadata", "name")
	scope := compName + "/" + xrName

	var gaps []ci.Gap
	steps := comp.pipeline
	if len(steps) > maxSteps {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_pipeline_too_long", Scope: scope, Message: fmt.Sprintf("pipeline has %d steps, exceeding the configured %d step bound", len(steps), maxSteps)})
		steps = steps[:maxSteps]
	}

	desired := map[string]map[string]any{}
	pctx := map[string]any{}
	for _, step := range steps {
		fnName, _ := manifestNestedString(step, "functionRef", "name")
		input, _ := manifestNestedMap(step, "input")
		switch fnName {
		case "function-environment-configs":
			gaps = append(gaps, manifestApplyEnvironmentConfigs(input, environments, pctx)...)
		case "function-patch-and-transform":
			gaps = append(gaps, manifestApplyPatchAndTransform(xr.Object, input, desired)...)
		case "function-go-templating":
			gaps = append(gaps, manifestApplyGoTemplating(xr.Object, input, desired, pctx)...)
		case "function-auto-ready":
			// Output-neutral: marks composed resources Ready once their
			// own readiness conditions are observed on a live cluster.
			// This analyzer never observes live state, so there is
			// nothing to apply and nothing to flag.
		default:
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_function_unsupported", Scope: scope + ":" + fnName, Message: "pipeline step function is not supported; output from prior steps is preserved"})
		}
	}

	names := make([]string, 0, len(desired))
	for n := range desired {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ci.Manifest, 0, len(names))
	for _, n := range names {
		out = append(out, ci.Manifest{Object: desired[n]})
	}
	return out, gaps
}

// manifestApplyEnvironmentConfigs resolves the documented
// "apiextensions.crossplane.io/environment" pipeline context key from
// function-environment-configs' static `type: Reference` entries, merging
// each referenced EnvironmentConfig's data in order (later entries
// overwrite earlier top-level keys, matching the function's own merge
// order). A `type: Selector` (or any other non-static form) cannot be
// resolved without live cluster label matching and is a scoped gap rather
// than a guess; the rest of the entries in the same step still resolve.
func manifestApplyEnvironmentConfigs(input map[string]any, environments map[string]map[string]any, pctx map[string]any) []ci.Gap {
	var gaps []ci.Gap
	entries, _ := manifestNestedSlice(input, "spec", "environmentConfigs")
	merged := map[string]any{}
	for i, e := range entries {
		em, ok := manifestAsMap(e)
		if !ok {
			continue
		}
		etype := manifestStringField(em, "type")
		if etype == "" {
			etype = "Reference"
		}
		if etype != "Reference" {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_environment_selector_unsupported", Scope: fmt.Sprintf("function-environment-configs[%d]", i), Message: "environment config selector type \"" + etype + "\" is not a static reference"})
			continue
		}
		name, _ := manifestNestedString(em, "ref", "name")
		if name == "" {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_environment_config_missing", Scope: fmt.Sprintf("function-environment-configs[%d]", i), Message: "reference has no ref.name"})
			continue
		}
		data, found := environments[name]
		if !found {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_environment_config_missing", Scope: name, Message: "referenced EnvironmentConfig was not present among the target's aggregated manifests"})
			continue
		}
		for k, v := range data {
			merged[k] = v
		}
	}
	pctx["apiextensions.crossplane.io/environment"] = merged
	return gaps
}

// manifestApplyPatchAndTransform implements the dominant real-world subset of
// function-patch-and-transform: each input.resources[] entry's "base" is
// deep-copied, then every FromCompositeFieldPath patch copies a field from
// the composite into the composed resource (optionally through a small,
// explicit set of string transforms). Any other patch type or transform is a
// scoped gap; the base resource is still produced with whatever patches did
// apply.
func manifestApplyPatchAndTransform(xr map[string]any, input map[string]any, desired map[string]map[string]any) []ci.Gap {
	var gaps []ci.Gap
	resources, _ := manifestAsSlice(input["resources"])
	for ri, r := range resources {
		rm, ok := manifestAsMap(r)
		if !ok {
			continue
		}
		resName := manifestStringField(rm, "name")
		if resName == "" {
			resName = fmt.Sprintf("resource-%d", ri)
		}
		base, ok := manifestAsMap(rm["base"])
		if !ok {
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_patch_unsupported", Scope: resName, Message: "resource entry has no base template"})
			continue
		}
		composed := manifestDeepCopyMap(base)
		patches, _ := manifestAsSlice(rm["patches"])
		for _, p := range patches {
			pm, ok := manifestAsMap(p)
			if !ok {
				continue
			}
			patchType := manifestStringField(pm, "type")
			if patchType == "" {
				patchType = "FromCompositeFieldPath"
			}
			if patchType != "FromCompositeFieldPath" {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_patch_unsupported", Scope: resName, Message: "patch type \"" + patchType + "\" is not supported"})
				continue
			}
			fromPath := manifestStringField(pm, "fromFieldPath")
			toPath := manifestStringField(pm, "toFieldPath")
			if toPath == "" {
				toPath = fromPath
			}
			if fromPath == "" {
				continue
			}
			value, ok := manifestGetFieldPath(xr, fromPath)
			if !ok {
				gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_patch_source_missing", Scope: resName + ":" + fromPath, Message: "patch source field was not present on the composite"})
				continue
			}
			value = manifestApplyTransforms(value, pm["transforms"], &gaps, resName+":"+toPath)
			manifestSetFieldPath(composed, toPath, value)
		}
		desired[resName] = composed
	}
	return gaps
}

func manifestApplyTransforms(value any, raw any, gaps *[]ci.Gap, scope string) any {
	list, ok := manifestAsSlice(raw)
	if !ok {
		return value
	}
	for _, t := range list {
		tm, ok := manifestAsMap(t)
		if !ok {
			continue
		}
		ttype := manifestStringField(tm, "type")
		if ttype != "string" {
			*gaps = append(*gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_transform_unsupported", Scope: scope, Message: "transform type \"" + ttype + "\" is not supported"})
			continue
		}
		sm, _ := manifestAsMap(tm["string"])
		stype := manifestStringField(sm, "type")
		s, isString := value.(string)
		switch stype {
		case "Format":
			value = fmt.Sprintf(manifestStringField(sm, "fmt"), value)
		case "TrimPrefix":
			if isString {
				value = strings.TrimPrefix(s, manifestStringField(sm, "trim"))
			}
		case "TrimSuffix":
			if isString {
				value = strings.TrimSuffix(s, manifestStringField(sm, "trim"))
			}
		case "Convert":
			switch manifestStringField(sm, "convert") {
			case "ToUpper":
				if isString {
					value = strings.ToUpper(s)
				}
			case "ToLower":
				if isString {
					value = strings.ToLower(s)
				}
			default:
				*gaps = append(*gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_transform_unsupported", Scope: scope, Message: "string convert \"" + manifestStringField(sm, "convert") + "\" is not supported"})
			}
		default:
			*gaps = append(*gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_transform_unsupported", Scope: scope, Message: "string transform type \"" + stype + "\" is not supported"})
		}
	}
	return value
}

// manifestCrossplaneAllowedFuncs is a deterministic function ALLOWLIST, not
// a blocklist: only functions known to produce the same output for the same
// input -- no wall-clock time, no process-wide pseudo-randomness, no
// crypto key/cert/password generation, no environment variable access, no
// DNS/network lookups -- are ever registered with the Go template engine
// that executes function-go-templating's inline template. Anything absent
// from this set (including future Sprig additions) is unsafe by default.
var manifestCrossplaneAllowedFuncs = map[string]bool{
	// Strings
	"abbrev": true, "abbrevboth": true, "trunc": true, "trim": true, "upper": true, "lower": true,
	"title": true, "untitle": true, "substr": true, "repeat": true, "trimall": true, "trimAll": true,
	"trimSuffix": true, "trimPrefix": true, "nospace": true, "initials": true, "swapcase": true,
	"snakecase": true, "camelcase": true, "kebabcase": true, "wrap": true, "wrapWith": true,
	"contains": true, "hasPrefix": true, "hasSuffix": true, "quote": true, "squote": true, "cat": true,
	"indent": true, "nindent": true, "replace": true, "plural": true, "sha1sum": true, "sha256sum": true,
	"sha512sum": true, "adler32sum": true, "toString": true,
	// Type conversion
	"atoi": true, "int64": true, "int": true, "float64": true, "seq": true, "toDecimal": true,
	// Split
	"split": true, "splitList": true, "splitn": true, "toStrings": true,
	// Loops
	"until": true, "untilStep": true,
	// Arithmetic (integer/decimal, not randomness)
	"add1": true, "add": true, "sub": true, "div": true, "mod": true, "mul": true,
	"add1f": true, "addf": true, "subf": true, "divf": true, "mulf": true,
	"biggest": true, "max": true, "min": true, "maxf": true, "minf": true,
	"ceil": true, "floor": true, "round": true,
	// String slices
	"join": true, "sortAlpha": true,
	// Defaults/flow
	"default": true, "empty": true, "coalesce": true, "all": true, "any": true, "compact": true,
	"mustCompact": true, "fromJson": true, "toJson": true, "toPrettyJson": true, "toRawJson": true,
	"mustFromJson": true, "mustToJson": true, "mustToPrettyJson": true, "mustToRawJson": true,
	"ternary": true, "deepCopy": true, "mustDeepCopy": true, "fail": true,
	// Reflection
	"typeOf": true, "typeIs": true, "typeIsLike": true, "kindOf": true, "kindIs": true, "deepEqual": true,
	// Paths (pure string manipulation, no filesystem access)
	"base": true, "dir": true, "clean": true, "ext": true, "isAbs": true,
	"osBase": true, "osClean": true, "osDir": true, "osExt": true, "osIsAbs": true,
	// Encoding
	"b64enc": true, "b64dec": true, "b32enc": true, "b32dec": true,
	// Data structures
	"tuple": true, "list": true, "dict": true, "get": true, "set": true, "unset": true, "hasKey": true,
	"pluck": true, "keys": true, "pick": true, "omit": true, "merge": true, "mergeOverwrite": true,
	"mustMerge": true, "mustMergeOverwrite": true, "values": true, "append": true, "push": true,
	"mustAppend": true, "mustPush": true, "prepend": true, "mustPrepend": true, "first": true,
	"mustFirst": true, "rest": true, "mustRest": true, "last": true, "mustLast": true, "initial": true,
	"mustInitial": true, "reverse": true, "mustReverse": true, "uniq": true, "mustUniq": true,
	"without": true, "mustWithout": true, "has": true, "mustHas": true, "slice": true, "mustSlice": true,
	"concat": true, "dig": true, "chunk": true, "mustChunk": true,
	// SemVer
	"semver": true, "semverCompare": true,
	// Regex (pure string matching, not I/O)
	"regexMatch": true, "mustRegexMatch": true, "regexFindAll": true, "mustRegexFindAll": true,
	"regexFind": true, "mustRegexFind": true, "regexReplaceAll": true, "mustRegexReplaceAll": true,
	"regexReplaceAllLiteral": true, "mustRegexReplaceAllLiteral": true, "regexSplit": true,
	"mustRegexSplit": true, "regexQuoteMeta": true,
	// URL parsing (string decomposition only, never a network request)
	"urlParse": true, "urlJoin": true,
}

// manifestCrossplaneFuncMap returns the Sprig function map filtered down to
// manifestCrossplaneAllowedFuncs.
func manifestCrossplaneFuncMap() template.FuncMap {
	all := sprig.TxtFuncMap()
	funcs := make(template.FuncMap, len(manifestCrossplaneAllowedFuncs))
	for name := range manifestCrossplaneAllowedFuncs {
		if fn, ok := all[name]; ok {
			funcs[name] = fn
		}
	}
	return funcs
}

var manifestCrossplaneActionPattern = regexp.MustCompile(`(?s)\{\{.*?\}\}`)

var manifestCrossplaneFuncPatterns = func() map[string]*regexp.Regexp {
	all := sprig.TxtFuncMap()
	m := make(map[string]*regexp.Regexp, len(all))
	for name := range all {
		if manifestCrossplaneAllowedFuncs[name] {
			continue
		}
		m[name] = regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
	}
	return m
}()

// manifestCrossplaneStripStringLiterals blanks out the contents of every
// double-quoted or backtick-quoted string literal in a `{{ ... }}` action
// (preserving length/positions is unnecessary here; only word matches
// outside literals matter), so prose inside a fail()/printf() message that
// happens to contain an unsafe function's name as an English word can never
// be mistaken for a call to it.
func manifestCrossplaneStripStringLiterals(action string) string {
	var out strings.Builder
	out.Grow(len(action))
	i := 0
	for i < len(action) {
		c := action[i]
		if c == '"' || c == '`' {
			quote := c
			out.WriteByte(' ')
			i++
			for i < len(action) {
				if quote == '"' && action[i] == '\\' && i+1 < len(action) {
					i += 2
					continue
				}
				if action[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.String()
}

// manifestCrossplaneScanDisallowedFuncs returns the distinct Sprig function
// names referenced inside any `{{ ... }}` action in source that are not in
// the deterministic allowlist. A match immediately preceded by `$` (a
// variable named e.g. `$env`) or `.` (a field/method access like `$env.env`
// or `.Values.now`) is a reference, not a call, and is not flagged.
func manifestCrossplaneScanDisallowedFuncs(source string) []string {
	actions := manifestCrossplaneActionPattern.FindAllString(source, -1)
	stripped := make([]string, len(actions))
	for i, a := range actions {
		stripped[i] = manifestCrossplaneStripStringLiterals(a)
	}
	var found []string
	for name, pattern := range manifestCrossplaneFuncPatterns {
		for _, s := range stripped {
			calls := false
			for _, loc := range pattern.FindAllStringIndex(s, -1) {
				if loc[0] > 0 && (s[loc[0]-1] == '$' || s[loc[0]-1] == '.') {
					continue
				}
				calls = true
				break
			}
			if calls {
				found = append(found, name)
				break
			}
		}
	}
	sort.Strings(found)
	return found
}

// manifestApplyGoTemplating executes a pinned inline Go template (the
// function-go-templating convention) with a typed context exposing the
// composite resource, this run's own accumulated desired resources, and the
// pipeline's accumulated context (".context", populated by a prior
// function-environment-configs step). ".observed.resources" always stays
// empty: it would require live cluster state from a previous reconcile that
// this analyzer never reads, so it is never fabricated. A template
// referencing any function outside the deterministic allowlist anywhere
// skips the whole step rather than executing it.
func manifestApplyGoTemplating(xr map[string]any, input map[string]any, desired map[string]map[string]any, pctx map[string]any) []ci.Gap {
	var gaps []ci.Gap
	tmplStr := ""
	if inline, ok := manifestAsMap(input["inline"]); ok {
		tmplStr = manifestStringField(inline, "template")
	}
	if tmplStr == "" {
		tmplStr = manifestStringField(input, "template")
	}
	if tmplStr == "" {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_function_unsupported", Scope: "function-go-templating", Message: "step has no inline template source"})
		return gaps
	}
	if found := manifestCrossplaneScanDisallowedFuncs(tmplStr); len(found) > 0 {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_nondeterministic_template", Scope: "function-go-templating", Message: "template references non-deterministic/unqueried-data function(s): " + strings.Join(found, ", ") + "; step skipped"})
		return gaps
	}

	desiredCopy := make(map[string]any, len(desired))
	for k, v := range desired {
		desiredCopy[k] = v
	}
	data := map[string]any{
		"observed": map[string]any{"composite": map[string]any{"resource": xr}, "resources": map[string]any{}},
		"desired":  map[string]any{"composite": map[string]any{"resource": xr}, "resources": desiredCopy},
		"context":  pctx,
	}

	t, err := template.New("crossplane").Funcs(manifestCrossplaneFuncMap()).Option("missingkey=zero").Parse(tmplStr)
	if err != nil {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_template_invalid", Scope: "function-go-templating", Message: err.Error()})
		return gaps
	}
	var buf strings.Builder
	if err := t.Execute(&buf, data); err != nil {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.crossplane_template_invalid", Scope: "function-go-templating", Message: err.Error()})
		return gaps
	}

	docs, err := manifestSplitYAMLDocuments([]byte(buf.String()))
	if err != nil {
		gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.document_malformed", Scope: "function-go-templating", Message: err.Error()})
		return gaps
	}
	for i, d := range docs {
		var obj map[string]any
		if err := k8syaml.Unmarshal(d, &obj); err != nil || obj == nil {
			msg := "decoded to an empty document"
			if err != nil {
				msg = err.Error()
			}
			gaps = append(gaps, ci.Gap{Code: "cloud_identity.manifest.document_malformed", Scope: fmt.Sprintf("function-go-templating[%d]", i), Message: msg})
			continue
		}
		resName, _ := manifestNestedString(obj, "metadata", "annotations", "gotemplating.fn.crossplane.io/composition-resource-name")
		if resName == "" {
			resName, _ = manifestNestedString(obj, "metadata", "name")
		}
		if resName == "" {
			resName = fmt.Sprintf("go-template-%d", i)
		}
		desired[resName] = obj
	}
	return gaps
}

func manifestDeepCopyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = manifestDeepCopyValue(v)
	}
	return out
}

func manifestDeepCopyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return manifestDeepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = manifestDeepCopyValue(e)
		}
		return out
	default:
		return v
	}
}
