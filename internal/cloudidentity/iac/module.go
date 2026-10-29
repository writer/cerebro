package iac

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

func sortedAttrNames(attrs hclsyntax.Attributes) []string {
	out := make([]string, 0, len(attrs))
	for n := range attrs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func isLocalModuleSource(src string) bool {
	return strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") || strings.HasPrefix(src, "/")
}

// tfvarsFilesUnderDir returns the Terraform implicitly auto-loaded tfvars
// files directly under dir, in Terraform's own precedence order:
// "terraform.tfvars" first (if present), then "terraform.tfvars.json" (if
// present), then every "*.auto.tfvars"/"*.auto.tfvars.json" file together,
// in lexical filename order (R14 finding 1). Any other
// "*.tfvars"/"*.tfvars.json" file (e.g. "prod.tfvars"/"prod.tfvars.json")
// is only loaded when explicitly selected with `-var-file`, which this
// reader never does implicitly; TerraformInput.Variables is the explicit
// channel for such values.
func tfvarsFilesUnderDir(files map[string]*ci.SourceFile, dir string) []*ci.SourceFile {
	var autoPaths []string
	var terraformTfvars, terraformTfvarsJSON *ci.SourceFile
	for p, f := range files {
		if normalizePath(p) != dir {
			continue
		}
		switch base := path.Base(p); {
		case base == "terraform.tfvars":
			terraformTfvars = f
		case base == "terraform.tfvars.json":
			terraformTfvarsJSON = f
		case strings.HasSuffix(base, ".auto.tfvars"), strings.HasSuffix(base, ".auto.tfvars.json"):
			autoPaths = append(autoPaths, p)
		}
	}
	sort.Strings(autoPaths)
	out := make([]*ci.SourceFile, 0, len(autoPaths)+2)
	if terraformTfvars != nil {
		out = append(out, terraformTfvars)
	}
	if terraformTfvarsJSON != nil {
		out = append(out, terraformTfvarsJSON)
	}
	for _, p := range autoPaths {
		out = append(out, files[p])
	}
	return out
}

// resolveRootVariables merges `variable` default literals discovered while
// parsing (applied inside processModule), auto-loaded *.tfvars files, and the
// caller-supplied TerraformInput.Variables (highest precedence, mirroring
// `-var`). It returns the tfvars+explicit layer only; processModule layers
// `variable { default = ... }` beneath it.
func (rn *run) resolveRootVariables(allFiles map[string]*ci.SourceFile, dir string, root moduleFiles, explicit map[string]any) (map[string]cty.Value, []ci.Gap) {
	var gaps []ci.Gap
	out := map[string]cty.Value{}

	for _, f := range tfvarsFilesUnderDir(allFiles, dir) {
		var body hcl.Body
		if strings.HasSuffix(f.Path, ".json") {
			// terraform.tfvars.json / *.auto.tfvars.json (R14 finding 1):
			// hclsyntax.ParseConfig cannot parse JSON syntax at all, so
			// these must go through the dedicated JSON variant parser.
			hf, diags := hcljson.Parse(f.Content, f.Path)
			if diags.HasErrors() || hf == nil {
				gaps = append(gaps, ci.Gap{
					Code:       "iac.unsupported_tfvars_value",
					Scope:      "variables",
					Message:    fmt.Sprintf("tfvars file %q is not valid JSON: %s", f.Path, diags.Error()),
					References: []ci.Reference{rn.refFor(root, f, hcl.Range{Filename: f.Path}, "variables")},
				})
				continue
			}
			body = hf.Body
		} else {
			hf, diags := hclsyntax.ParseConfig(f.Content, f.Path, hcl.InitialPos)
			if diags.HasErrors() || hf == nil {
				continue
			}
			body = hf.Body
		}
		attrs, adiags := body.JustAttributes()
		if adiags.HasErrors() {
			continue
		}
		names := make([]string, 0, len(attrs))
		for n := range attrs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			attr := attrs[n]
			v, vdiags := attr.Expr.Value(nil)
			if vdiags.HasErrors() || !v.IsWhollyKnown() {
				gaps = append(gaps, ci.Gap{
					Code:       "iac.unsupported_tfvars_value",
					Scope:      "variables",
					Message:    fmt.Sprintf("tfvars value for %q is not a static literal", n),
					References: []ci.Reference{rn.refFor(root, f, attr.Expr.Range(), "variables")},
				})
				continue
			}
			out[n] = v
		}
	}

	for k, v := range explicit {
		cv, err := anyToCty(v)
		if err != nil {
			gaps = append(gaps, ci.Gap{
				Code:    "iac.unsupported_variable_value",
				Scope:   "variables",
				Message: fmt.Sprintf("TerraformInput.Variables[%q]: %s", k, err.Error()),
			})
			continue
		}
		out[k] = cv
	}
	return out, gaps
}

// resolveLocals/processModuleBlocks were superseded by the unified
// dependency-ordered resolver in symbols.go (resolveValueSymbols), which
// handles locals, module calls, and data/computed-identity symbols
// referencing each other in either direction.

// buildInstanceIndex assembles the per-type/label value exposed on the
// EvalContext for implicit resource references (aws_iam_role.foo.arn,
// aws_iam_role.foo[0].arn, aws_iam_role.foo["k"].arn), matching Terraform's
// own addressing for count/for_each/singleton resources.
func (rn *run) buildInstanceIndex(instances []instanceExpansion, f func(instanceExpansion) cty.Value) cty.Value {
	if len(instances) == 1 && instances[0].addrSuffix == "" {
		return f(instances[0])
	}
	keyed := map[string]cty.Value{}
	var tuple []cty.Value
	isKeyed := false
	for _, inst := range instances {
		v := f(inst)
		suffix := inst.addrSuffix
		if strings.HasPrefix(suffix, `["`) {
			isKeyed = true
			key := strings.TrimSuffix(strings.TrimPrefix(suffix, `["`), `"]`)
			keyed[key] = v
		} else {
			tuple = append(tuple, v)
		}
	}
	if isKeyed {
		return cty.ObjectVal(keyed)
	}
	if len(tuple) == 0 {
		return cty.EmptyTupleVal
	}
	return cty.TupleVal(tuple)
}

func mapOfObjectVals(m map[string]map[string]cty.Value) map[string]cty.Value {
	out := make(map[string]cty.Value, len(m))
	for k, inner := range m {
		out[k] = cty.ObjectVal(inner)
	}
	return out
}

// resolveOneModuleCall is reused by symbols.go's unified resolver (it
// resolves one module call -- local or pinned public -- once its
// dependencies are known); processModuleBlocks itself was removed, see the
// comment above resolveLocals.

func (rn *run) resolveOneModuleCall(tb taggedBlock, inst instanceExpansion, mf moduleFiles, depth int, scope string) cty.Value {
	srcAttr, hasSrc := tb.block.Body.Attributes["source"]
	if !hasSrc {
		rn.addGap(ci.Gap{
			Code:       "iac.module_missing_source",
			Scope:      scope,
			Message:    "module block has no source attribute",
			References: []ci.Reference{rn.refFor(mf, tb.file, tb.block.DefRange(), scope)},
		})
		return cty.EmptyObjectVal
	}
	srcVal, diags := srcAttr.Expr.Value(nil) // module source must be a literal constant
	if diags.HasErrors() || srcVal.Type() != cty.String || !srcVal.IsWhollyKnown() {
		rn.addGap(ci.Gap{
			Code:       "iac.module_source_not_literal",
			Scope:      scope,
			Message:    "module source is not a static string literal",
			References: []ci.Reference{rn.refFor(mf, tb.file, srcAttr.Expr.Range(), scope)},
		})
		return cty.EmptyObjectVal
	}
	source := srcVal.AsString()

	version := ""
	if vAttr, ok := tb.block.Body.Attributes["version"]; ok {
		vv, vdiags := vAttr.Expr.Value(nil)
		if !vdiags.HasErrors() && vv.Type() == cty.String && vv.IsWhollyKnown() {
			version = vv.AsString()
		} else {
			rn.addGap(ci.Gap{
				Code:       "iac.unsupported_expression",
				Scope:      scope,
				Message:    "module version is not a static string literal",
				References: []ci.Reference{rn.refFor(mf, tb.file, vAttr.Expr.Range(), scope)},
			})
		}
	}

	reserved := map[string]bool{"source": true, "version": true, "providers": true, "count": true, "for_each": true, "depends_on": true}
	// R14 finding 3: an explicit `providers = {...}` mapping on this
	// module call means the child's "default" provider can no longer be
	// assumed to be the root's own default provider, so childGoogleProjectAmbiguous
	// propagates down to every descendant module scope too.
	_, hasProvidersMap := tb.block.Body.Attributes["providers"]
	childGoogleProjectAmbiguous := mf.googleProjectAmbiguous || hasProvidersMap
	// Argument expressions are captured unevaluated here and resolved
	// lazily inside the child module's own var namespace (valueSymbols.
	// resolveVar), only when the child actually references the matching
	// var.<name> from an identity/trust/grant/boundary-reachable
	// expression (finding 8): an unused argument referencing unsupported
	// data (e.g. data.sops_file) must never be evaluated at all.
	overrides := map[string]moduleOverride{}
	for _, n := range sortedAttrNames(tb.block.Body.Attributes) {
		if reserved[n] {
			continue
		}
		attr := tb.block.Body.Attributes[n]
		overrides[n] = moduleOverride{expr: attr.Expr, ctx: inst.ctx, mf: mf, file: tb.file, scope: scope}
	}

	var child moduleFiles
	if isLocalModuleSource(source) {
		dir := path.Clean(path.Join(mf.dir, source))
		if dir == "." {
			dir = ""
		}
		child = moduleFiles{pin: mf.pin, dir: dir, addr: scope + inst.addrSuffix, files: filesUnderDir(mf.index, dir), index: mf.index, googleProjectAmbiguous: childGoogleProjectAmbiguous}
		if len(child.files) == 0 {
			rn.addGap(ci.Gap{
				Code:       "iac.module_not_found",
				Scope:      scope,
				Message:    fmt.Sprintf("local module source %q resolved to %q with no .tf files", source, dir),
				References: []ci.Reference{rn.refFor(mf, tb.file, srcAttr.Expr.Range(), scope)},
			})
			return cty.EmptyObjectVal
		}
	} else {
		if rn.modules == nil {
			rn.addGap(ci.Gap{
				Code:       "iac.module_reader_unavailable",
				Scope:      scope,
				Message:    fmt.Sprintf("no ModuleReader configured to resolve public module source %q", source),
				References: []ci.Reference{rn.refFor(mf, tb.file, srcAttr.Expr.Range(), scope)},
			})
			return cty.EmptyObjectVal
		}
		repo, err := rn.modules.ReadModule(rn.ctx, source, version)
		if err != nil {
			rn.addGap(ci.Gap{
				Code:       "iac.module_read_error",
				Scope:      scope,
				Message:    fmt.Sprintf("reading module %q@%q: %s", source, version, err.Error()),
				References: []ci.Reference{rn.refFor(mf, tb.file, srcAttr.Expr.Range(), scope)},
			})
			return cty.EmptyObjectVal
		}
		rn.gaps = append(rn.gaps, repo.Gaps...)
		if !repo.Pin.Exact {
			rn.addGap(ci.Gap{
				Code:       "iac.unpinned_module_source",
				Scope:      scope,
				Message:    fmt.Sprintf("module %q is not pinned to an immutable revision", source),
				References: []ci.Reference{rn.refFor(mf, tb.file, srcAttr.Expr.Range(), scope)},
			})
		}
		// The materialized repository keeps repo-relative file paths; the
		// module's own content lives under repo.Pin.Root (empty for a
		// repository root module, or the requested "//subdir" otherwise).
		// Evaluating from dir "" unconditionally (as if every remote module
		// were fetched at its repository root) would miss every file for a
		// "//subdir"-pinned module. The full remote index is carried on
		// child.index so a local child module reached from inside this
		// remote module (e.g. "./submodules/role") resolves against this
		// same remote repository, never the primary stack materialization.
		remoteIndex := indexFiles(repo.Files)
		dir := normalizeDir(repo.Pin.Root)
		child = moduleFiles{pin: repo.Pin, dir: dir, addr: scope + inst.addrSuffix, files: filesUnderDir(remoteIndex, dir), index: remoteIndex, googleProjectAmbiguous: childGoogleProjectAmbiguous}
		if len(child.files) == 0 {
			rn.addGap(ci.Gap{
				Code:    "iac.module_not_found",
				Scope:   scope,
				Message: fmt.Sprintf("module %q@%q returned no .tf files at %q", source, version, dir),
			})
			return cty.EmptyObjectVal
		}
	}

	key := child.pin.Repository + "@" + child.pin.Revision + ":" + child.dir
	if rn.moduleStack[key] {
		rn.addGap(ci.Gap{Code: "iac.module_cycle", Scope: scope, Message: fmt.Sprintf("module call %q participates in a containment cycle", source)})
		return cty.EmptyObjectVal
	}
	if depth+1 >= maxModuleDepth {
		rn.addGap(ci.Gap{Code: "iac.module_depth_exceeded", Scope: scope, Message: "maximum module nesting depth exceeded"})
		return cty.EmptyObjectVal
	}
	rn.moduleStack[key] = true
	out := rn.processModule(child, overrides, depth+1)
	delete(rn.moduleStack, key)
	return out
}

func (rn *run) resolveOutputs(pm parsedModule, ctx *hcl.EvalContext, mf moduleFiles) cty.Value {
	out := map[string]cty.Value{}
	for _, tb := range pm.outputs {
		if len(tb.block.Labels) == 0 {
			continue
		}
		name := tb.block.Labels[0]
		attr, ok := tb.block.Body.Attributes["value"]
		if !ok {
			continue
		}
		v, resolved := rn.eval(attr.Expr, ctx, mf, tb.file, mf.addr+".output."+name)
		if !resolved {
			out[name] = cty.DynamicVal
			continue
		}
		out[name] = v
	}
	if len(out) == 0 {
		return cty.EmptyObjectVal
	}
	return cty.ObjectVal(out)
}

// processModule fully resolves one module directory: variables, locals,
// child modules (recursively, bottom-up so their outputs are ready),
// aws_iam_policy_document data sources, declared identity resources, trust
// and permission-boundary attachments on those identities, and every other
// grant-producing resource (inline policies, attachments, group membership,
// GCP IAM bindings). It returns the module's own `output` values for the
// parent module call to consume as module.<label> -- except for the root
// module (depth 0), whose outputs are never consumed by anything in this
// analysis (there is no parent module call to read them back), so they are
// never evaluated at all (finding 8): a discarded root output referencing
// unsupported data must never gap.
func (rn *run) processModule(mf moduleFiles, overrides map[string]moduleOverride, depth int) cty.Value {
	pm, diags := parseModuleFiles(mf, rn)
	for _, d := range diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		ref := ci.Reference{Repository: mf.pin.Repository, Revision: mf.pin.Revision, Scope: mf.addr}
		if d.Subject != nil {
			ref.Path = d.Subject.Filename
			ref.StartLine = d.Subject.Start.Line
			ref.EndLine = d.Subject.End.Line
			if f, ok := mf.files[d.Subject.Filename]; ok {
				ref.Digest = f.Digest
			}
		}
		rn.addGap(ci.Gap{Code: "iac.parse_error", Scope: mf.addr, Message: d.Error(), References: []ci.Reference{ref}})
	}

	ctx := baseEvalContext()
	rn.resolveValueSymbols(pm, ctx, mf, depth, overrides)
	rn.passTrustAndBoundary(pm, ctx, mf)
	rn.passGrants(pm, ctx, mf)
	if pm.hasUnsupportedJSON {
		rn.markModuleScopeIncomplete(mf)
	}
	if depth == 0 {
		return cty.EmptyObjectVal
	}
	return rn.resolveOutputs(pm, ctx, mf)
}

// addDiagGaps converts every error diagnostic from a PartialContent/dynblock
// expansion call into a scoped iac gap, never silently discarded: a block or
// attribute that failed to expand must not quietly look like it was simply
// never declared, since that would understate a trust/condition/permission
// the declaration actually carries (a dynamic "condition"/"principals" block
// that fails to expand must not silently produce a broader, unconditioned
// grant than what is actually written).
func (rn *run) addDiagGaps(diags hcl.Diagnostics, mf moduleFiles, file *ci.SourceFile, scope string) {
	for _, d := range diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		ref := ci.Reference{Scope: scope}
		if mf.pin.Repository != "" {
			ref.Repository = mf.pin.Repository
			ref.Revision = mf.pin.Revision
		}
		if d.Subject != nil && file != nil {
			ref.Path = file.Path
			ref.StartLine = d.Subject.Start.Line
			ref.EndLine = d.Subject.End.Line
			ref.Digest = file.Digest
		} else if file != nil {
			ref.Path = file.Path
			ref.Digest = file.Digest
		}
		rn.addGap(ci.Gap{
			Code:       "iac.block_expansion_error",
			Scope:      scope,
			Message:    fmt.Sprintf("%s: %s", d.Summary, d.Detail),
			References: []ci.Reference{ref},
		})
	}
}

// expandBlocks applies dynamic-block expansion to body (which may itself be
// the result of a previous expansion step) and returns the direct children
// of the given block type, letting callers read nested, possibly-dynamic
// repeatable blocks (statement/condition/principals/...) uniformly. Any
// expansion error is a scoped gap (see addDiagGaps), never discarded.
func (rn *run) expandBlocks(mf moduleFiles, file *ci.SourceFile, scope string, body hcl.Body, ctx *hcl.EvalContext, blockType string) []*hcl.Block {
	wrapped := dynblock.Expand(body, ctx)
	content, _, diags := wrapped.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{{Type: blockType}},
	})
	rn.addDiagGaps(diags, mf, file, scope)
	return content.Blocks
}

// bodyAttr reads a single optional attribute out of body via PartialContent,
// tolerant of any other attributes/blocks also present. Any diagnostic error
// is a scoped gap (see addDiagGaps), never discarded.
func (rn *run) bodyAttr(mf moduleFiles, file *ci.SourceFile, scope string, body hcl.Body, name string) (hcl.Expression, bool) {
	content, _, diags := body.PartialContent(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{{Name: name}},
	})
	rn.addDiagGaps(diags, mf, file, scope)
	attr, ok := content.Attributes[name]
	if !ok {
		return nil, false
	}
	return attr.Expr, true
}

// bodyAttrs reads several optional attributes out of body in one
// PartialContent call, for the small number of nested blocks (condition,
// principals, inline_policy) whose extraction needs more than one attribute
// at once. Any diagnostic error is a scoped gap (see addDiagGaps).
func (rn *run) bodyAttrs(mf moduleFiles, file *ci.SourceFile, scope string, body hcl.Body, names ...string) map[string]*hcl.Attribute {
	schema := &hcl.BodySchema{Attributes: make([]hcl.AttributeSchema, len(names))}
	for i, n := range names {
		schema.Attributes[i] = hcl.AttributeSchema{Name: n}
	}
	content, _, diags := body.PartialContent(schema)
	rn.addDiagGaps(diags, mf, file, scope)
	return content.Attributes
}
