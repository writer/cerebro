package iac

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/ext/dynblock"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// dataDocKinds/computedValueKinds name the data-source and resource kinds
// this resolver treats as ctx-populating "value" symbols that a local, a
// module call's input, or one of these symbols itself may depend on in
// either direction (a local reading a computed EKS OIDC issuer; a module
// argument reading a local; a local reading a module output; a dynamic
// block's for_each reading a local; a module argument reading a declared
// identity's own arn/name/email, e.g. module input `policies =
// [aws_iam_policy.foo.arn]` -- all real patterns, not just one fixture's
// shape). computedValueKinds also names every declared-identity resource
// kind (aws_iam_role/user/group/policy, google_service_account, GCP custom
// roles): their name/arn/email-shaped value participates in this same
// dependency graph (finding 6) so a module call evaluated here can already
// see it, while the grant-producing resource types (inline/attached
// policies, group membership, IAM member/binding resources) remain NOT part
// of this graph: they are strictly consumers of these values via
// passTrustAndBoundary/passGrants, which always run after this resolver
// settles.
var dataDocKinds = map[string]bool{
	"aws_iam_policy_document": true, "aws_eks_cluster": true,
	"aws_caller_identity": true, "google_project": true, "aws_region": true,
	"terraform_remote_state": true,
}

var computedValueKinds = map[string]bool{
	"aws_eks_cluster": true, "aws_iam_openid_connect_provider": true,
	"google_iam_workload_identity_pool": true, "google_iam_workload_identity_pool_provider": true,
	"aws_iam_role": true, "aws_iam_user": true, "aws_iam_group": true, "aws_iam_policy": true,
	"google_service_account": true, "google_project_iam_custom_role": true, "google_organization_iam_custom_role": true,
}

// collectVariables walks body and every nested block recursively (including
// inside "dynamic" blocks' own for_each/labels and their "content" blocks),
// returning every variable traversal referenced anywhere inside. This gives
// a symbol's complete dependency set before anything is evaluated, so
// locals/data sources/computed resources with references buried inside
// nested statement/condition/dynamic blocks are still ordered correctly.
func collectVariables(body *hclsyntax.Body) []hcl.Traversal {
	var out []hcl.Traversal
	for _, attr := range body.Attributes {
		out = append(out, attr.Expr.Variables()...)
	}
	for _, blk := range body.Blocks {
		out = append(out, collectVariables(blk.Body)...)
	}
	return out
}

type taggedExpr struct {
	expr hcl.Expression
	file *ci.SourceFile
}

type kindLabel struct{ kind, label string }

// moduleOverride carries one Terraform input variable's override for a
// module scope: either a value already resolved to a literal cty.Value
// (TerraformInput.Variables / an auto-loaded tfvars file for the root
// module -- pure literals that can never themselves gap further), or an
// unevaluated HCL expression from a parent module call's own argument,
// together with the exact parent scope (ctx/mf/file/scope) it must be
// evaluated against. The expression form is resolved lazily (see
// valueSymbols.resolveVar): it is only ever evaluated when something
// inside the child module actually references var.<name> from an
// identity/trust/grant/boundary-reachable expression (finding 8), so an
// unused module argument referencing unsupported data (e.g.
// data.sops_file) is never touched and never gaps.
type moduleOverride struct {
	literal   cty.Value
	isLiteral bool
	expr      hcl.Expression
	ctx       *hcl.EvalContext
	mf        moduleFiles
	file      *ci.SourceFile
	scope     string
}

// literalOverrides wraps a map of already-resolved values (root module
// tfvars/explicit TerraformInput.Variables) as moduleOverride entries.
func literalOverrides(vars map[string]cty.Value) map[string]moduleOverride {
	out := make(map[string]moduleOverride, len(vars))
	for k, v := range vars {
		out[k] = moduleOverride{literal: v, isLiteral: true}
	}
	return out
}

// valueSymbols resolves locals, module calls, aws_iam_policy_document/
// aws_eks_cluster data sources, and the computed-identity resources
// (aws_eks_cluster, aws_iam_openid_connect_provider, GCP workload identity
// pool/provider) as one dependency graph instead of a rigid phase order.
// Resolution is lazy, recursive, and memoized per symbol: evaluating a
// symbol first resolves every other symbol its definition references
// (anywhere in its body, not just a top-level attribute), regardless of
// which of these four categories that dependency belongs to. A true
// dependency cycle is never fabricated or infinitely retried: the symbol
// still "visiting" simply is not yet in ctx when the cycle closes, so the
// expression that needed it surfaces the existing unresolved-expression gap
// exactly as any other unresolvable reference does.
type valueSymbols struct {
	rn    *run
	ctx   *hcl.EvalContext
	mf    moduleFiles
	depth int

	locals   map[string]taggedExpr
	modules  map[string]taggedBlock
	data     map[kindLabel]taggedBlock
	computed map[kindLabel]taggedBlock

	// overrides holds this module scope's own `var.<name>` values -- the
	// child module case carries an unevaluated parent-scope expression
	// (see moduleOverride), resolved lazily by resolveVar only when
	// var.<name> is actually reachable (finding 8).
	overrides map[string]moduleOverride

	localResolved    map[string]cty.Value
	moduleResolved   map[string]cty.Value
	dataResolved     map[string]map[string]cty.Value
	computedResolved map[string]map[string]cty.Value
	varResolved      map[string]cty.Value

	localDone, localVisiting       map[string]bool
	moduleDone, moduleVisiting     map[string]bool
	dataDone, dataVisiting         map[kindLabel]bool
	computedDone, computedVisiting map[kindLabel]bool
	varDone, varVisiting           map[string]bool
}

// resolveValueSymbols builds and resolves the full symbol graph for one
// module scope and installs ctx.Variables["local"/"module"/"data"/<computed
// kind>/"var"] from the result. overrides carries this scope's own
// `var.<name>` values (see moduleOverride); `variable { default = ... }`
// literals discovered in pm seed the same var namespace eagerly (pure
// literals, never a gap risk), while an override's own expression resolves
// lazily through the same dependency graph as locals/modules/data/computed
// (finding 8).
func (rn *run) resolveValueSymbols(pm parsedModule, ctx *hcl.EvalContext, mf moduleFiles, depth int, overrides map[string]moduleOverride) {
	vs := &valueSymbols{
		rn: rn, ctx: ctx, mf: mf, depth: depth,
		locals:           map[string]taggedExpr{},
		modules:          map[string]taggedBlock{},
		data:             map[kindLabel]taggedBlock{},
		computed:         map[kindLabel]taggedBlock{},
		overrides:        overrides,
		localResolved:    map[string]cty.Value{},
		moduleResolved:   map[string]cty.Value{},
		dataResolved:     map[string]map[string]cty.Value{},
		computedResolved: map[string]map[string]cty.Value{},
		varResolved:      map[string]cty.Value{},
		localDone:        map[string]bool{}, localVisiting: map[string]bool{},
		moduleDone: map[string]bool{}, moduleVisiting: map[string]bool{},
		dataDone: map[kindLabel]bool{}, dataVisiting: map[kindLabel]bool{},
		computedDone: map[kindLabel]bool{}, computedVisiting: map[kindLabel]bool{},
		varDone: map[string]bool{}, varVisiting: map[string]bool{},
	}

	// `variable { default = ... }` literals are pure constant expressions
	// (HCL/Terraform forbid anything else), so seeding them eagerly carries
	// no gap risk; only an override's own expression (see moduleOverride)
	// is deferred to resolveVar.
	for _, tb := range pm.variables {
		if len(tb.block.Labels) == 0 {
			continue
		}
		name := tb.block.Labels[0]
		attr, ok := tb.block.Body.Attributes["default"]
		if !ok {
			continue
		}
		v, diags := attr.Expr.Value(nil)
		if !diags.HasErrors() && v.IsWhollyKnown() {
			vs.varResolved[name] = v
		}
	}
	if len(vs.varResolved) > 0 {
		ctx.Variables["var"] = cty.ObjectVal(vs.varResolved)
	}

	for _, tb := range pm.locals {
		for _, n := range sortedAttrNames(tb.block.Body.Attributes) {
			attr := tb.block.Body.Attributes[n]
			if _, exists := vs.locals[n]; exists {
				rn.addGap(ci.Gap{
					Code: "iac.duplicate_local", Scope: mf.addr,
					Message:    fmt.Sprintf("local %q is defined more than once", n),
					References: []ci.Reference{rn.refFor(mf, tb.file, attr.Expr.Range(), mf.addr)},
				})
			}
			vs.locals[n] = taggedExpr{expr: attr.Expr, file: tb.file}
		}
	}
	for _, tb := range pm.modules {
		if len(tb.block.Labels) == 0 {
			continue
		}
		vs.modules[tb.block.Labels[0]] = tb
	}
	for _, tb := range pm.data {
		if len(tb.block.Labels) < 2 {
			continue
		}
		kind, label := tb.block.Labels[0], tb.block.Labels[1]
		if !dataDocKinds[kind] {
			continue
		}
		vs.data[kindLabel{kind, label}] = tb
	}
	for _, tb := range pm.resources {
		if len(tb.block.Labels) < 2 {
			continue
		}
		kind, label := tb.block.Labels[0], tb.block.Labels[1]
		if !computedValueKinds[kind] {
			continue
		}
		vs.computed[kindLabel{kind, label}] = tb
	}

	// Locals are resolved lazily and memoized (see resolveLocal), never
	// eagerly here: an unrelated local that is never reachable from any
	// identity/trust/grant/module-input/requested-output expression must
	// never surface a gap (finding 8). Modules/data/computed below remain
	// eagerly visited (they are themselves declarations or narrowly
	// supported data kinds, not incidental bookkeeping), and each pulls in
	// whatever locals it actually references via visitDeps; the seed loop
	// after them covers the remaining reachable-but-not-yet-visited
	// categories (grant-producing resources, requested outputs).

	moduleLabels := make([]string, 0, len(vs.modules))
	for l := range vs.modules {
		moduleLabels = append(moduleLabels, l)
	}
	sort.Strings(moduleLabels)
	for _, l := range moduleLabels {
		vs.resolveModule(l)
	}

	dataKeys := make([]kindLabel, 0, len(vs.data))
	for k := range vs.data {
		dataKeys = append(dataKeys, k)
	}
	sort.Slice(dataKeys, func(i, j int) bool {
		if dataKeys[i].kind != dataKeys[j].kind {
			return dataKeys[i].kind < dataKeys[j].kind
		}
		return dataKeys[i].label < dataKeys[j].label
	})
	for _, k := range dataKeys {
		vs.resolveDataBlock(k.kind, k.label)
	}

	// R14 finding 3: the default (non-aliased) `provider "google" {...}`
	// block's own `project`, if set and resolvable, must be ready before
	// any google_* computed identity in this scope is processed below.
	vs.resolveDefaultGoogleProviderProject(pm)

	computedKeys := make([]kindLabel, 0, len(vs.computed))
	for k := range vs.computed {
		computedKeys = append(computedKeys, k)
	}
	sort.Slice(computedKeys, func(i, j int) bool {
		if computedKeys[i].kind != computedKeys[j].kind {
			return computedKeys[i].kind < computedKeys[j].kind
		}
		return computedKeys[i].label < computedKeys[j].label
	})
	for _, k := range computedKeys {
		vs.resolveComputedBlock(k.kind, k.label)
	}
	// Seed locals reachable only from grant-producing resources (inline/
	// attached policies, group membership, IAM member/binding resources --
	// none of which are part of the computed/data graph above, since they
	// are consumers, not value symbols) and from requested module outputs,
	// so a local referenced solely from one of those still resolves.
	for _, tb := range pm.resources {
		if len(tb.block.Labels) < 1 {
			continue
		}
		kind := tb.block.Labels[0]
		if !grantProducingKinds[kind] && !gcpResourceLevelKinds[kind] && !gcpIAMMemberBindingPolicyPattern.MatchString(kind) {
			continue
		}
		vs.visitDeps(collectVariables(tb.block.Body))
	}
	for _, tb := range pm.outputs {
		vs.visitDeps(collectVariables(tb.block.Body))
	}

	ctx.Variables["local"] = cty.ObjectVal(vs.localResolved)
	if len(vs.moduleResolved) > 0 {
		ctx.Variables["module"] = cty.ObjectVal(vs.moduleResolved)
	}
	vs.flushData()
	for kind := range vs.computedResolved {
		vs.flushComputed(kind)
	}
}

// visitDeps recursively resolves every local/module/data/computed symbol
// referenced by traversals, before the caller evaluates its own definition.
func (vs *valueSymbols) visitDeps(traversals []hcl.Traversal) {
	for _, tr := range traversals {
		root := tr.RootName()
		switch {
		case root == "var":
			if len(tr) > 1 {
				if a, ok := tr[1].(hcl.TraverseAttr); ok {
					vs.resolveVar(a.Name)
				}
			}
		case root == "local":
			if len(tr) > 1 {
				if a, ok := tr[1].(hcl.TraverseAttr); ok {
					vs.resolveLocal(a.Name)
				}
			}
		case root == "module":
			if len(tr) > 1 {
				if a, ok := tr[1].(hcl.TraverseAttr); ok {
					vs.resolveModule(a.Name)
				}
			}
		case root == "data":
			if len(tr) > 2 {
				typeStep, ok1 := tr[1].(hcl.TraverseAttr)
				labelStep, ok2 := tr[2].(hcl.TraverseAttr)
				if ok1 && ok2 && dataDocKinds[typeStep.Name] {
					vs.resolveDataBlock(typeStep.Name, labelStep.Name)
				}
			}
		case computedValueKinds[root]:
			if len(tr) > 1 {
				if a, ok := tr[1].(hcl.TraverseAttr); ok {
					vs.resolveComputedBlock(root, a.Name)
				}
			}
		}
	}
}

func (vs *valueSymbols) resolveLocal(name string) {
	if vs.localDone[name] || vs.localVisiting[name] {
		return
	}
	def, ok := vs.locals[name]
	if !ok {
		return
	}
	vs.localVisiting[name] = true
	vs.visitDeps(def.expr.Variables())
	vs.localVisiting[name] = false

	vs.ctx.Variables["local"] = cty.ObjectVal(vs.localResolved)
	v, ok2 := vs.rn.eval(def.expr, vs.ctx, vs.mf, def.file, vs.mf.addr+".local."+name)
	if ok2 {
		vs.localResolved[name] = v
	} else {
		vs.localResolved[name] = cty.DynamicVal
	}
	vs.localDone[name] = true
}

// resolveVar resolves one var.<name> reference. `variable { default }`
// literals were already seeded eagerly into vs.varResolved (no gap risk);
// this only ever evaluates the module-call-argument override form, and
// only when var.<name> is itself reachable from an identity/trust/grant/
// boundary-relevant expression (finding 8) -- an unused override's
// expression (e.g. one referencing unsupported data such as
// data.sops_file) is never touched. An override that fails to resolve
// falls back to the variable's own default (already in vs.varResolved),
// exactly as Terraform would if the argument were simply omitted; it is
// never fabricated as a DynamicVal placeholder.
func (vs *valueSymbols) resolveVar(name string) {
	if vs.varDone[name] || vs.varVisiting[name] {
		return
	}
	vs.varVisiting[name] = true
	if ov, ok := vs.overrides[name]; ok {
		if ov.isLiteral {
			vs.varResolved[name] = ov.literal
		} else if v, resolved := vs.rn.eval(ov.expr, ov.ctx, ov.mf, ov.file, ov.scope); resolved {
			vs.varResolved[name] = v
		}
	}
	vs.varVisiting[name] = false
	if len(vs.varResolved) > 0 {
		vs.ctx.Variables["var"] = cty.ObjectVal(vs.varResolved)
	}
	vs.varDone[name] = true
}

func (vs *valueSymbols) resolveModule(label string) {
	if vs.moduleDone[label] || vs.moduleVisiting[label] {
		return
	}
	tb, ok := vs.modules[label]
	if !ok {
		return
	}
	vs.moduleVisiting[label] = true
	vs.visitDeps(collectVariables(tb.block.Body))
	vs.moduleVisiting[label] = false

	if len(vs.moduleResolved) > 0 {
		vs.ctx.Variables["module"] = cty.ObjectVal(vs.moduleResolved)
	}
	scope := vs.mf.addr + ".module." + label
	instances := vs.rn.expandInstances(tb.block, vs.ctx, vs.mf, tb.file, scope)
	out := vs.rn.buildInstanceIndex(instances, func(inst instanceExpansion) cty.Value {
		return vs.rn.resolveOneModuleCall(tb, inst, vs.mf, vs.depth, scope)
	})
	vs.moduleResolved[label] = out
	vs.ctx.Variables["module"] = cty.ObjectVal(vs.moduleResolved)
	vs.moduleDone[label] = true
}

func (vs *valueSymbols) resolveDataBlock(kind, label string) {
	key := kindLabel{kind, label}
	if vs.dataDone[key] || vs.dataVisiting[key] {
		return
	}
	tb, ok := vs.data[key]
	if !ok {
		return
	}
	vs.dataVisiting[key] = true
	vs.visitDeps(collectVariables(tb.block.Body))
	vs.dataVisiting[key] = false

	vs.flushData()
	scope := vs.mf.addr + ".data." + kind + "." + label
	instances := vs.rn.expandInstances(tb.block, vs.ctx, vs.mf, tb.file, scope)
	out := vs.rn.buildInstanceIndex(instances, func(inst instanceExpansion) cty.Value {
		wrapped := dynblock.Expand(tb.block.Body, inst.ctx)
		addr := scope + inst.addrSuffix
		switch kind {
		case "aws_eks_cluster":
			return vs.rn.eksClusterValue(addr, tb.block.DefRange(), wrapped, inst.ctx, vs.mf, tb.file)
		case "aws_caller_identity":
			return vs.rn.awsCallerIdentityValue(addr, tb.block.DefRange(), vs.mf, tb.file)
		case "aws_region":
			return vs.rn.awsRegionValue(addr, tb.block.DefRange(), vs.mf, tb.file)
		case "google_project":
			return vs.rn.googleProjectValue(addr, tb.block.DefRange(), wrapped, inst.ctx, vs.mf, tb.file)
		case "terraform_remote_state":
			return vs.rn.terraformRemoteStateValue(addr, tb.block.DefRange(), label, vs.mf, tb.file)
		}
		return vs.rn.awsPolicyDocumentValue(addr, tb.block.DefRange(), wrapped, inst.ctx, vs.mf, tb.file)
	})
	if vs.dataResolved[kind] == nil {
		vs.dataResolved[kind] = map[string]cty.Value{}
	}
	vs.dataResolved[kind][label] = out
	vs.flushData()
	vs.dataDone[key] = true
}

func (vs *valueSymbols) flushData() {
	if len(vs.dataResolved) > 0 {
		vs.ctx.Variables["data"] = cty.ObjectVal(mapOfObjectVals(vs.dataResolved))
	}
}

// resolveDefaultGoogleProviderProject resolves vs.mf's own (non-aliased)
// `provider "google" { project = ... }` value, if present and resolvable
// (R14 finding 3): google resources with no `project` attribute of their
// own, and no `provider = google.<alias>` meta-argument, fall back to this
// before TerraformInput.Project (see resolveGoogleProject in gcp.go).
// Skipped entirely when this module scope is already provider-ambiguous
// (vs.mf.googleProjectAmbiguous): an aliased/ambiguous provider situation
// never consults the default provider block at all.
func (vs *valueSymbols) resolveDefaultGoogleProviderProject(pm parsedModule) {
	if vs.mf.googleProjectAmbiguous {
		return
	}
	for _, tb := range pm.providers {
		if len(tb.block.Labels) == 0 || tb.block.Labels[0] != "google" {
			continue
		}
		if _, hasAlias := tb.block.Body.Attributes["alias"]; hasAlias {
			continue
		}
		attr, ok := tb.block.Body.Attributes["project"]
		if !ok {
			return
		}
		vs.visitDeps(attr.Expr.Variables())
		v, resolved := vs.rn.evalString(attr.Expr, vs.ctx, vs.mf, tb.file, vs.mf.addr+".provider.google")
		if resolved {
			vs.mf.defaultGoogleProject = v
		}
		return
	}
}

func (vs *valueSymbols) resolveComputedBlock(kind, label string) {
	key := kindLabel{kind, label}
	if vs.computedDone[key] || vs.computedVisiting[key] {
		return
	}
	tb, ok := vs.computed[key]
	if !ok {
		return
	}
	vs.computedVisiting[key] = true
	vs.visitDeps(collectVariables(tb.block.Body))
	vs.computedVisiting[key] = false

	vs.flushComputed(kind)
	scope := vs.mf.addr + "." + kind + "." + label
	instances := vs.rn.expandInstances(tb.block, vs.ctx, vs.mf, tb.file, scope)
	out := vs.rn.buildInstanceIndex(instances, func(inst instanceExpansion) cty.Value {
		wrapped := dynblock.Expand(tb.block.Body, inst.ctx)
		addr := scope + inst.addrSuffix
		return vs.rn.computedIdentityValue(kind, addr, tb.block.DefRange(), wrapped, inst.ctx, vs.mf, tb.file, inst.partial)
	})
	if vs.computedResolved[kind] == nil {
		vs.computedResolved[kind] = map[string]cty.Value{}
	}
	vs.computedResolved[kind][label] = out
	vs.flushComputed(kind)
	vs.computedDone[key] = true
}

func (vs *valueSymbols) flushComputed(kind string) {
	if labels, ok := vs.computedResolved[kind]; ok {
		vs.ctx.Variables[kind] = cty.ObjectVal(labels)
	}
}
