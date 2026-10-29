package iac

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// baseEvalContext returns a fresh root *hcl.EvalContext carrying only the
// deterministic, pure function table. Variable namespaces (var/local/module/
// data/resource types) are layered on by the caller.
func baseEvalContext() *hcl.EvalContext {
	return &hcl.EvalContext{
		Variables: map[string]cty.Value{},
		Functions: stdFunctions(),
	}
}

// refFor builds a citation for a diagnostic/fact rooted at rng within file.
func (rn *run) refFor(mf moduleFiles, file *ci.SourceFile, rng hcl.Range, scope string) ci.Reference {
	ref := ci.Reference{
		Path:      file.Path,
		StartLine: rng.Start.Line,
		EndLine:   rng.End.Line,
		Scope:     scope,
		Digest:    file.Digest,
	}
	if mf.pin.Repository != "" {
		ref.Repository = mf.pin.Repository
		ref.Revision = mf.pin.Revision
	}
	return ref
}

// exprText recovers the literal HCL source text for an expression, used to
// preserve an unresolved/computed reference verbatim instead of fabricating
// a value for it (e.g. an EKS OIDC issuer or GCP project number known only
// at apply/live time).
func exprText(file *ci.SourceFile, rng hcl.Range) string {
	if file == nil || rng.Start.Byte < 0 || rng.End.Byte > len(file.Content) || rng.Start.Byte > rng.End.Byte {
		return ""
	}
	return string(file.Content[rng.Start.Byte:rng.End.Byte])
}

// eval evaluates expr under ctx, treating any diagnostic or not-wholly-known
// result as unresolved: it records a scoped gap (preserving the literal
// source text, never a fabricated value) and returns ok=false. Callers that
// can still make partial progress with an unknown value should inspect the
// gap themselves; most should simply skip the fact being extracted.
func (rn *run) eval(expr hcl.Expression, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string) (cty.Value, bool) {
	v, diags := expr.Value(ctx)
	rng := expr.Range()
	if diags.HasErrors() {
		code := "iac.unresolved_expression"
		for _, d := range diags {
			if d.Severity == hcl.DiagError && d.Summary == "Call to unknown function" {
				code = "iac.unsupported_function"
				break
			}
		}
		rn.addGap(ci.Gap{
			Code:       code,
			Scope:      scope,
			Message:    fmt.Sprintf("could not statically evaluate %q: %s", exprText(file, rng), diags.Error()),
			References: []ci.Reference{rn.refFor(mf, file, rng, scope)},
		})
		return cty.NilVal, false
	}
	if !v.IsWhollyKnown() {
		rn.addGap(ci.Gap{
			Code:       "iac.unresolved_computed_value",
			Scope:      scope,
			Message:    fmt.Sprintf("expression %q depends on a computed/provider value not known until apply or live resolution", exprText(file, rng)),
			References: []ci.Reference{rn.refFor(mf, file, rng, scope)},
		})
		return cty.NilVal, false
	}
	return v, true
}

// evalString is a convenience wrapper for the very common case of an
// attribute that must resolve to a string.
func (rn *run) evalString(expr hcl.Expression, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string) (string, bool) {
	v, ok := rn.eval(expr, ctx, mf, file, scope)
	if !ok {
		return "", false
	}
	sv, err := convert.Convert(v, cty.String)
	if err != nil || sv.IsNull() {
		rn.addGap(ci.Gap{
			Code:       "iac.unsupported_expression",
			Scope:      scope,
			Message:    fmt.Sprintf("expected a string value from %q", exprText(file, expr.Range())),
			References: []ci.Reference{rn.refFor(mf, file, expr.Range(), scope)},
		})
		return "", false
	}
	return sv.AsString(), true
}

// evalStringList evaluates expr as a list/set/tuple of strings, skipping
// (with a gap) any element that is not statically a string.
func (rn *run) evalStringList(expr hcl.Expression, ctx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string) []string {
	v, ok := rn.eval(expr, ctx, mf, file, scope)
	if !ok || v.IsNull() || !v.CanIterateElements() {
		return nil
	}
	var out []string
	v.ForEachElement(func(_, ev cty.Value) bool {
		sv, err := convert.Convert(ev, cty.String)
		if err != nil || !sv.IsWhollyKnown() || sv.IsNull() {
			rn.addGap(ci.Gap{
				Code:       "iac.unsupported_expression",
				Scope:      scope,
				Message:    "list element did not statically resolve to a string",
				References: []ci.Reference{rn.refFor(mf, file, expr.Range(), scope)},
			})
			return false
		}
		out = append(out, sv.AsString())
		return false
	})
	return out
}

// instanceExpansion is one resolved count/for_each instance of a resource or
// module block.
type instanceExpansion struct {
	addrSuffix string
	ctx        *hcl.EvalContext
	partial    bool // true when the instance set itself could not be fully resolved
}

func withEach(base *hcl.EvalContext, key, value cty.Value) *hcl.EvalContext {
	child := base.NewChild()
	child.Variables = map[string]cty.Value{
		"each": cty.ObjectVal(map[string]cty.Value{"key": key, "value": value}),
	}
	return child
}

func withCount(base *hcl.EvalContext, index cty.Value) *hcl.EvalContext {
	child := base.NewChild()
	child.Variables = map[string]cty.Value{"count": cty.ObjectVal(map[string]cty.Value{"index": index})}
	return child
}

// expandInstances resolves the count/for_each meta-arguments of block (if
// present) against baseCtx and returns one instanceExpansion per instance. A
// block without count/for_each yields exactly one instance using baseCtx
// unmodified. An unresolvable for_each/count still yields one best-effort
// instance (marked partial) so that instance-independent facts are not lost.
func (rn *run) expandInstances(block *hclsyntax.Block, baseCtx *hcl.EvalContext, mf moduleFiles, file *ci.SourceFile, scope string) []instanceExpansion {
	if attr, ok := block.Body.Attributes["for_each"]; ok {
		v, resolved := rn.eval(attr.Expr, baseCtx, mf, file, scope)
		if !resolved || v.IsNull() || !v.CanIterateElements() {
			return []instanceExpansion{{addrSuffix: "[?]", ctx: withEach(baseCtx, cty.UnknownVal(cty.String), cty.DynamicVal), partial: true}}
		}
		type kv struct {
			k, v cty.Value
		}
		var pairs []kv
		v.ForEachElement(func(k, val cty.Value) bool {
			pairs = append(pairs, kv{k, val})
			return false
		})
		sort.Slice(pairs, func(i, j int) bool { return ctyKeyLabel(pairs[i].k) < ctyKeyLabel(pairs[j].k) })
		out := make([]instanceExpansion, 0, len(pairs))
		for i, p := range pairs {
			if i >= maxResourceCount {
				break
			}
			out = append(out, instanceExpansion{
				addrSuffix: fmt.Sprintf("[%q]", ctyKeyLabel(p.k)),
				ctx:        withEach(baseCtx, p.k, p.v),
			})
		}
		return out
	}
	if attr, ok := block.Body.Attributes["count"]; ok {
		v, resolved := rn.eval(attr.Expr, baseCtx, mf, file, scope)
		if !resolved {
			return []instanceExpansion{{addrSuffix: "[?]", ctx: withCount(baseCtx, cty.UnknownVal(cty.Number)), partial: true}}
		}
		nv, err := convert.Convert(v, cty.Number)
		if err != nil {
			return []instanceExpansion{{addrSuffix: "[?]", ctx: withCount(baseCtx, cty.UnknownVal(cty.Number)), partial: true}}
		}
		bf := nv.AsBigFloat()
		n64, _ := bf.Int64()
		if n64 <= 0 {
			return nil
		}
		if n64 > maxResourceCount {
			n64 = maxResourceCount
		}
		out := make([]instanceExpansion, 0, n64)
		for i := int64(0); i < n64; i++ {
			out = append(out, instanceExpansion{
				addrSuffix: fmt.Sprintf("[%d]", i),
				ctx:        withCount(baseCtx, cty.NumberIntVal(i)),
			})
		}
		return out
	}
	return []instanceExpansion{{ctx: baseCtx}}
}

func ctyKeyLabel(k cty.Value) string {
	if k.Type() == cty.String {
		return k.AsString()
	}
	sv, err := convert.Convert(k, cty.String)
	if err == nil && sv.IsWhollyKnown() {
		return sv.AsString()
	}
	return "?"
}

// anyToCty converts the loosely-typed JSON-ish values carried on
// ci.TerraformInput.Variables (and HCL-evaluated tfvars) into cty.Value.
func anyToCty(v any) (cty.Value, error) {
	switch t := v.(type) {
	case nil:
		return cty.NullVal(cty.DynamicPseudoType), nil
	case bool:
		return cty.BoolVal(t), nil
	case string:
		return cty.StringVal(t), nil
	case float64:
		return cty.NumberFloatVal(t), nil
	case int:
		return cty.NumberIntVal(int64(t)), nil
	case int64:
		return cty.NumberIntVal(t), nil
	case []any:
		if len(t) == 0 {
			return cty.EmptyTupleVal, nil
		}
		vals := make([]cty.Value, len(t))
		for i, e := range t {
			cv, err := anyToCty(e)
			if err != nil {
				return cty.NilVal, err
			}
			vals[i] = cv
		}
		return cty.TupleVal(vals), nil
	case map[string]any:
		if len(t) == 0 {
			return cty.EmptyObjectVal, nil
		}
		attrs := make(map[string]cty.Value, len(t))
		for k, e := range t {
			cv, err := anyToCty(e)
			if err != nil {
				return cty.NilVal, err
			}
			attrs[k] = cv
		}
		return cty.ObjectVal(attrs), nil
	default:
		return cty.NilVal, fmt.Errorf("unsupported variable value type %T", v)
	}
}
