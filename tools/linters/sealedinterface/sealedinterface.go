package sealedinterface

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const doc = `forbid implementing //cerebro:sealed interfaces outside their package

Sealed interfaces define extension boundaries: implementations must live beside
the interface they satisfy.`

const sealedMarker = "cerebro:sealed"

type sealedFact struct{}

func (*sealedFact) AFact() {}

var Analyzer = &analysis.Analyzer{
	Name:      "sealedinterface",
	Doc:       doc,
	FactTypes: []analysis.Fact{new(sealedFact)},
	Run:       run,
}

func run(pass *analysis.Pass) (any, error) {
	sealed := map[*types.TypeName]*types.Interface{}

	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, ok := ts.Type.(*ast.InterfaceType); !ok || !hasSealedMarker(gen.Doc, ts.Doc) {
					continue
				}
				obj, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
				if !ok || obj == nil {
					continue
				}
				iface := namedInterface(obj.Type())
				if iface == nil {
					continue
				}
				sealed[obj] = iface
				pass.ExportObjectFact(obj, &sealedFact{})
			}
		}
	}

	for _, objectFact := range pass.AllObjectFacts() {
		if _, ok := objectFact.Fact.(*sealedFact); !ok {
			continue
		}
		obj, ok := objectFact.Object.(*types.TypeName)
		if !ok || obj == nil {
			continue
		}
		iface := namedInterface(obj.Type())
		if iface == nil {
			continue
		}
		sealed[obj] = iface
	}

	sealedObjects := make([]*types.TypeName, 0, len(sealed))
	for obj := range sealed {
		sealedObjects = append(sealedObjects, obj)
	}
	sort.Slice(sealedObjects, func(i int, j int) bool {
		left := qualifiedTypeName(sealedObjects[i])
		right := qualifiedTypeName(sealedObjects[j])
		return left < right
	})

	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		reported := map[token.Pos]struct{}{}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if _, ok := ts.Type.(*ast.InterfaceType); ok {
					continue
				}
				obj, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
				if !ok || obj == nil {
					continue
				}
				named, ok := obj.Type().(*types.Named)
				if !ok {
					continue
				}
				for _, sealedObj := range sealedObjects {
					if sealedObj == nil || sealedObj.Pkg() == nil || sealedObj.Pkg().Path() == pass.Pkg.Path() {
						continue
					}
					iface := sealed[sealedObj]
					if !implementsSealed(named, iface) {
						continue
					}
					pass.Report(analysis.Diagnostic{
						Pos:     ts.Pos(),
						End:     ts.End(),
						Message: "type " + ts.Name.Name + " implements sealed interface " + sealedObj.Pkg().Name() + "." + sealedObj.Name() + " outside its home package; move the implementation beside the interface. (see PLAN.md §7 sin #8)",
					})
					break
				}
			}
		}

		for _, decl := range file.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				if node.Body == nil {
					continue
				}
				sig, ok := pass.TypesInfo.Defs[node.Name].Type().(*types.Signature)
				if !ok {
					continue
				}
				inspectFlow(pass, node.Body, sig.Results(), sealedObjects, sealed, reported)
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					valueSpec, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					inspectValueSpec(pass, valueSpec, nil, sealedObjects, sealed, reported)
				}
			}
		}
	}

	return nil, nil
}

func inspectFlow(pass *analysis.Pass, body *ast.BlockStmt, results *types.Tuple, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	inspectFlowWithFacts(pass, body, results, nil, sealedObjects, sealed, reported)
}

func inspectFlowWithFacts(pass *analysis.Pass, body *ast.BlockStmt, results *types.Tuple, inherited *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	facts := inherited.clone()
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			if node.Body == nil {
				return false
			}
			sig, ok := pass.TypesInfo.TypeOf(node).(*types.Signature)
			if !ok {
				return false
			}
			inspectFlowWithFacts(pass, node.Body, sig.Results(), facts, sealedObjects, sealed, reported)
			return false
		case *ast.DeclStmt:
			decl, ok := node.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				inspectValueSpec(pass, valueSpec, facts, sealedObjects, sealed, reported)
			}
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 1 {
				if tuple, ok := pass.TypesInfo.TypeOf(node.Results[0]).(*types.Tuple); ok {
					for index := 0; results != nil && index < results.Len() && index < tuple.Len(); index++ {
						reportImportedSealedValueWithFactsAt(pass, node.Results[0], results.At(index).Type(), index, facts, sealedObjects, sealed, reported)
					}
					break
				}
			}
			for index, result := range node.Results {
				if results == nil || index >= results.Len() {
					break
				}
				reportImportedSealedValueWithFacts(pass, result, results.At(index).Type(), facts, sealedObjects, sealed, reported)
			}
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 {
				if tuple, ok := pass.TypesInfo.TypeOf(node.Rhs[0]).(*types.Tuple); ok {
					for index, lhs := range node.Lhs {
						if index >= tuple.Len() {
							break
						}
						inspectAssignmentTarget(pass, lhs, facts, sealedObjects, sealed, reported)
						reportImportedSealedValueWithFactsAt(pass, node.Rhs[0], pass.TypesInfo.TypeOf(lhs), index, facts, sealedObjects, sealed, reported)
						facts.record(pass, lhs, node.Rhs[0], index)
					}
					break
				}
			}
			for index, rhs := range node.Rhs {
				if index >= len(node.Lhs) {
					break
				}
				inspectAssignmentTarget(pass, node.Lhs[index], facts, sealedObjects, sealed, reported)
				reportImportedSealedValueWithFacts(pass, rhs, pass.TypesInfo.TypeOf(node.Lhs[index]), facts, sealedObjects, sealed, reported)
				facts.record(pass, node.Lhs[index], rhs, -1)
			}
		case *ast.RangeStmt:
			keyType, valueType := rangeTypes(pass.TypesInfo.TypeOf(node.X))
			inspectRangeAssignmentTarget(pass, node.Key, keyType, facts, sealedObjects, sealed, reported)
			inspectRangeAssignmentTarget(pass, node.Value, valueType, facts, sealedObjects, sealed, reported)
		case *ast.CallExpr:
			inspectCall(pass, node, facts, sealedObjects, sealed, reported)
		case *ast.CompositeLit:
			inspectCompositeLiteral(pass, node, facts, sealedObjects, sealed, reported)
		case *ast.SendStmt:
			if ch, ok := underlying(pass.TypesInfo.TypeOf(node.Chan)).(*types.Chan); ok {
				reportImportedSealedValueWithFacts(pass, node.Value, ch.Elem(), facts, sealedObjects, sealed, reported)
			}
		}
		return true
	})
}

func inspectRangeAssignmentTarget(pass *analysis.Pass, target ast.Expr, actual types.Type, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if target == nil || actual == nil {
		return
	}
	inspectAssignmentTarget(pass, target, facts, sealedObjects, sealed, reported)
	reportImportedSealedActual(pass, target, actual, pass.TypesInfo.TypeOf(target), sealedObjects, sealed, reported)
	facts.recordActual(pass, target, actual)
}

func rangeTypes(t types.Type) (types.Type, types.Type) {
	switch typ := underlying(t).(type) {
	case *types.Slice:
		return types.Typ[types.Int], typ.Elem()
	case *types.Array:
		return types.Typ[types.Int], typ.Elem()
	case *types.Map:
		return typ.Key(), typ.Elem()
	case *types.Chan:
		return typ.Elem(), nil
	default:
		return nil, nil
	}
}

func inspectAssignmentTarget(pass *analysis.Pass, lhs ast.Expr, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	indexExpr, ok := lhs.(*ast.IndexExpr)
	if !ok {
		return
	}
	if m, ok := underlying(pass.TypesInfo.TypeOf(indexExpr.X)).(*types.Map); ok {
		reportImportedSealedValueWithFacts(pass, indexExpr.Index, m.Key(), facts, sealedObjects, sealed, reported)
	}
}

type flowFacts struct {
	concrete map[*types.Var]types.Type
}

func newFlowFacts() *flowFacts {
	return &flowFacts{concrete: map[*types.Var]types.Type{}}
}

func (f *flowFacts) clone() *flowFacts {
	cloned := newFlowFacts()
	if f == nil {
		return cloned
	}
	for key, value := range f.concrete {
		cloned.concrete[key] = value
	}
	return cloned
}

func (f *flowFacts) recordName(pass *analysis.Pass, name *ast.Ident, rhs ast.Expr, tupleIndex int) {
	if f == nil || name == nil || name.Name == "_" {
		return
	}
	obj, ok := pass.TypesInfo.Defs[name].(*types.Var)
	if !ok || obj == nil {
		obj, ok = pass.TypesInfo.Uses[name].(*types.Var)
	}
	if !ok || obj == nil {
		return
	}
	f.recordObject(pass, obj, rhs, tupleIndex)
}

func (f *flowFacts) record(pass *analysis.Pass, lhs ast.Expr, rhs ast.Expr, tupleIndex int) {
	if f == nil {
		return
	}
	ident, ok := lhs.(*ast.Ident)
	if !ok {
		return
	}
	f.recordName(pass, ident, rhs, tupleIndex)
}

func (f *flowFacts) recordActual(pass *analysis.Pass, lhs ast.Expr, actual types.Type) {
	if f == nil {
		return
	}
	ident, ok := lhs.(*ast.Ident)
	if !ok || ident.Name == "_" {
		return
	}
	obj, ok := pass.TypesInfo.Defs[ident].(*types.Var)
	if !ok || obj == nil {
		obj, ok = pass.TypesInfo.Uses[ident].(*types.Var)
	}
	if !ok || obj == nil {
		return
	}
	f.recordObjectActual(obj, actual)
}

func (f *flowFacts) recordObject(pass *analysis.Pass, obj *types.Var, rhs ast.Expr, tupleIndex int) {
	actual := pass.TypesInfo.TypeOf(rhs)
	if tuple, ok := actual.(*types.Tuple); ok {
		if tupleIndex < 0 || tupleIndex >= tuple.Len() {
			delete(f.concrete, obj)
			return
		}
		actual = tuple.At(tupleIndex).Type()
	}
	if namedImplementation(actual) == nil {
		if converted, ok := concreteFromConversion(pass, rhs); ok {
			actual = converted
		}
	}
	if namedImplementation(actual) == nil {
		delete(f.concrete, obj)
		return
	}
	f.recordObjectActual(obj, actual)
}

func (f *flowFacts) recordObjectActual(obj *types.Var, actual types.Type) {
	if f == nil || obj == nil {
		return
	}
	if namedImplementation(actual) == nil {
		delete(f.concrete, obj)
		return
	}
	f.concrete[obj] = actual
}

func (f *flowFacts) assertedConcrete(pass *analysis.Pass, expr ast.Expr) (types.Type, bool) {
	if f == nil {
		return nil, false
	}
	assertion, ok := expr.(*ast.TypeAssertExpr)
	if !ok {
		return nil, false
	}
	return f.concreteForExpr(pass, assertion.X)
}

func (f *flowFacts) concreteForExpr(pass *analysis.Pass, expr ast.Expr) (types.Type, bool) {
	if ident, ok := expr.(*ast.Ident); ok {
		obj, ok := pass.TypesInfo.Uses[ident].(*types.Var)
		if !ok || obj == nil {
			return nil, false
		}
		actual, ok := f.concrete[obj]
		return actual, ok
	}
	if actual, ok := concreteFromConversion(pass, expr); ok {
		return actual, true
	}
	actual := pass.TypesInfo.TypeOf(expr)
	if namedImplementation(actual) == nil {
		return nil, false
	}
	return actual, true
}

func concreteFromConversion(pass *analysis.Pass, expr ast.Expr) (types.Type, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, false
	}
	if _, ok := pass.TypesInfo.TypeOf(call.Fun).(*types.Signature); ok {
		return nil, false
	}
	actual := pass.TypesInfo.TypeOf(call.Args[0])
	if namedImplementation(actual) == nil {
		return nil, false
	}
	return actual, true
}

func inspectValueSpec(pass *analysis.Pass, valueSpec *ast.ValueSpec, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	var expected types.Type
	if valueSpec.Type != nil {
		expected = pass.TypesInfo.TypeOf(valueSpec.Type)
	}
	if len(valueSpec.Values) == 1 && len(valueSpec.Names) > 1 {
		if _, ok := pass.TypesInfo.TypeOf(valueSpec.Values[0]).(*types.Tuple); ok {
			for index, name := range valueSpec.Names {
				reportImportedSealedValueWithFactsAt(pass, valueSpec.Values[0], expected, index, facts, sealedObjects, sealed, reported)
				if facts != nil {
					facts.recordName(pass, name, valueSpec.Values[0], index)
				}
			}
			inspectExpressionCalls(pass, valueSpec.Values[0], facts, sealedObjects, sealed, reported)
			return
		}
	}
	for index, value := range valueSpec.Values {
		reportImportedSealedValueWithFacts(pass, value, expected, facts, sealedObjects, sealed, reported)
		if facts != nil && index < len(valueSpec.Names) {
			facts.recordName(pass, valueSpec.Names[index], value, -1)
		}
		inspectExpressionCalls(pass, value, facts, sealedObjects, sealed, reported)
	}
}

func inspectExpressionCalls(pass *analysis.Pass, expr ast.Expr, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			if node.Body == nil {
				return false
			}
			sig, ok := pass.TypesInfo.TypeOf(node).(*types.Signature)
			if !ok {
				return false
			}
			inspectFlowWithFacts(pass, node.Body, sig.Results(), facts, sealedObjects, sealed, reported)
			return false
		case *ast.CallExpr:
			inspectCall(pass, node, facts, sealedObjects, sealed, reported)
		case *ast.CompositeLit:
			inspectCompositeLiteral(pass, node, facts, sealedObjects, sealed, reported)
		}
		return true
	})
}

func inspectCall(pass *analysis.Pass, call *ast.CallExpr, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if target := sealedObjectForType(pass.TypesInfo.TypeOf(call.Fun), sealedObjects); target != nil && len(call.Args) == 1 {
		reportImportedSealedValueWithFacts(pass, call.Args[0], target.Type(), facts, sealedObjects, sealed, reported)
		return
	}
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "append" && len(call.Args) > 1 {
		if _, ok := pass.TypesInfo.Uses[ident].(*types.Builtin); !ok {
			return
		}
		if slice, ok := underlying(pass.TypesInfo.TypeOf(call.Args[0])).(*types.Slice); ok {
			for _, arg := range call.Args[1:] {
				reportImportedSealedValueWithFacts(pass, arg, slice.Elem(), facts, sealedObjects, sealed, reported)
			}
		}
		return
	}
	sig, ok := pass.TypesInfo.TypeOf(call.Fun).(*types.Signature)
	if !ok {
		return
	}
	params := sig.Params()
	if len(call.Args) == 1 {
		if tuple, ok := pass.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); ok {
			for index := 0; params != nil && index < tuple.Len(); index++ {
				paramIndex := index
				if sig.Variadic() && index >= params.Len()-1 {
					paramIndex = params.Len() - 1
				}
				if paramIndex < 0 || paramIndex >= params.Len() {
					break
				}
				expected := params.At(paramIndex).Type()
				if sig.Variadic() && index >= params.Len()-1 {
					if slice, ok := expected.(*types.Slice); ok {
						expected = slice.Elem()
					}
				}
				reportImportedSealedValueWithFactsAt(pass, call.Args[0], expected, index, facts, sealedObjects, sealed, reported)
			}
			return
		}
	}
	for index, arg := range call.Args {
		if params == nil || params.Len() == 0 {
			break
		}
		paramIndex := index
		if sig.Variadic() && index >= params.Len()-1 {
			paramIndex = params.Len() - 1
		}
		if paramIndex >= params.Len() {
			break
		}
		expected := params.At(paramIndex).Type()
		if sig.Variadic() && index >= params.Len()-1 && call.Ellipsis == token.NoPos {
			if slice, ok := expected.(*types.Slice); ok {
				expected = slice.Elem()
			}
		}
		reportImportedSealedValueWithFacts(pass, arg, expected, facts, sealedObjects, sealed, reported)
	}
}

func inspectCompositeLiteral(pass *analysis.Pass, lit *ast.CompositeLit, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	switch typ := underlying(pass.TypesInfo.TypeOf(lit)).(type) {
	case *types.Slice:
		for _, elt := range lit.Elts {
			reportImportedSealedValueWithFacts(pass, compositeLiteralValue(elt), typ.Elem(), facts, sealedObjects, sealed, reported)
		}
	case *types.Array:
		for _, elt := range lit.Elts {
			reportImportedSealedValueWithFacts(pass, compositeLiteralValue(elt), typ.Elem(), facts, sealedObjects, sealed, reported)
		}
	case *types.Map:
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				reportImportedSealedValueWithFacts(pass, kv.Key, typ.Key(), facts, sealedObjects, sealed, reported)
				reportImportedSealedValueWithFacts(pass, kv.Value, typ.Elem(), facts, sealedObjects, sealed, reported)
			}
		}
	case *types.Struct:
		for index, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if field := structFieldForKey(typ, kv.Key); field != nil {
					reportImportedSealedValueWithFacts(pass, kv.Value, field.Type(), facts, sealedObjects, sealed, reported)
				}
				continue
			}
			if index < typ.NumFields() {
				reportImportedSealedValueWithFacts(pass, elt, typ.Field(index).Type(), facts, sealedObjects, sealed, reported)
			}
		}
	}
}

func underlying(t types.Type) types.Type {
	t = unalias(t)
	if named, ok := t.(*types.Named); ok {
		return named.Underlying()
	}
	return t
}

func structFieldForKey(typ *types.Struct, key ast.Expr) *types.Var {
	ident, ok := key.(*ast.Ident)
	if !ok {
		return nil
	}
	for i := 0; i < typ.NumFields(); i++ {
		field := typ.Field(i)
		if field.Name() == ident.Name {
			return field
		}
	}
	return nil
}

func compositeLiteralValue(expr ast.Expr) ast.Expr {
	if kv, ok := expr.(*ast.KeyValueExpr); ok {
		return kv.Value
	}
	return expr
}

func reportImportedSealedValue(pass *analysis.Pass, expr ast.Expr, expected types.Type, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	reportImportedSealedValueAt(pass, expr, expected, -1, sealedObjects, sealed, reported)
}

func reportImportedSealedValueWithFacts(pass *analysis.Pass, expr ast.Expr, expected types.Type, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	reportImportedSealedValueWithFactsAt(pass, expr, expected, -1, facts, sealedObjects, sealed, reported)
}

func reportImportedSealedValueWithFactsAt(pass *analysis.Pass, expr ast.Expr, expected types.Type, tupleIndex int, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if actual, ok := facts.assertedConcrete(pass, expr); ok {
		reportImportedSealedActual(pass, expr, actual, expected, sealedObjects, sealed, reported)
		return
	}
	reportImportedSealedValueAt(pass, expr, expected, tupleIndex, sealedObjects, sealed, reported)
}

func reportImportedSealedValueAt(pass *analysis.Pass, expr ast.Expr, expected types.Type, tupleIndex int, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	actual := pass.TypesInfo.TypeOf(expr)
	if tuple, ok := actual.(*types.Tuple); ok {
		if tupleIndex < 0 || tupleIndex >= tuple.Len() {
			return
		}
		actual = tuple.At(tupleIndex).Type()
	}
	reportImportedSealedActual(pass, expr, actual, expected, sealedObjects, sealed, reported)
}

func reportImportedSealedActual(pass *analysis.Pass, expr ast.Expr, actual types.Type, expected types.Type, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	sealedObj := sealedObjectForType(expected, sealedObjects)
	if sealedObj == nil {
		return
	}
	named := namedImplementation(actual)
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return
	}
	if named.Obj().Pkg().Path() == pass.Pkg.Path() || named.Obj().Pkg().Path() == sealedObj.Pkg().Path() {
		return
	}
	if !implementsSealed(named, sealed[sealedObj]) {
		return
	}
	if _, ok := reported[expr.Pos()]; ok {
		return
	}
	reported[expr.Pos()] = struct{}{}
	pass.Report(analysis.Diagnostic{
		Pos:     expr.Pos(),
		End:     expr.End(),
		Message: qualifiedImportedName(named) + " crosses sealed interface " + sealedObj.Pkg().Name() + "." + sealedObj.Name() + " outside its home package; move the implementation beside the interface. (see PLAN.md §7 sin #8)",
	})
}

func sealedObjectForType(t types.Type, sealedObjects []*types.TypeName) *types.TypeName {
	t = unalias(t)
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return nil
	}
	for _, sealedObj := range sealedObjects {
		if sealedObj == named.Obj() {
			return sealedObj
		}
	}
	return nil
}

func namedImplementation(t types.Type) *types.Named {
	t = unalias(t)
	if named, ok := t.(*types.Named); ok {
		return named
	}
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := unalias(ptr.Elem()).(*types.Named); ok {
			return named
		}
	}
	return nil
}

func unalias(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return types.Unalias(t)
}

func qualifiedImportedName(named *types.Named) string {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	return named.Obj().Pkg().Name() + "." + named.Obj().Name()
}

func qualifiedTypeName(obj *types.TypeName) string {
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

func namedInterface(t types.Type) *types.Interface {
	t = unalias(t)
	named, ok := t.(*types.Named)
	if !ok {
		return nil
	}
	iface, ok := named.Underlying().(*types.Interface)
	if !ok {
		return nil
	}
	return iface.Complete()
}

func implementsSealed(named *types.Named, iface *types.Interface) bool {
	return types.Implements(named, iface) || types.Implements(types.NewPointer(named), iface)
}

func hasSealedMarker(groups ...*ast.CommentGroup) bool {
	for _, group := range groups {
		if group == nil {
			continue
		}
		for _, comment := range group.List {
			if strings.Contains(comment.Text, sealedMarker) {
				return true
			}
		}
	}
	return false
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
