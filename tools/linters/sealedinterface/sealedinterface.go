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
					var expected types.Type
					if valueSpec.Type != nil {
						expected = pass.TypesInfo.TypeOf(valueSpec.Type)
					}
					for _, value := range valueSpec.Values {
						reportImportedSealedValue(pass, value, expected, sealedObjects, sealed, reported)
						inspectExpressionCalls(pass, value, sealedObjects, sealed, reported)
					}
				}
			}
		}
	}

	return nil, nil
}

func inspectFlow(pass *analysis.Pass, body *ast.BlockStmt, results *types.Tuple, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
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
			inspectFlow(pass, node.Body, sig.Results(), sealedObjects, sealed, reported)
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 1 {
				if tuple, ok := pass.TypesInfo.TypeOf(node.Results[0]).(*types.Tuple); ok {
					for index := 0; results != nil && index < results.Len() && index < tuple.Len(); index++ {
						reportImportedSealedValueAt(pass, node.Results[0], results.At(index).Type(), index, sealedObjects, sealed, reported)
					}
					break
				}
			}
			for index, result := range node.Results {
				if results == nil || index >= results.Len() {
					break
				}
				reportImportedSealedValue(pass, result, results.At(index).Type(), sealedObjects, sealed, reported)
			}
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 {
				if tuple, ok := pass.TypesInfo.TypeOf(node.Rhs[0]).(*types.Tuple); ok {
					for index, lhs := range node.Lhs {
						if index >= tuple.Len() {
							break
						}
						reportImportedSealedValueAt(pass, node.Rhs[0], pass.TypesInfo.TypeOf(lhs), index, sealedObjects, sealed, reported)
					}
					break
				}
			}
			for index, rhs := range node.Rhs {
				if index >= len(node.Lhs) {
					break
				}
				reportImportedSealedValue(pass, rhs, pass.TypesInfo.TypeOf(node.Lhs[index]), sealedObjects, sealed, reported)
			}
		case *ast.CallExpr:
			inspectCall(pass, node, sealedObjects, sealed, reported)
		case *ast.CompositeLit:
			inspectCompositeLiteral(pass, node, sealedObjects, sealed, reported)
		}
		return true
	})
}

func inspectExpressionCalls(pass *analysis.Pass, expr ast.Expr, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
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
			inspectFlow(pass, node.Body, sig.Results(), sealedObjects, sealed, reported)
			return false
		case *ast.CallExpr:
			inspectCall(pass, node, sealedObjects, sealed, reported)
		case *ast.CompositeLit:
			inspectCompositeLiteral(pass, node, sealedObjects, sealed, reported)
		}
		return true
	})
}

func inspectCall(pass *analysis.Pass, call *ast.CallExpr, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if target := sealedObjectForType(pass.TypesInfo.TypeOf(call.Fun), sealedObjects); target != nil && len(call.Args) == 1 {
		reportImportedSealedValue(pass, call.Args[0], target.Type(), sealedObjects, sealed, reported)
		return
	}
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "append" && len(call.Args) > 1 {
		if _, ok := pass.TypesInfo.Uses[ident].(*types.Builtin); !ok {
			return
		}
		if slice, ok := underlying(pass.TypesInfo.TypeOf(call.Args[0])).(*types.Slice); ok {
			for _, arg := range call.Args[1:] {
				reportImportedSealedValue(pass, arg, slice.Elem(), sealedObjects, sealed, reported)
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
			for index := 0; params != nil && index < params.Len() && index < tuple.Len(); index++ {
				reportImportedSealedValueAt(pass, call.Args[0], params.At(index).Type(), index, sealedObjects, sealed, reported)
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
		reportImportedSealedValue(pass, arg, expected, sealedObjects, sealed, reported)
	}
}

func inspectCompositeLiteral(pass *analysis.Pass, lit *ast.CompositeLit, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	switch typ := underlying(pass.TypesInfo.TypeOf(lit)).(type) {
	case *types.Slice:
		for _, elt := range lit.Elts {
			reportImportedSealedValue(pass, compositeLiteralValue(elt), typ.Elem(), sealedObjects, sealed, reported)
		}
	case *types.Array:
		for _, elt := range lit.Elts {
			reportImportedSealedValue(pass, compositeLiteralValue(elt), typ.Elem(), sealedObjects, sealed, reported)
		}
	case *types.Map:
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				reportImportedSealedValue(pass, kv.Key, typ.Key(), sealedObjects, sealed, reported)
				reportImportedSealedValue(pass, kv.Value, typ.Elem(), sealedObjects, sealed, reported)
			}
		}
	case *types.Struct:
		for index, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if field := structFieldForKey(typ, kv.Key); field != nil {
					reportImportedSealedValue(pass, kv.Value, field.Type(), sealedObjects, sealed, reported)
				}
				continue
			}
			if index < typ.NumFields() {
				reportImportedSealedValue(pass, elt, typ.Field(index).Type(), sealedObjects, sealed, reported)
			}
		}
	}
}

func underlying(t types.Type) types.Type {
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

func reportImportedSealedValueAt(pass *analysis.Pass, expr ast.Expr, expected types.Type, tupleIndex int, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	sealedObj := sealedObjectForType(expected, sealedObjects)
	if sealedObj == nil {
		return
	}
	actual := pass.TypesInfo.TypeOf(expr)
	if tuple, ok := actual.(*types.Tuple); ok {
		if tupleIndex < 0 || tupleIndex >= tuple.Len() {
			return
		}
		actual = tuple.At(tupleIndex).Type()
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
	if named, ok := t.(*types.Named); ok {
		return named
	}
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := ptr.Elem().(*types.Named); ok {
			return named
		}
	}
	return nil
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
