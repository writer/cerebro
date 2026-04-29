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
	}

	for _, file := range pass.Files {
		if isTestFile(pass, file.Pos()) {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ValueSpec:
				if node.Type == nil {
					return true
				}
				target := pass.TypesInfo.TypeOf(node.Type)
				for _, value := range node.Values {
					reportImportedImplementation(pass, sealed, sealedObjects, target, value)
				}
			case *ast.AssignStmt:
				if len(node.Lhs) != len(node.Rhs) {
					return true
				}
				for i := range node.Lhs {
					reportImportedImplementation(pass, sealed, sealedObjects, pass.TypesInfo.TypeOf(node.Lhs[i]), node.Rhs[i])
				}
			}
			return true
		})
	}

	return nil, nil
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

func reportImportedImplementation(pass *analysis.Pass, sealed map[*types.TypeName]*types.Interface, sealedObjects []*types.TypeName, targetType types.Type, value ast.Expr) {
	sealedObj, iface := sealedTarget(sealed, sealedObjects, targetType)
	if sealedObj == nil || iface == nil {
		return
	}
	named := assignedNamedType(pass.TypesInfo.TypeOf(value))
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return
	}
	if named.Obj().Pkg().Path() == sealedObj.Pkg().Path() {
		return
	}
	if pass.Pkg != nil && named.Obj().Pkg().Path() == pass.Pkg.Path() {
		return
	}
	if !implementsSealed(named, iface) {
		return
	}
	pass.Report(analysis.Diagnostic{
		Pos:     value.Pos(),
		End:     value.End(),
		Message: "type " + named.Obj().Pkg().Name() + "." + named.Obj().Name() + " implements sealed interface " + sealedObj.Pkg().Name() + "." + sealedObj.Name() + " outside its home package; move the implementation beside the interface. (see PLAN.md §7 sin #8)",
	})
}

func sealedTarget(sealed map[*types.TypeName]*types.Interface, sealedObjects []*types.TypeName, targetType types.Type) (*types.TypeName, *types.Interface) {
	named, ok := types.Unalias(targetType).(*types.Named)
	if !ok || named.Obj() == nil {
		return nil, nil
	}
	targetName := qualifiedTypeName(named.Obj())
	for _, sealedObj := range sealedObjects {
		if qualifiedTypeName(sealedObj) != targetName {
			continue
		}
		return sealedObj, sealed[sealedObj]
	}
	return nil, nil
}

func assignedNamedType(t types.Type) *types.Named {
	switch current := types.Unalias(t).(type) {
	case *types.Named:
		return current
	case *types.Pointer:
		named, _ := types.Unalias(current.Elem()).(*types.Named)
		return named
	default:
		return nil
	}
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
