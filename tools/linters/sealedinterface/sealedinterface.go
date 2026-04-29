package sealedinterface

import (
	"go/ast"
	"go/token"
	"go/types"
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

type sealedInterface struct {
	obj   *types.TypeName
	iface *types.Interface
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
				ifaceNode, ok := ts.Type.(*ast.InterfaceType)
				if !ok || !hasSealedMarker(gen.Doc, ts.Doc) {
					continue
				}
				_ = ifaceNode
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
				for sealedObj, iface := range sealed {
					if sealedObj == nil || sealedObj.Pkg() == nil || sealedObj.Pkg().Path() == pass.Pkg.Path() {
						continue
					}
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

	return nil, nil
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
