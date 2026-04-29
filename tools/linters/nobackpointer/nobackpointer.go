package nobackpointer

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid struct fields that point back to *App or *Server

Back-pointers recreate god-objects and hide dependency boundaries. Pass a
narrow interface instead.`

const allowMarker = "cerebro:lint:allow nobackpointer"

var Analyzer = &analysis.Analyzer{
	Name:     "nobackpointer",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.GenDecl)(nil)}, func(n ast.Node) {
		decl := n.(*ast.GenDecl)
		if hasAllowMarker(decl.Doc) {
			return
		}
		for _, spec := range decl.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || isTestFile(pass, ts.Pos()) {
				continue
			}
			if hasAllowMarker(ts.Doc) {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			for _, field := range st.Fields.List {
				target, ok := backPointerTarget(pass, pass.TypesInfo.TypeOf(field.Type))
				if !ok {
					continue
				}
				pass.Report(analysis.Diagnostic{
					Pos:     field.Pos(),
					End:     field.End(),
					Message: "struct field " + fieldLabel(field) + " stores back-pointer to *" + target + "; inject a narrow interface instead. (see PLAN.md §7 sin #7)",
				})
			}
		}
	})
	return nil, nil
}

func backPointerTarget(pass *analysis.Pass, t types.Type) (string, bool) {
	named, ok := namedPointerTarget(t)
	if !ok || named.Obj() == nil {
		return "", false
	}
	if named.Obj().Pkg() == nil || pass.Pkg == nil || named.Obj().Pkg().Path() != pass.Pkg.Path() {
		return "", false
	}
	switch named.Obj().Name() {
	case "App", "Server":
		return named.Obj().Name(), true
	default:
		return "", false
	}
}

func namedPointerTarget(t types.Type) (*types.Named, bool) {
	seen := map[types.Type]struct{}{}
	for t != nil {
		t = types.Unalias(t)
		if _, ok := seen[t]; ok {
			return nil, false
		}
		seen[t] = struct{}{}
		switch current := t.(type) {
		case *types.Pointer:
			named, ok := types.Unalias(current.Elem()).(*types.Named)
			if !ok {
				return nil, false
			}
			return named, true
		case *types.Named:
			t = current.Underlying()
		default:
			return nil, false
		}
	}
	return nil, false
}

func fieldLabel(field *ast.Field) string {
	if field == nil || len(field.Names) == 0 {
		return "embedded field"
	}
	return "'" + field.Names[0].Name + "'"
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}

func hasAllowMarker(group *ast.CommentGroup) bool {
	if group == nil {
		return false
	}
	for _, comment := range group.List {
		if strings.Contains(comment.Text, allowMarker) {
			return true
		}
	}
	return false
}
