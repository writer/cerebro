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
	return backPointerTargetIn(pass, t, map[types.Type]struct{}{})
}

func backPointerTargetIn(pass *analysis.Pass, t types.Type, seen map[types.Type]struct{}) (string, bool) {
	if t == nil {
		return "", false
	}
	t = types.Unalias(t)
	if _, ok := seen[t]; ok {
		return "", false
	}
	seen[t] = struct{}{}
	switch tt := t.(type) {
	case *types.Pointer:
		if target, ok := namedBackPointerTarget(pass, tt.Elem()); ok {
			return target, true
		}
		return backPointerTargetIn(pass, tt.Elem(), seen)
	case *types.Named:
		return backPointerTargetIn(pass, tt.Underlying(), seen)
	case *types.Slice:
		return backPointerTargetIn(pass, tt.Elem(), seen)
	case *types.Array:
		return backPointerTargetIn(pass, tt.Elem(), seen)
	case *types.Map:
		if target, ok := backPointerTargetIn(pass, tt.Key(), seen); ok {
			return target, true
		}
		return backPointerTargetIn(pass, tt.Elem(), seen)
	case *types.Chan:
		return backPointerTargetIn(pass, tt.Elem(), seen)
	default:
		return "", false
	}
}

func namedBackPointerTarget(pass *analysis.Pass, t types.Type) (string, bool) {
	t = types.Unalias(t)
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil {
		return "", false
	}
	if named.Obj().Pkg() == nil {
		return "", false
	}
	path := named.Obj().Pkg().Path()
	if pass != nil && path == pass.Pkg.Path() {
		// Back-pointers to the current package's App/Server types are still back-pointers.
	} else if path != "github.com/writer/cerebro" && !strings.HasPrefix(path, "github.com/writer/cerebro/") {
		return "", false
	}
	switch named.Obj().Name() {
	case "App", "Server":
		return named.Obj().Name(), true
	default:
		return "", false
	}
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
