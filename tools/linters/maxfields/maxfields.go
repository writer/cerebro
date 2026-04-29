// Package maxfields forbids structs with more than a configurable
// threshold (default 24) of fields. Exported + unexported + embedded
// all count; a, b, c int counts as three.
//
// Sin #2 in PLAN.md §7. Large structs are the habitat of god-types:
// once a struct has 40+ fields it is almost always used as a bag for
// unrelated concerns, and the lifetime of one field drags in the
// lifetime of all the others.
//
// A struct named `Config` is exempt *only* inside pkg `config`; every
// other struct must split.
package maxfields

import (
	"flag"
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `enforce a maximum number of fields per struct (default 24)

Large structs accrete unrelated concerns. Split them into smaller
cohesive types. The limit is intentionally strict; use composition.`

const allowMarker = "cerebro:lint:allow maxfields"

// Analyzer is the exported analyzer registered with cerebrolint.
var Analyzer = newAnalyzer()

func newAnalyzer() *analysis.Analyzer {
	a := &analysis.Analyzer{
		Name:     "maxfields",
		Doc:      doc,
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      run,
	}
	a.Flags.Init("maxfields", flag.ExitOnError)
	a.Flags.Int("max", defaultMax, "maximum number of fields allowed per struct")
	return a
}

const defaultMax = 24

func run(pass *analysis.Pass) (any, error) {
	limit := defaultMax
	if f := pass.Analyzer.Flags.Lookup("max"); f != nil {
		if gv, ok := f.Value.(flag.Getter); ok {
			if v, ok := gv.Get().(int); ok && v > 0 {
				limit = v
			}
		}
	}

	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{(*ast.GenDecl)(nil)}

	ins.Preorder(nodeFilter, func(n ast.Node) {
		decl := n.(*ast.GenDecl)
		if hasAllowMarker(decl.Doc) {
			return
		}
		for _, spec := range decl.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			count := countFields(st)
			if count > limit {
				pass.Report(analysis.Diagnostic{
					Pos: ts.Pos(),
					End: ts.End(),
					Message: "struct " + ts.Name.Name + " declares " +
						itoa(count) + " fields; max allowed is " + itoa(limit) +
						". Split into smaller cohesive types. (see PLAN.md §7 sin #2)",
				})
			}
		}
	})
	return nil, nil
}

func countFields(st *ast.StructType) int {
	n := 0
	for _, f := range st.Fields.List {
		k := len(f.Names)
		if k == 0 {
			k = 1
		}
		n += k
	}
	return n
}

func hasAllowMarker(g *ast.CommentGroup) bool {
	if g == nil {
		return false
	}
	for _, c := range g.List {
		if strings.Contains(c.Text, allowMarker) {
			return true
		}
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
