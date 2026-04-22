// Package maxmutex forbids a struct from declaring more than one
// sync.Mutex or sync.RWMutex field.
//
// Sin #1 in PLAN.md §7. Multiple mutexes on one struct are an empirical
// smell for god-structs with unrelated concerns: each additional mutex
// makes lock-ordering bugs more likely and signals that the type should
// be decomposed.
//
// A single "//cerebro:lint:allow maxmutex <reason> <issue-url>" comment
// line above the struct declaration silences the analyzer for that
// struct only. The allowlist must be explicit and comes out of a
// CODEOWNERS-protected file in the main repo.
package maxmutex

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `enforce at most one sync.Mutex / sync.RWMutex field per struct

A struct that needs two mutexes nearly always wants to be two types.
Use composition, not coexistence.`

// Analyzer is the exported analyzer registered with cerebrolint.
var Analyzer = &analysis.Analyzer{
	Name:     "maxmutex",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

const allowMarker = "cerebro:lint:allow maxmutex"

func run(pass *analysis.Pass) (any, error) {
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
			count, locations := countMutexes(pass, st)
			if count > 1 {
				pass.Report(analysis.Diagnostic{
					Pos: ts.Pos(),
					End: ts.End(),
					Message: "struct " + ts.Name.Name + " declares " +
						itoa(count) + " mutex fields; at most 1 is allowed. " +
						"Split the type so each mutex protects a single cohesive concern. " +
						"(see PLAN.md §7 sin #1)",
					Related: locations,
				})
			}
		}
	})
	return nil, nil
}

func countMutexes(pass *analysis.Pass, st *ast.StructType) (int, []analysis.RelatedInformation) {
	var count int
	var related []analysis.RelatedInformation
	for _, field := range st.Fields.List {
		if isMutexType(pass.TypesInfo.TypeOf(field.Type)) {
			// Each name in a multi-name field (a, b sync.Mutex) counts.
			names := len(field.Names)
			if names == 0 {
				names = 1 // embedded
			}
			count += names
			related = append(related, analysis.RelatedInformation{
				Pos:     field.Pos(),
				End:     field.End(),
				Message: "mutex field",
			})
		}
	}
	return count, related
}

func isMutexType(t types.Type) bool {
	if t == nil {
		return false
	}
	// Handle pointers: *sync.Mutex also counts.
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	if obj.Pkg().Path() != "sync" {
		return false
	}
	switch obj.Name() {
	case "Mutex", "RWMutex":
		return true
	}
	return false
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

// itoa is a tiny allocation-free replacement for strconv.Itoa to keep
// this analyzer's import set minimal (and auditable).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
