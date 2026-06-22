package archtests

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// duplicateFunctionMinNodes is the minimum AST-node count for a function body
// to be considered for cross-source duplication. Trivial helpers below this are
// ignored to keep the signal high and avoid flagging tiny shared idioms.
const duplicateFunctionMinNodes = 50

// allowlistedSourceDuplicates lists cross-source duplicate function bodies that
// are known and explicitly accepted. Keys are the sorted, "|"-joined
// "pkg.Func" members of a duplicate group; values explain why the duplication
// is tolerated (ideally a tracking issue or a reason it is not extractable).
//
// This is a ratchet: every entry is current, pre-existing duplication. Do not
// add new entries to silence a fresh copy-paste; instead lift the shared logic
// into internal/sourcecdk. Remove an entry when its extraction lands.
var allowlistedSourceDuplicates = map[string]string{
	"aws.parseAWSURNs|azure.parseAzureURNs":     "provider URN parsing with provider-specific identifiers; consolidate cautiously (#956)",
	"okta.oktaURNsFor|sentinelone.urnsFor":      "provider URN construction; consolidate into Source CDK URN helper (#956)",
	"azure.New|gcp.New|googleworkspace.New":     "constructor scaffold building a concrete *Source; needs a generic CDK builder to deduplicate (#684)",
	"archetype.New|sdk.New|trustedendpoint.New": "constructor scaffold for sample/fixture sources; structural boilerplate (#684)",
}

// TestSourcePackagesDoNotDuplicateExtractableHelpers fails when the same
// (structurally identical) function body of meaningful size appears in two or
// more source packages. Such duplication is the signal that provider-agnostic
// behavior should live in internal/sourcecdk instead of being copy-pasted per
// source. The fingerprint ignores the function name, so renamed copies (e.g.
// IsUnsafeHost vs HostIsUnsafe) are still detected.
func TestSourcePackagesDoNotDuplicateExtractableHelpers(t *testing.T) {
	root := repoRoot(t)
	sourceRoot := filepath.Join(root, "sources")
	entries, err := os.ReadDir(sourceRoot)
	if err != nil {
		t.Fatalf("ReadDir(sources): %v", err)
	}

	type occurrence struct{ pkg, name string }
	groups := map[string][]occurrence{}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "internal" {
			continue
		}
		pkg := entry.Name()
		walkErr := filepath.WalkDir(filepath.Join(sourceRoot, pkg), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				fingerprint, nodes := funcBodyFingerprint(fn)
				if nodes < duplicateFunctionMinNodes {
					continue
				}
				groups[fingerprint] = append(groups[fingerprint], occurrence{pkg: pkg, name: funcDeclName(fn)})
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk sources/%s: %v", pkg, walkErr)
		}
	}

	var violations []string
	for _, members := range groups {
		distinctPkgs := map[string]struct{}{}
		for _, m := range members {
			distinctPkgs[m.pkg] = struct{}{}
		}
		if len(distinctPkgs) < 2 {
			continue
		}
		labels := make([]string, 0, len(members))
		for _, m := range members {
			labels = append(labels, m.pkg+"."+m.name)
		}
		key := strings.Join(uniqueSorted(labels), "|")
		if _, ok := allowlistedSourceDuplicates[key]; ok {
			continue
		}
		violations = append(violations, key)
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Fatalf("found %d cross-source duplicate function group(s); move shared, provider-agnostic logic into internal/sourcecdk, or add an allowlist entry with a reason:\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

// funcBodyFingerprint returns a position-independent structural fingerprint of a
// function body plus the number of AST nodes it contains. The function's own
// name is excluded so renamed copies share a fingerprint; identifiers, literals,
// and operator tokens are included so genuinely different logic does not.
func funcBodyFingerprint(fn *ast.FuncDecl) (string, int) {
	hash := sha256.New()
	nodes := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		nodes++
		hash.Write([]byte(reflect.TypeOf(n).String()))
		switch t := n.(type) {
		case *ast.Ident:
			hash.Write([]byte(":" + t.Name))
		case *ast.BasicLit:
			hash.Write([]byte(":" + t.Kind.String() + ":" + t.Value))
		case *ast.BinaryExpr:
			hash.Write([]byte(":" + t.Op.String()))
		case *ast.UnaryExpr:
			hash.Write([]byte(":" + t.Op.String()))
		case *ast.AssignStmt:
			hash.Write([]byte(":" + t.Tok.String()))
		case *ast.IncDecStmt:
			hash.Write([]byte(":" + t.Tok.String()))
		case *ast.BranchStmt:
			hash.Write([]byte(":" + t.Tok.String()))
		}
		hash.Write([]byte(";"))
		return true
	})
	return hex.EncodeToString(hash.Sum(nil)), nodes
}

func funcDeclName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return receiverTypeName(fn.Recv.List[0].Type) + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return "*" + receiverTypeName(t.X)
	case *ast.IndexExpr:
		return receiverTypeName(t.X)
	case *ast.IndexListExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return "?"
	}
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func TestFuncBodyFingerprintIgnoresFunctionName(t *testing.T) {
	body := `{
	if h == "" {
		return true
	}
	for _, c := range h {
		if c == ' ' {
			return true
		}
	}
	return false
}`
	a := mustParseFuncDecl(t, "package p\nfunc IsUnsafeHost(h string) bool "+body)
	b := mustParseFuncDecl(t, "package p\nfunc HostIsUnsafe(h string) bool "+body)
	fpA, _ := funcBodyFingerprint(a)
	fpB, _ := funcBodyFingerprint(b)
	if fpA != fpB {
		t.Fatalf("identical bodies with different function names must share a fingerprint")
	}
}

func TestFuncBodyFingerprintDistinguishesOperators(t *testing.T) {
	a := mustParseFuncDecl(t, "package p\nfunc f(x int) int { return x + 2 }")
	b := mustParseFuncDecl(t, "package p\nfunc f(x int) int { return x - 2 }")
	fpA, _ := funcBodyFingerprint(a)
	fpB, _ := funcBodyFingerprint(b)
	if fpA == fpB {
		t.Fatalf("bodies differing only by operator must produce different fingerprints")
	}
}

func mustParseFuncDecl(t *testing.T, src string) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn
		}
	}
	t.Fatalf("no func decl in %q", src)
	return nil
}
