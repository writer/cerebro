package noidentityemail

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `forbid direct email-field reads from mcpoauth.Identity

OAuth identity email is a trust boundary. Callers must use the typed
VerifiedEmail, ContactEmail, or PrincipalSubject methods so unverified email
claims cannot become token subjects or entitlement authority.`

var Analyzer = &analysis.Analyzer{
	Name:     "noidentityemail",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.FuncDecl)(nil)}, func(n ast.Node) {
		fn := n.(*ast.FuncDecl)
		if fn.Body == nil || isTestFile(pass, fn.Pos()) {
			return
		}
		allowDirectEmailField := isIdentityAccessor(pass, fn)
		allowVerifiedEmailLiteral := isVerifiedEmailConstructor(pass, fn)
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if lit, ok := node.(*ast.CompositeLit); ok {
				if !allowVerifiedEmailLiteral && isMCPOAuthVerifiedEmail(pass.TypesInfo.TypeOf(lit)) {
					pass.Report(analysis.Diagnostic{
						Pos:     lit.Pos(),
						End:     lit.End(),
						Message: "direct mcpoauth.VerifiedEmail construction bypasses email verification; use NewVerifiedEmail",
					})
				}
				return true
			}
			sel, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if !isIdentityEmailField(sel.Sel.Name) {
				return true
			}
			if allowDirectEmailField {
				return true
			}
			if !isMCPOAuthIdentity(pass.TypesInfo.TypeOf(sel.X)) {
				return true
			}
			pass.Report(analysis.Diagnostic{
				Pos:     sel.Pos(),
				End:     sel.End(),
				Message: "direct mcpoauth.Identity email field read bypasses verified-email authority boundary; use VerifiedEmail(), ContactEmail(), or PrincipalSubject()",
			})
			return true
		})
	})
	return nil, nil
}

func isIdentityEmailField(name string) bool {
	switch name {
	case "email", "Email", "EmailVerified":
		return true
	default:
		return false
	}
}

func isIdentityAccessor(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	if pass == nil || pass.Pkg == nil || fn == nil || fn.Recv == nil {
		return false
	}
	if pass.Pkg.Path() != "github.com/writer/cerebro/internal/mcpoauth" {
		return false
	}
	switch fn.Name.Name {
	case "VerifiedEmail", "ContactEmail":
		return true
	default:
		return false
	}
}

func isVerifiedEmailConstructor(pass *analysis.Pass, fn *ast.FuncDecl) bool {
	if pass == nil || pass.Pkg == nil || fn == nil {
		return false
	}
	return pass.Pkg.Path() == "github.com/writer/cerebro/internal/mcpoauth" && fn.Name.Name == "NewVerifiedEmail"
}

func isMCPOAuthIdentity(t types.Type) bool {
	return isMCPOAuthNamedType(t, "Identity")
}

func isMCPOAuthVerifiedEmail(t types.Type) bool {
	return isMCPOAuthNamedType(t, "VerifiedEmail")
}

func isMCPOAuthNamedType(t types.Type, name string) bool {
	t = types.Unalias(t)
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Name() == name && strings.HasSuffix(named.Obj().Pkg().Path(), "/internal/mcpoauth")
}

func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
