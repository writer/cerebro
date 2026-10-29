package requirements

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// requirementsGoImportPrefixes maps a recognized SDK import path prefix to
// its provider. The service name is derived from the remainder of the
// import path. Only these two SDK families are in the documented closed
// subset.
var requirementsGoImportPrefixes = []struct {
	prefix   string
	provider ci.Provider
}{
	{prefix: "github.com/aws/aws-sdk-go-v2/service/", provider: ci.AWS},
	{prefix: "cloud.google.com/go/", provider: ci.GCP},
	{prefix: "google.golang.org/api/", provider: ci.GCP},
}

// requirementsGoSafeImportPaths are standard-library import paths a file may
// call into without blocking closed-world completeness. Matching is against
// the import's canonical PATH, never its local alias: `import fmt
// "attacker.example/sdk"` must never be treated as safe just because the
// file happens to call it "fmt".
var requirementsGoSafeImportPaths = map[string]bool{
	"fmt": true, "errors": true, "context": true, "strings": true,
	"strconv": true, "time": true, "sort": true, "bytes": true,
	"encoding/json": true, "log": true, "math": true, "unicode": true,
	"path": true, "path/filepath": true, "regexp": true, "sync": true,
	"io": true, "bufio": true, "unicode/utf8": true, "log/slog": true,
}

// requirementsGoSafeImportPathPrefixes are non-stdlib import paths known to
// carry no cloud-identity-relevant API calls of their own (pure config/type/
// pointer-boxing helpers such as aws.String/aws.Config), so calling into
// them does not block closed-world completeness. The AWS SDK v2 config
// loader is included: config.LoadDefaultConfig(...) and its With* options
// assemble a credential chain, but the resulting *trust* is governed
// separately (who the chain resolves to assume), never by this role's own
// permission policy, so bootstrapping it is never itself an IAM-relevant
// call (see ci-impl-context's config.LoadDefaultConfig bound).
var requirementsGoSafeImportPathPrefixes = []string{
	"github.com/aws/aws-sdk-go-v2/aws",
	"github.com/aws/aws-sdk-go-v2/config",
}

func requirementsGoImportIsSafe(importPath string) bool {
	if requirementsGoSafeImportPaths[importPath] {
		return true
	}
	for _, prefix := range requirementsGoSafeImportPathPrefixes {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

// requirementsGoBuiltinFuncs never block completeness.
var requirementsGoBuiltinFuncs = map[string]bool{
	"len": true, "cap": true, "make": true, "append": true, "new": true,
	"panic": true, "recover": true, "close": true, "copy": true,
	"delete": true, "print": true, "println": true, "min": true, "max": true,
}

// requirementsGoGCPServiceAccessors are the PROVEN pure fluent-accessor
// method names, keyed by GCP service namespace. A method here is verified
// (per the official SDK surface / GcpIdentityEvidence's cited method
// reference) to only construct a local handle/reference — it never itself
// performs an API call. This is deliberately per-service, never global: a
// bare name like "Query" is a pure builder for bigquery
// (client.Query(sql).Read(ctx)), but is a REAL terminal operation for other
// services (e.g. a direct client.Query(ctx, stmt) call), so treating it as
// a universal accessor would silently hide a real cloud operation. A
// service with no entry here (secretmanager, kms, ...) has no proven
// accessor: every call on its client is either the real operation itself
// or — if chained through something unrecognized — explicitly flagged
// rather than guessed.
//
// firestore (Collection/Doc), logging (Logger), and spanner (Single) are
// each proven pure handle constructors per their real client source
// (firestore.Client.Collection/Doc, logging.Client.Logger,
// spanner.Client.Single all return a local reference with no RPC); the
// terminal call reached through them (Doc.Get, Logger.Log, Single.Query,
// ...) is recorded with a qualified "<Accessor>.<Method>" token exactly
// like the storage/bigquery/pubsub chains below.
var requirementsGoGCPServiceAccessors = map[string]map[string]bool{
	"storage":   {"Bucket": true, "Object": true},
	"bigquery":  {"Dataset": true, "Table": true, "Query": true},
	"pubsub":    {"Topic": true, "Subscription": true},
	"firestore": {"Doc": true, "Collection": true},
	"logging":   {"Logger": true},
	"spanner":   {"Single": true},
}

func requirementsGoGCPIsAccessor(service, method string) bool {
	return requirementsGoGCPServiceAccessors[service][method]
}

// requirementsGoGCPHandleServices are the GCP service namespaces whose
// fluent sub-handle types are known to expose colliding bare method names
// across different receiver types (storage BucketHandle vs ObjectHandle,
// bigquery Dataset vs Table vs Query), so a bare `client.Method(...)` call
// there — with no qualifying accessor immediately before it — is ambiguous
// and never positively promoted. Flat-API GCP services (secretmanager, kms,
// logging, datastore, ...) are deliberately NOT in this set: their whole
// SDK surface has no such collision, so a bare client method call there is
// a confident positive match, exactly like AWS.
var requirementsGoGCPHandleServices = map[string]bool{
	"storage":  true,
	"bigquery": true,
}

// requirementsGoResultKindLifecycle maps a tracked SDK-derived result/
// handle object's kind (see requirementsGoHandleReturningCalls) to the
// single documented non-IAM lifecycle/control method recognized on it. Any
// other bare call reached directly on such a var is outside the documented
// closed subset and blocks completeness rather than being guessed at,
// since this package never performs general interprocedural/type analysis.
var requirementsGoResultKindLifecycle = map[string]string{
	"reader":        "Close",
	"writer":        "Close",
	"iterator":      "Next",
	"publishresult": "Get",
}

// requirementsGoHandleReturn identifies one already-recorded SDK operation
// call (by the exact provider/service/token requirementsGoFileContext
// recordOperation would use) whose documented Go SDK return type is itself
// a tracked result/handle object — never a new service client — exposing
// exactly one further non-IAM lifecycle/control method.
type requirementsGoHandleReturn struct {
	provider ci.Provider
	service  string
	token    string
}

// requirementsGoHandleReturningCalls lists the proven handle-returning
// calls: GCS NewReader/NewWriter return an io.Reader/Writer-shaped type
// whose only further documented call this package tracks is Close; GCS
// Bucket.Objects returns an *ObjectIterator whose only tracked further call
// is Next; Pub/Sub Topic.Publish returns a *PublishResult whose only
// tracked further call is Get. Anything assigned from a call not listed
// here stays untracked, so an unrecognized follow-up call on it still
// blocks completeness exactly as before.
var requirementsGoHandleReturningCalls = map[requirementsGoHandleReturn]string{
	{ci.GCP, "storage", "Object.NewReader"}: "reader",
	{ci.GCP, "storage", "Object.NewWriter"}: "writer",
	{ci.GCP, "storage", "Bucket.Objects"}:   "iterator",
	{ci.GCP, "pubsub", "Topic.Publish"}:     "publishresult",
}

// requirementsGoPaginatorConstructorPattern recognizes the AWS SDK v2
// `New<Operation>Paginator` constructor shape (e.g. NewListBucketsPaginator,
// NewListObjectsV2Paginator). AWS's own primary API documentation
// recommends this shape over raw pagination tokens for every paginated
// list/describe operation, so it is a first-class recognized constructor —
// not a generic service client — carrying the single real operation its
// NextPage(ctx) calls perform.
var requirementsGoPaginatorConstructorPattern = regexp.MustCompile(`^New(.+)Paginator$`)

// requirementsGoS3PlainBucketNamePattern matches a syntactically valid
// plain S3 bucket name (lowercase letters, digits, dots, hyphens; 3-63
// chars; must start and end with a letter or digit). This is deliberately
// narrower than full AWS bucket-naming validation (consecutive dots,
// IP-address-shaped names, ...): it only needs to reject the documented
// non-bucket-name forms the resource builder must never prefix with
// "arn:aws:s3:::" (see requirementsGoIsPlainS3BucketName).
var requirementsGoS3PlainBucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// requirementsGoIsPlainS3BucketName reports whether name is syntactically a
// plain S3 bucket name — never an access-point ARN, an access-point alias,
// a directory-bucket name, or an Outposts identifier, all of which are
// also documented-valid values for the GetObject `Bucket` field but have a
// completely different resource-ARN shape that must never be built by
// simply prefixing "arn:aws:s3:::".
func requirementsGoIsPlainS3BucketName(name string) bool {
	if name == "" || strings.HasPrefix(name, "arn:") {
		return false
	}
	// Access-point alias: "<name>-<account-alias>-s3alias".
	if strings.HasSuffix(name, "-s3alias") {
		return false
	}
	// Directory bucket: "<base>--<zone-id>--x-s3".
	if strings.HasSuffix(name, "--x-s3") {
		return false
	}
	return requirementsGoS3PlainBucketNamePattern.MatchString(name)
}

func requirementsGoImportService(importPath string) (ci.Provider, string, bool) {
	for _, candidate := range requirementsGoImportPrefixes {
		if strings.HasPrefix(importPath, candidate.prefix) {
			rest := strings.Trim(strings.TrimPrefix(importPath, candidate.prefix), "/")
			if rest == "" {
				return "", "", false
			}
			return candidate.provider, strings.SplitN(rest, "/", 2)[0], true
		}
	}
	return "", "", false
}

// requirementsGoClientVar is one lexically-scoped binding tracked by the
// scope walker. A plain tracked SDK client has provider/service set.
// paginatorOp, when non-empty, means the var is an AWS `*Paginator` value
// (see requirementsGoPaginatorConstructorPattern) rather than a service
// client: only NextPage/HasMorePages are recognized on it. resultKind, when
// non-empty, means the var is a non-client SDK-derived result/handle object
// (see requirementsGoHandleReturningCalls): only its one documented
// lifecycle/control method (requirementsGoResultKindLifecycle) is
// recognized on it. At most one of paginatorOp/resultKind is ever set.
type requirementsGoClientVar struct {
	provider    ci.Provider
	service     string
	paginatorOp string
	resultKind  string
}

// requirementsGoBinding is one scope-stack entry: tracked=true means name
// is a tracked requirementsGoClientVar at this exact scope; tracked=false
// is an explicit shadow/invalidation marker — written whenever a name is
// (re)declared or reassigned from something that is NOT a recognized
// tracked value — that stops lookup from falling through to an outer
// scope's (possibly tracked) binding of the same name.
type requirementsGoBinding struct {
	clientVar requirementsGoClientVar
	tracked   bool
}

// requirementsGoScope is one lexical scope in the scope-stack used to track
// SDK client/paginator/result-handle variable bindings with real Go block
// scoping: a name introduced in an inner block shadows (and never leaks
// out past) the same name in an outer scope, and a non-constructor
// reassignment invalidates whatever the name used to be bound to, instead
// of a single function-wide map that is never invalidated or restored.
type requirementsGoScope struct {
	parent *requirementsGoScope
	vars   map[string]requirementsGoBinding
}

func requirementsGoNewScope(parent *requirementsGoScope) *requirementsGoScope {
	return &requirementsGoScope{parent: parent, vars: map[string]requirementsGoBinding{}}
}

// lookup returns the tracked client var bound to name (if any), plus two
// distinct booleans: tracked reports whether that binding is currently a
// usable SDK client/paginator/result value; present reports whether name
// is bound in the scope stack AT ALL (tracked, or an explicit untracked
// shadow/invalidation marker). present=false means name is genuinely
// absent from every visible scope — only then may a caller fall back to
// treating it as a Go builtin, a same-file function, or an import package
// alias; present=true with tracked=false means name is a local shadow of
// whatever it would otherwise mean, and must never fall through to those
// meanings just because the name collides.
func (s *requirementsGoScope) lookup(name string) (clientVar requirementsGoClientVar, tracked bool, present bool) {
	for sc := s; sc != nil; sc = sc.parent {
		if b, ok := sc.vars[name]; ok {
			return b.clientVar, b.tracked, true
		}
	}
	return requirementsGoClientVar{}, false, false
}

// define binds name in the CURRENT (innermost) scope, matching Go `:=`/
// local `var` semantics: it always introduces or shadows a binding at this
// exact block, regardless of what an outer scope holds for the same name.
func (s *requirementsGoScope) define(name string, binding requirementsGoBinding) {
	s.vars[name] = binding
}

// assign updates an existing binding's value wherever it is currently
// visible (searching outward), matching Go `=` reassignment semantics
// (mutating the existing variable in place rather than shadowing it); if
// the name is not yet tracked anywhere, it behaves like a fresh definition
// in the current scope.
func (s *requirementsGoScope) assign(name string, binding requirementsGoBinding) {
	for sc := s; sc != nil; sc = sc.parent {
		if _, ok := sc.vars[name]; ok {
			sc.vars[name] = binding
			return
		}
	}
	s.vars[name] = binding
}

// requirementsGoSeedFuncScope binds every receiver, parameter, and named
// result of a function signature as an explicit untracked shadow in scope
// (define, matching Go's own function-scope introduction semantics),
// BEFORE the function body is walked. Without this, a parameter (or
// receiver, or named result) that happens to share a name with a
// package-level tracked SDK client would never appear in the scope stack
// at all, so lookup would silently fall through past the function's own
// local meaning of that name to the unrelated package-level client —
// promoting operations against a value the function never actually
// touches.
func requirementsGoSeedFuncScope(scope *requirementsGoScope, recv *ast.FieldList, typ *ast.FuncType) {
	seed := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				if name.Name != "_" {
					scope.define(name.Name, requirementsGoBinding{})
				}
			}
		}
	}
	seed(recv)
	if typ != nil {
		seed(typ.Params)
		seed(typ.Results)
	}
}

// requirementsGoFileContext bundles the per-file state shared by every call
// inspected in it, so inner helpers do not need long parameter lists.
type requirementsGoFileContext struct {
	fset          *token.FileSet
	lines         []string
	path          string
	digest        string
	aliasToImport map[string]string
	localFuncs    map[string]bool
	ops           *[]StaticOperation
	fileSupported *bool
	gaps          *[]ci.Gap
}

func (c *requirementsGoFileContext) blockCompleteness(pos, end token.Pos, code, message string) {
	*c.fileSupported = false
	startLine, endLine := c.fset.Position(pos).Line, c.fset.Position(end).Line
	gap := ci.Gap{Code: code, Scope: c.path, Message: message}
	if startLine >= 1 && endLine >= startLine {
		gap.References = []ci.Reference{{Path: c.path, StartLine: startLine, EndLine: endLine, Digest: c.digest}}
	}
	*c.gaps = append(*c.gaps, gap)
}

func (c *requirementsGoFileContext) recordOperation(call *ast.CallExpr, provider ci.Provider, service, tok string, chainFields map[string]string, scope *requirementsGoScope) {
	if !ast.IsExported(tok) {
		return
	}
	startLine, endLine := c.fset.Position(call.Pos()).Line, c.fset.Position(call.End()).Line
	quote, ok := requirementsQuoteLines(c.lines, startLine, endLine)
	if !ok {
		return
	}
	var resources []string
	switch provider {
	case ci.AWS:
		if res, ok := requirementsGoBuildAWSResource(service, requirementsGoExtractAWSFields(call, c.aliasToImport, scope)); ok {
			resources = []string{res}
		}
	case ci.GCP:
		if res, ok := requirementsGoBuildGCPResource(service, chainFields); ok {
			resources = []string{res}
		}
	}
	*c.ops = append(*c.ops, StaticOperation{
		Provider: provider, Service: service, Token: tok,
		Path: c.path, StartLine: startLine, EndLine: endLine, Quote: quote,
		Resources: resources,
	})
}

// requirementsExtractGoFile parses one Go source file and extracts direct
// SDK call sites under closed-world analysis: every call reachable from a
// top-level function or a package-level variable initializer must resolve
// to a tracked SDK client (directly, or through a chain whose every
// intermediate link is a PROVEN pure accessor for that exact service — see
// requirementsGoGCPServiceAccessors), a declared same-file function (itself
// analyzed), a Go builtin, or an allowlisted standard-library package;
// anything else — including a blank/dot import of an unapproved package,
// whose init-time side effects run whether or not anything in the file
// ever uses it, a chain through an unrecognized intermediate method that
// could itself be a real cloud operation, or any callee expression form
// other than a plain identifier or selector (parenthesized, indexed/
// generic, a called function literal, a method value, ...) — is outside
// the documented closed subset and blocks completeness for the file. ok is
// false whenever the file could not be parsed, or any construct in it
// could not be closed over.
//
// Variable tracking uses a real lexical scope stack (requirementsGoScope):
// a name introduced in an inner block shadows the same name in an outer
// scope for exactly that block, and any non-constructor
// reassignment/redeclaration invalidates the tracked binding rather than
// leaving a stale one visible to later code.
func requirementsExtractGoFile(path string, content []byte) (ops []StaticOperation, gaps []ci.Gap, ok bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, 0)
	if err != nil {
		return nil, []ci.Gap{{Code: GapGoParseError, Scope: path, Message: "go source could not be parsed: " + err.Error()}}, false
	}

	aliasToImport := map[string]string{}
	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			segments := strings.Split(importPath, "/")
			alias = segments[len(segments)-1]
		}
		aliasToImport[alias] = importPath
	}
	localFuncs := map[string]bool{}
	for _, decl := range file.Decls {
		if fn, isFn := decl.(*ast.FuncDecl); isFn {
			localFuncs[fn.Name.Name] = true
		}
	}

	fileSupported := true
	ctx := &requirementsGoFileContext{
		fset: fset, lines: requirementsFileLines(content), path: path,
		digest: ci.Digest(content), aliasToImport: aliasToImport, localFuncs: localFuncs,
		ops: &ops, fileSupported: &fileSupported, gaps: &gaps,
	}

	// A blank/dot import of anything outside the recognized SDK families or
	// the stdlib/aws-core safe list executes unreviewed init-time side
	// effects regardless of whether the file ever references it (Go would
	// reject an unused *named* import at compile time, so this specifically
	// targets the one shape that bypasses that check).
	for _, imp := range file.Imports {
		if imp.Name == nil || (imp.Name.Name != "_" && imp.Name.Name != ".") {
			continue
		}
		importPath := strings.Trim(imp.Path.Value, `"`)
		if requirementsGoImportIsSafe(importPath) {
			continue
		}
		if _, _, isSDK := requirementsGoImportService(importPath); isSDK {
			continue
		}
		ctx.blockCompleteness(imp.Pos(), imp.End(), GapUnreviewablePackageInit, "blank/dot import of \""+importPath+"\" executes unreviewed init-time side effects outside the documented closed subset")
	}

	// Package-level variable initializers run at program-init time
	// regardless of whether the resulting variable is ever referenced, so
	// they get the same closed-world treatment as a function body: a
	// recognized SDK constructor binds a client var every function can use,
	// but its own argument expressions / nested function literals still run
	// at init time too and are inspected exactly like any other call site —
	// only the recognized outer `pkg.NewXxx(...)` constructor call itself
	// is suppressed; any other call blocks completeness.
	packageVars := map[string]requirementsGoClientVar{}
	for _, decl := range file.Decls {
		genDecl, isGen := decl.(*ast.GenDecl)
		if !isGen || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, isValueSpec := spec.(*ast.ValueSpec)
			if !isValueSpec {
				continue
			}
			for i, value := range valueSpec.Values {
				if provider, service, paginatorOp, isClient := requirementsGoConstructorCall(value, aliasToImport, nil); isClient {
					if i < len(valueSpec.Names) {
						packageVars[valueSpec.Names[i].Name] = requirementsGoClientVar{provider: provider, service: service, paginatorOp: paginatorOp}
					}
					if callExpr, isCallExpr := value.(*ast.CallExpr); isCallExpr {
						argScope := requirementsGoNewScope(nil)
						for _, arg := range callExpr.Args {
							ctx.walkExpr(arg, argScope)
						}
					}
					continue
				}
				ast.Inspect(value, func(inner ast.Node) bool {
					if call, isCall := inner.(*ast.CallExpr); isCall {
						ctx.blockCompleteness(call.Pos(), call.End(), GapUnreviewablePackageInit, "package-level variable initializer performs a call that cannot be closed over statically; it runs at program-init time regardless of whether the variable is ever used")
					}
					return true
				})
			}
		}
	}

	rootScope := requirementsGoNewScope(nil)
	for name, v := range packageVars {
		rootScope.define(name, requirementsGoBinding{clientVar: v, tracked: true})
	}

	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || fn.Body == nil {
			continue
		}
		fnScope := requirementsGoNewScope(rootScope)
		requirementsGoSeedFuncScope(fnScope, fn.Recv, fn.Type)
		ctx.walkBlock(fn.Body, fnScope)
	}
	return ops, gaps, fileSupported
}

// walkBlock pushes a new child scope for one Go block and walks its
// statements in it, so any binding introduced inside never leaks past the
// block's closing brace.
func (c *requirementsGoFileContext) walkBlock(block *ast.BlockStmt, scope *requirementsGoScope) {
	if block == nil {
		return
	}
	inner := requirementsGoNewScope(scope)
	for _, stmt := range block.List {
		c.walkStmt(stmt, inner)
	}
}

func (c *requirementsGoFileContext) walkCaseClause(clause *ast.CaseClause, scope *requirementsGoScope) {
	inner := requirementsGoNewScope(scope)
	for _, e := range clause.List {
		c.walkExpr(e, inner)
	}
	for _, st := range clause.Body {
		c.walkStmt(st, inner)
	}
}

// walkStmt dispatches one statement, pushing a fresh child scope for every
// Go construct that introduces its own lexical scope (if/for/range/switch
// init-and-body, select comm-clauses, case clauses, function literals), so
// variable tracking matches real Go block scoping rather than a single
// function-wide map.
func (c *requirementsGoFileContext) walkStmt(stmt ast.Stmt, scope *requirementsGoScope) {
	switch s := stmt.(type) {
	case nil:
		return
	case *ast.BlockStmt:
		c.walkBlock(s, scope)
	case *ast.ExprStmt:
		c.walkExpr(s.X, scope)
	case *ast.AssignStmt:
		c.walkAssign(s, scope)
	case *ast.DeclStmt:
		c.walkDecl(s.Decl, scope)
	case *ast.IfStmt:
		inner := requirementsGoNewScope(scope)
		c.walkStmt(s.Init, inner)
		c.walkExpr(s.Cond, inner)
		c.walkBlock(s.Body, inner)
		c.walkStmt(s.Else, inner)
	case *ast.ForStmt:
		inner := requirementsGoNewScope(scope)
		c.walkStmt(s.Init, inner)
		c.walkExpr(s.Cond, inner)
		c.walkStmt(s.Post, inner)
		c.walkBlock(s.Body, inner)
	case *ast.RangeStmt:
		inner := requirementsGoNewScope(scope)
		c.walkExpr(s.X, inner)
		if s.Tok == token.DEFINE {
			if key, isIdent := s.Key.(*ast.Ident); isIdent && key.Name != "_" {
				inner.define(key.Name, requirementsGoBinding{})
			}
			if val, isIdent := s.Value.(*ast.Ident); isIdent && val.Name != "_" {
				inner.define(val.Name, requirementsGoBinding{})
			}
		}
		c.walkBlock(s.Body, inner)
	case *ast.SwitchStmt:
		inner := requirementsGoNewScope(scope)
		c.walkStmt(s.Init, inner)
		c.walkExpr(s.Tag, inner)
		if s.Body != nil {
			for _, clause := range s.Body.List {
				if cc, isCase := clause.(*ast.CaseClause); isCase {
					c.walkCaseClause(cc, inner)
				}
			}
		}
	case *ast.TypeSwitchStmt:
		inner := requirementsGoNewScope(scope)
		c.walkStmt(s.Init, inner)
		c.walkStmt(s.Assign, inner)
		if s.Body != nil {
			for _, clause := range s.Body.List {
				if cc, isCase := clause.(*ast.CaseClause); isCase {
					c.walkCaseClause(cc, inner)
				}
			}
		}
	case *ast.SelectStmt:
		if s.Body == nil {
			return
		}
		for _, clause := range s.Body.List {
			comm, isComm := clause.(*ast.CommClause)
			if !isComm {
				continue
			}
			inner := requirementsGoNewScope(scope)
			c.walkStmt(comm.Comm, inner)
			for _, st := range comm.Body {
				c.walkStmt(st, inner)
			}
		}
	case *ast.ReturnStmt:
		for _, r := range s.Results {
			c.walkExpr(r, scope)
		}
	case *ast.GoStmt:
		c.walkCall(s.Call, scope)
	case *ast.DeferStmt:
		c.walkCall(s.Call, scope)
	case *ast.LabeledStmt:
		c.walkStmt(s.Stmt, scope)
	case *ast.SendStmt:
		c.walkExpr(s.Chan, scope)
		c.walkExpr(s.Value, scope)
	case *ast.IncDecStmt:
		c.walkExpr(s.X, scope)
	}
}

// walkAssign binds the LHS of one assignment/short-variable-declaration
// statement from the evaluated RHS. A single-RHS, multi-LHS assignment
// (`x, err := f()`, the dominant Go error-handling idiom) binds only the
// first name from f()'s evaluation and leaves the rest explicitly
// untracked; an N-LHS/N-RHS assignment evaluates and binds each pair
// positionally. Any RHS that is not itself a recognized constructor call or
// a known handle-returning SDK call explicitly invalidates whatever the
// target name used to be bound to (shadow/reassignment never silently
// leaves a stale tracked binding visible).
func (c *requirementsGoFileContext) walkAssign(assign *ast.AssignStmt, scope *requirementsGoScope) {
	if len(assign.Rhs) == 1 && len(assign.Lhs) >= 1 {
		binding := c.evalRHS(assign.Rhs[0], scope)
		c.bindAssignTarget(assign.Lhs[0], assign.Tok, binding, scope)
		for _, extra := range assign.Lhs[1:] {
			c.bindAssignTarget(extra, assign.Tok, requirementsGoBinding{}, scope)
		}
		return
	}
	n := len(assign.Lhs)
	if len(assign.Rhs) < n {
		n = len(assign.Rhs)
	}
	bindings := make([]requirementsGoBinding, len(assign.Rhs))
	for i, rhs := range assign.Rhs {
		bindings[i] = c.evalRHS(rhs, scope)
	}
	for i := range n {
		c.bindAssignTarget(assign.Lhs[i], assign.Tok, bindings[i], scope)
	}
	for i := n; i < len(assign.Lhs); i++ {
		c.bindAssignTarget(assign.Lhs[i], assign.Tok, requirementsGoBinding{}, scope)
	}
}

func (c *requirementsGoFileContext) bindAssignTarget(lhs ast.Expr, tok token.Token, binding requirementsGoBinding, scope *requirementsGoScope) {
	ident, isIdent := lhs.(*ast.Ident)
	if !isIdent {
		// An indexed/selector/etc. assignment target (`m[k] = v`,
		// `s.Field = v`) can itself embed a call — e.g. `m[client.Publish(
		// ctx, msg)] = v` — that must still be walked for SDK calls even
		// though the target as a whole is never a trackable plain name.
		c.walkExpr(lhs, scope)
		return
	}
	if ident.Name == "_" {
		return
	}
	if tok == token.DEFINE {
		scope.define(ident.Name, binding)
	} else {
		scope.assign(ident.Name, binding)
	}
}

// walkDecl handles a local `var` declaration exactly like an assignment:
// each named value is evaluated (and any embedded call inspected) and
// bound if it is a recognized constructor or known handle-returning call;
// a name with no initializer, or an unsupported-shape multi-value decl's
// extra names, are explicitly left untracked.
func (c *requirementsGoFileContext) walkDecl(decl ast.Decl, scope *requirementsGoScope) {
	genDecl, isGen := decl.(*ast.GenDecl)
	if !isGen || genDecl.Tok != token.VAR {
		return
	}
	for _, spec := range genDecl.Specs {
		valueSpec, isValueSpec := spec.(*ast.ValueSpec)
		if !isValueSpec {
			continue
		}
		switch {
		case len(valueSpec.Values) == 0:
			for _, name := range valueSpec.Names {
				if name.Name != "_" {
					scope.define(name.Name, requirementsGoBinding{})
				}
			}
		case len(valueSpec.Values) == len(valueSpec.Names):
			for i, value := range valueSpec.Values {
				binding := c.evalRHS(value, scope)
				if valueSpec.Names[i].Name != "_" {
					scope.define(valueSpec.Names[i].Name, binding)
				}
			}
		default:
			// A single multi-return initializer (var x, err = f()).
			binding := c.evalRHS(valueSpec.Values[0], scope)
			for i, name := range valueSpec.Names {
				b := requirementsGoBinding{}
				if i == 0 {
					b = binding
				}
				if name.Name != "_" {
					scope.define(name.Name, b)
				}
			}
		}
	}
}

// evalRHS walks one assignment/declaration RHS expression for embedded
// calls and determines what (if anything) the resulting value should be
// tracked as: a recognized SDK client/paginator constructor (its own
// argument expressions are still walked for embedded calls — only the
// recognized outer constructor call itself is suppressed), or a known
// handle-returning SDK operation call whose only documented further use is
// one lifecycle/control method. Anything else is walked for embedded calls
// and left untracked.
func (c *requirementsGoFileContext) evalRHS(rhs ast.Expr, scope *requirementsGoScope) requirementsGoBinding {
	call, isCall := rhs.(*ast.CallExpr)
	if !isCall {
		c.walkExpr(rhs, scope)
		return requirementsGoBinding{}
	}
	if provider, service, paginatorOp, isClient := requirementsGoConstructorCall(call, c.aliasToImport, scope); isClient {
		for _, arg := range call.Args {
			c.walkExpr(arg, scope)
		}
		return requirementsGoBinding{clientVar: requirementsGoClientVar{provider: provider, service: service, paginatorOp: paginatorOp}, tracked: true}
	}
	provider, service, tok, recorded := c.walkCall(call, scope)
	if recorded {
		if kind, known := requirementsGoHandleReturningCalls[requirementsGoHandleReturn{provider, service, tok}]; known {
			return requirementsGoBinding{clientVar: requirementsGoClientVar{resultKind: kind}, tracked: true}
		}
	}
	return requirementsGoBinding{}
}

// walkExpr recurses into every sub-expression position that could contain a
// call, including inside composite literal values (both keys and values —
// an indexed/map-keyed expression like `m[client.Publish(ctx, msg)]` must
// never be skipped just because it is a key, not a value) and function
// literal bodies, so a call buried in an argument, a condition, a struct
// literal field, or an immediately-invoked function literal is never
// silently skipped just because it is not itself a top-level statement.
func (c *requirementsGoFileContext) walkExpr(expr ast.Expr, scope *requirementsGoScope) {
	switch e := expr.(type) {
	case nil:
		return
	case *ast.CallExpr:
		c.walkCall(e, scope)
	case *ast.FuncLit:
		litScope := requirementsGoNewScope(scope)
		requirementsGoSeedFuncScope(litScope, nil, e.Type)
		c.walkBlock(e.Body, litScope)
	case *ast.BinaryExpr:
		c.walkExpr(e.X, scope)
		c.walkExpr(e.Y, scope)
	case *ast.UnaryExpr:
		c.walkExpr(e.X, scope)
	case *ast.ParenExpr:
		c.walkExpr(e.X, scope)
	case *ast.StarExpr:
		c.walkExpr(e.X, scope)
	case *ast.SelectorExpr:
		c.walkExpr(e.X, scope)
	case *ast.IndexExpr:
		c.walkExpr(e.X, scope)
		c.walkExpr(e.Index, scope)
	case *ast.IndexListExpr:
		c.walkExpr(e.X, scope)
		for _, idx := range e.Indices {
			c.walkExpr(idx, scope)
		}
	case *ast.SliceExpr:
		c.walkExpr(e.X, scope)
		c.walkExpr(e.Low, scope)
		c.walkExpr(e.High, scope)
		c.walkExpr(e.Max, scope)
	case *ast.TypeAssertExpr:
		c.walkExpr(e.X, scope)
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			c.walkExpr(elt, scope)
		}
	case *ast.KeyValueExpr:
		c.walkExpr(e.Key, scope)
		c.walkExpr(e.Value, scope)
	}
}

// walkCall always walks a call's argument expressions first (so a call
// embedded in an argument — including inside a recognized constructor's own
// arguments — is never skipped), then dispatches on the callee expression
// form. Only a plain identifier (builtin/same-file function/unresolved) or
// a plain selector (`recv.Method`) are in the documented closed subset;
// every other callee form — parenthesized (`(get)(...)`), indexed/generic
// instantiation, a directly-invoked function literal, or anything else — is
// an unsupported dynamic call that blocks completeness, never silently
// accepted. The returned (provider, service, token, recorded) identify the
// SDK operation this exact call resolved to, when it did, so a caller
// binding a variable from this call's return value (evalRHS) can recognize
// a known handle-returning call.
func (c *requirementsGoFileContext) walkCall(call *ast.CallExpr, scope *requirementsGoScope) (ci.Provider, string, string, bool) {
	for _, arg := range call.Args {
		c.walkExpr(arg, scope)
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if _, _, present := scope.lookup(fun.Name); present {
			// A local binding shadows whatever "fun.Name" would otherwise
			// mean (a Go builtin or a same-file function) — e.g. `len :=
			// client.GetObject; len(ctx, input)`. Calling through it is a
			// method value / dynamic call this package never statically
			// resolves, and must never be silently treated as the
			// shadowed builtin or function just because the names
			// collide.
			c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call through \""+fun.Name+"\" which is a local binding shadowing a builtin/function name, not itself a resolvable static call")
			return "", "", "", false
		}
		if requirementsGoBuiltinFuncs[fun.Name] || c.localFuncs[fun.Name] {
			return "", "", "", false
		}
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call to unresolved identifier \""+fun.Name+"\" cannot be closed over statically")
		return "", "", "", false
	case *ast.SelectorExpr:
		return c.inspectSelectorCall(call, fun, scope)
	default:
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call through an unsupported callee expression form (parenthesized, indexed/generic-instantiated, a directly-invoked function literal, or otherwise not a plain identifier or selector) cannot be closed over statically")
		return "", "", "", false
	}
}

// requirementsGoChainLink is one `.Method("literal")` step walked out of a
// fluent chain expression, in the order encountered (root-to-leaf after
// requirementsGoWalkChain reverses its internal walk).
type requirementsGoChainLink struct {
	method string
	arg    string
}

// requirementsGoWalkChain walks a (possibly deeply nested) fluent chain
// expression back to its ultimate non-call root, returning the ordered
// sequence of intermediate links (root-to-leaf) plus whether the chain is
// structurally closed — every link is a plain `X.Method(...)` selector
// call, never e.g. an index or type-assertion expression. It makes no
// judgement about whether any link is a "safe" accessor; the caller
// resolves that per-service once the root is known. Every intermediate
// link's OWN argument expressions are walked here too (never only the
// chain's terminal call's arguments), so a real SDK call embedded inside a
// fluent-accessor argument — e.g. a Pub/Sub Publish passed into a Logging
// accessor's argument — is never silently skipped just because it sits
// inside one link's arguments rather than the chain's outermost call.
func (c *requirementsGoFileContext) walkChain(expr ast.Expr, scope *requirementsGoScope) (root ast.Expr, links []requirementsGoChainLink, closed bool) {
	var reversed []requirementsGoChainLink
	for {
		call, isCall := expr.(*ast.CallExpr)
		if !isCall {
			links = make([]requirementsGoChainLink, len(reversed))
			for i, l := range reversed {
				links[len(reversed)-1-i] = l
			}
			return expr, links, true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return nil, nil, false
		}
		link := requirementsGoChainLink{method: sel.Sel.Name}
		for _, arg := range call.Args {
			c.walkExpr(arg, scope)
		}
		if len(call.Args) == 1 {
			if value, ok := requirementsGoStringLiteral(call.Args[0], c.aliasToImport, scope); ok {
				link.arg = value
			}
		}
		reversed = append(reversed, link)
		expr = sel.X
	}
}

// inspectSelectorCall handles one `recv.Method(...)` call expression. recv
// is either a direct identifier (a tracked SDK client/paginator/result
// var, a known import path, or neither) or itself a call expression,
// meaning this call is one link in a fluent chain
// (client.Bucket("x").Object("y")). The returned tuple mirrors walkCall's:
// the exact (provider, service, token) a caller recorded an operation as,
// when it did.
func (c *requirementsGoFileContext) inspectSelectorCall(call *ast.CallExpr, sel *ast.SelectorExpr, scope *requirementsGoScope) (ci.Provider, string, string, bool) {
	if sel.Sel.Name == "MethodByName" {
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "MethodByName dynamic dispatch cannot be statically proven")
		return "", "", "", false
	}
	if ident, isIdent := sel.X.(*ast.Ident); isIdent {
		if ident.Name == "reflect" {
			c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "reflect-based dynamic dispatch cannot be statically proven")
			return "", "", "", false
		}
		clientVar, tracked, present := scope.lookup(ident.Name)
		if tracked {
			// Closing the client itself is a local lifecycle/control
			// operation, never IAM-relevant, regardless of provider or
			// service — including a GCP handle-collision service where a
			// bare call would otherwise be ambiguous.
			if sel.Sel.Name == "Close" && clientVar.resultKind == "" && clientVar.paginatorOp == "" {
				return "", "", "", false
			}
			if clientVar.resultKind != "" {
				if lifecycle, known := requirementsGoResultKindLifecycle[clientVar.resultKind]; known && sel.Sel.Name == lifecycle {
					return "", "", "", false
				}
				c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call \""+sel.Sel.Name+"\" on a tracked SDK result/handle object is outside its one documented lifecycle/control method")
				return "", "", "", false
			}
			if clientVar.paginatorOp != "" {
				switch sel.Sel.Name {
				case "HasMorePages":
					// Local pagination-loop control flow, never IAM-relevant.
					return "", "", "", false
				case "NextPage":
					c.recordOperation(call, clientVar.provider, clientVar.service, clientVar.paginatorOp, nil, scope)
					return clientVar.provider, clientVar.service, clientVar.paginatorOp, true
				}
				c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call \""+sel.Sel.Name+"\" on a paginator variable is outside the documented NextPage/HasMorePages subset")
				return "", "", "", false
			}
			if clientVar.provider == ci.GCP && requirementsGoGCPIsAccessor(clientVar.service, sel.Sel.Name) {
				// A proven pure accessor for this exact service (e.g.
				// client.Bucket("x")) only constructs a local handle; it
				// performs no API call, so there is nothing to record.
				return "", "", "", false
			}
			if clientVar.provider == ci.GCP && requirementsGoGCPHandleServices[clientVar.service] {
				// A bare call on a handle-collision service, with no
				// qualifying accessor, cannot be attributed to a specific
				// resource type (storage Bucket.Delete vs Object.Delete,
				// bigquery Table.Read vs Query.Read, ...).
				c.blockCompleteness(call.Pos(), call.End(), GapAmbiguousGCPOperation, "call \""+sel.Sel.Name+"\" directly on a "+clientVar.service+" client cannot be attributed to a specific resource type without a qualifying accessor immediately preceding it")
				return "", "", "", false
			}
			c.recordOperation(call, clientVar.provider, clientVar.service, sel.Sel.Name, nil, scope)
			return clientVar.provider, clientVar.service, sel.Sel.Name, true
		}
		if present {
			// ident is bound in the scope stack but not as a tracked SDK
			// value — a local variable (param, receiver, loop var, ...)
			// that shadows a package-level tracked client, a builtin, or
			// an import alias of the same name. It must never fall
			// through to the import-alias handling below just because the
			// names collide.
			c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call through \""+ident.Name+"\" which is a local binding shadowing a package-level identifier of the same name, not itself a tracked SDK client")
			return "", "", "", false
		}
		if importPath, isImport := c.aliasToImport[ident.Name]; isImport {
			if requirementsGoImportIsSafe(importPath) {
				return "", "", "", false
			}
			if _, _, isSDK := requirementsGoImportService(importPath); isSDK {
				if strings.HasPrefix(sel.Sel.Name, "New") {
					// A recognized `pkg.NewXxx(...)` constructor shape is
					// always in scope, whether or not its result was bound
					// to a tracked variable: requirementsGoConstructorCall
					// already handles the binding case on the AssignStmt
					// (or package-level ValueSpec) that wraps it; an unbound
					// constructor call simply produces no further
					// operations to find.
					return "", "", "", false
				}
				c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "package-level SDK call \""+ident.Name+"."+sel.Sel.Name+"\" is outside the documented client-variable-binding subset")
				return "", "", "", false
			}
			c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call through imported package \""+importPath+"\" is an unresolved wrapper that may itself perform cloud calls")
			return "", "", "", false
		}
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "call through unresolved receiver \""+ident.Name+"\" cannot be closed over statically")
		return "", "", "", false
	}
	// A chained call: walk back to its ultimate root expression.
	root, links, closed := c.walkChain(sel.X, scope)
	if !closed {
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "chained call root is not a resolvable selector chain")
		return "", "", "", false
	}
	rootIdent, isIdent := root.(*ast.Ident)
	if !isIdent {
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "chained call through an unresolved receiver expression cannot be closed over statically")
		return "", "", "", false
	}
	clientVar, bound, _ := scope.lookup(rootIdent.Name)
	if !bound {
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "chained call root \""+rootIdent.Name+"\" is not a tracked SDK client")
		return "", "", "", false
	}
	if clientVar.resultKind != "" || clientVar.paginatorOp != "" {
		c.blockCompleteness(call.Pos(), call.End(), GapUnsupportedDynamicCall, "chained call through a tracked SDK result/paginator handle is outside the documented subset")
		return "", "", "", false
	}
	chainFields := map[string]string{}
	if clientVar.provider == ci.GCP {
		// Every intermediate link must be a PROVEN accessor for this exact
		// service; an unrecognized one could itself be a real cloud
		// operation (or a different service's accessor entirely), and is
		// never silently assumed to be a harmless builder just because it
		// precedes another selector call.
		for _, link := range links {
			if !requirementsGoGCPIsAccessor(clientVar.service, link.method) {
				c.blockCompleteness(call.Pos(), call.End(), GapUnresolvedChainMethod, "chained call passes through \""+link.method+"\" which is not a proven pure accessor for "+clientVar.service+"; it may itself be a cloud operation and is never silently treated as safe")
				return "", "", "", false
			}
			if link.arg != "" {
				chainFields[link.method] = link.arg
			}
		}
		if requirementsGoGCPIsAccessor(clientVar.service, sel.Sel.Name) {
			// This call's own terminal method is itself just one more
			// proven accessor-chain link (e.g. the "Object" in
			// Bucket("x").Object("y")); nothing to record yet.
			return "", "", "", false
		}
	}
	tok := sel.Sel.Name
	if clientVar.provider == ci.GCP && len(links) > 0 {
		tok = links[len(links)-1].method + "." + sel.Sel.Name
	}
	c.recordOperation(call, clientVar.provider, clientVar.service, tok, chainFields, scope)
	return clientVar.provider, clientVar.service, tok, true
}

// requirementsGoExtractAWSFields extracts named literal fields (lowercased
// key) from any AWS-style input-struct literal argument on the call. These
// are raw candidate values only; requirementsGoBuildAWSResource alone
// decides whether they form a documented, unambiguous canonical resource.
func requirementsGoExtractAWSFields(call *ast.CallExpr, aliasToImport map[string]string, scope *requirementsGoScope) map[string]string {
	fields := map[string]string{}
	for _, arg := range call.Args {
		lit := arg
		if unary, isUnary := arg.(*ast.UnaryExpr); isUnary {
			lit = unary.X
		}
		composite, isComposite := lit.(*ast.CompositeLit)
		if !isComposite {
			continue
		}
		for _, elt := range composite.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				continue
			}
			key, isIdent := kv.Key.(*ast.Ident)
			if !isIdent {
				continue
			}
			if value, ok := requirementsGoStringLiteral(kv.Value, aliasToImport, scope); ok {
				fields[strings.ToLower(key.Name)] = value
			}
		}
	}
	return fields
}

// requirementsGoBuildAWSResource constructs a canonical AWS resource
// identifier only for a documented, unambiguous service/field mapping
// (currently S3 bucket/key -> an S3 object ARN), and only when the bucket
// field is a syntactically plain bucket name. Any other service, a missing
// bucket field, or a bucket value that is actually an access-point ARN,
// access-point alias, directory-bucket name, or Outposts identifier (all
// documented-valid `Bucket` forms with a completely different resource-ARN
// shape) returns false: the caller must stay wildcard-unknown rather than
// emit an invalid or misleading constructed ARN.
func requirementsGoBuildAWSResource(service string, fields map[string]string) (string, bool) {
	if service != "s3" {
		return "", false
	}
	bucket := fields["bucket"]
	if bucket == "" || !requirementsGoIsPlainS3BucketName(bucket) {
		return "", false
	}
	if key := fields["key"]; key != "" {
		return "arn:aws:s3:::" + bucket + "/" + key, true
	}
	return "arn:aws:s3:::" + bucket + "/*", true
}

// requirementsGoBuildGCPResource constructs a canonical GCS resource path
// only for the documented storage bucket/object mapping. Any other service,
// or a missing bucket field, returns false.
func requirementsGoBuildGCPResource(service string, fields map[string]string) (string, bool) {
	if service != "storage" {
		return "", false
	}
	bucket := fields["Bucket"]
	if bucket == "" {
		return "", false
	}
	if object := fields["Object"]; object != "" {
		return "projects/_/buckets/" + bucket + "/objects/" + object, true
	}
	return "projects/_/buckets/" + bucket, true
}

// requirementsGoStringLiteral resolves a plain string literal, or a call to
// the canonical `github.com/aws/aws-sdk-go-v2/aws` package's String
// pointer-boxing helper wrapping one, to its decoded value. Any other call
// — including a local helper that merely LOOKS like a transparent
// pass-through wrapper (e.g. `func bucketName(string) *string { return
// aws.String("real-bucket") }` ignoring its argument) — is never unwrapped:
// only the verified canonical aws.String import is trusted to be
// transparent, since this package performs no general interprocedural
// analysis that could otherwise prove a given local function's return
// value actually matches its literal argument. scope, when non-nil, is
// also consulted: a local binding that shadows the "aws" identifier at
// this point in the lexical scope (e.g. a parameter or local var named
// `aws`) is never the canonical import, regardless of what the file's
// import-alias table says about that name globally, so it is never
// trusted to narrow a resource.
func requirementsGoStringLiteral(expr ast.Expr, aliasToImport map[string]string, scope *requirementsGoScope) (string, bool) {
	switch v := expr.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		decoded, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return decoded, true
	case *ast.CallExpr:
		if len(v.Args) != 1 {
			return "", false
		}
		sel, isSel := v.Fun.(*ast.SelectorExpr)
		if !isSel {
			return "", false
		}
		pkgIdent, isIdent := sel.X.(*ast.Ident)
		if !isIdent || sel.Sel.Name != "String" {
			return "", false
		}
		if scope != nil {
			if _, _, present := scope.lookup(pkgIdent.Name); present {
				return "", false
			}
		}
		importPath, known := aliasToImport[pkgIdent.Name]
		if !known || importPath != "github.com/aws/aws-sdk-go-v2/aws" {
			return "", false
		}
		return requirementsGoStringLiteral(v.Args[0], aliasToImport, scope)
	}
	return "", false
}

// requirementsGoConstructorCall recognizes `pkg.NewXxx(...)` call
// expressions where pkg resolves (via the file's imports) to a recognized
// AWS/GCP SDK import path, returning the provider and service the
// resulting value binds. When the constructor name matches the AWS SDK v2
// `New<Operation>Paginator` shape, paginatorOp is the captured <Operation>
// (see requirementsGoPaginatorConstructorPattern); otherwise it is empty
// and the binding is a plain service client. scope, when non-nil, is
// consulted first: a local binding that shadows the package identifier
// (e.g. a parameter named the same as an imported SDK package alias) means
// pkg is never that import here, regardless of the file-wide alias table.
func requirementsGoConstructorCall(expr ast.Expr, aliasToImport map[string]string, scope *requirementsGoScope) (provider ci.Provider, service string, paginatorOp string, isClient bool) {
	call, isCall := expr.(*ast.CallExpr)
	if !isCall {
		return "", "", "", false
	}
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return "", "", "", false
	}
	pkgIdent, isIdent := sel.X.(*ast.Ident)
	if !isIdent || !strings.HasPrefix(sel.Sel.Name, "New") {
		return "", "", "", false
	}
	if scope != nil {
		if _, _, present := scope.lookup(pkgIdent.Name); present {
			return "", "", "", false
		}
	}
	importPath, known := aliasToImport[pkgIdent.Name]
	if !known {
		return "", "", "", false
	}
	provider, service, isSDK := requirementsGoImportService(importPath)
	if !isSDK {
		return "", "", "", false
	}
	if m := requirementsGoPaginatorConstructorPattern.FindStringSubmatch(sel.Sel.Name); m != nil {
		return provider, service, m[1], true
	}
	return provider, service, "", true
}
