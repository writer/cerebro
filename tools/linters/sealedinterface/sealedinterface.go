package sealedinterface

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strconv"
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
					inspectValueSpec(pass, valueSpec, nil, sealedObjects, sealed, reported)
				}
			}
		}
	}

	return nil, nil
}

func inspectFlow(pass *analysis.Pass, body *ast.BlockStmt, results *types.Tuple, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	inspectFlowWithFacts(pass, body, results, nil, sealedObjects, sealed, reported)
}

func inspectFlowWithFacts(pass *analysis.Pass, body *ast.BlockStmt, results *types.Tuple, inherited *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	inspectFlowNodeWithFacts(pass, body, results, inherited, sealedObjects, sealed, reported)
}

func inspectFlowNodeWithFacts(pass *analysis.Pass, node ast.Node, results *types.Tuple, inherited *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) *flowFacts {
	facts := inherited.clone()
	if node == nil {
		return facts
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			if node.Body == nil {
				return false
			}
			sig, ok := pass.TypesInfo.TypeOf(node).(*types.Signature)
			if !ok {
				return false
			}
			inspectFlowWithFacts(pass, node.Body, sig.Results(), facts, sealedObjects, sealed, reported)
			return false
		case *ast.DeclStmt:
			decl, ok := node.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				inspectValueSpec(pass, valueSpec, facts, sealedObjects, sealed, reported)
			}
			return false
		case *ast.IfStmt:
			facts = inspectFlowStmtWithFacts(pass, node.Init, results, facts, sealedObjects, sealed, reported)
			inspectExpressionCalls(pass, node.Cond, facts, sealedObjects, sealed, reported)
			thenFacts := inspectFlowNodeWithFacts(pass, node.Body, results, facts, sealedObjects, sealed, reported)
			branches := make([]*flowFacts, 0, 2)
			if !stmtTerminates(node.Body) {
				branches = append(branches, thenFacts)
			}
			if node.Else != nil {
				elseFacts := inspectFlowNodeWithFacts(pass, node.Else, results, facts, sealedObjects, sealed, reported)
				if !stmtTerminates(node.Else) {
					branches = append(branches, elseFacts)
				}
			} else {
				branches = append(branches, facts.clone())
			}
			facts = mergeFlowFacts(branches...)
			return false
		case *ast.SwitchStmt:
			facts = inspectFlowStmtWithFacts(pass, node.Init, results, facts, sealedObjects, sealed, reported)
			inspectExpressionCalls(pass, node.Tag, facts, sealedObjects, sealed, reported)
			branches := make([]*flowFacts, 0, len(node.Body.List)+1)
			hasDefault := false
			var fallthroughFacts []*flowFacts
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				if len(clause.List) == 0 {
					hasDefault = true
				}
				for _, expr := range clause.List {
					inspectExpressionCalls(pass, expr, facts, sealedObjects, sealed, reported)
				}
				starts := append([]*flowFacts{facts}, fallthroughFacts...)
				fallthroughFacts = nil
				clauseFacts := make([]*flowFacts, 0, len(starts))
				clauseBlock := &ast.BlockStmt{List: clause.Body}
				for _, start := range starts {
					clauseFacts = append(clauseFacts, inspectFlowNodeWithFacts(pass, clauseBlock, results, start, sealedObjects, sealed, reported))
				}
				if caseFallsThrough(clause) {
					fallthroughFacts = clauseFacts
					continue
				}
				if !stmtTerminates(clauseBlock) {
					branches = append(branches, clauseFacts...)
				}
			}
			if !hasDefault {
				branches = append(branches, facts.clone())
			}
			facts = mergeFlowFacts(branches...)
			return false
		case *ast.TypeSwitchStmt:
			facts = inspectFlowStmtWithFacts(pass, node.Init, results, facts, sealedObjects, sealed, reported)
			facts = inspectFlowStmtWithFacts(pass, node.Assign, results, facts, sealedObjects, sealed, reported)
			branches := make([]*flowFacts, 0, len(node.Body.List)+1)
			hasDefault := false
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				if len(clause.List) == 0 {
					hasDefault = true
				}
				branchFacts := facts.clone()
				if len(clause.List) == 0 {
					seedTypeSwitchDefaultFacts(pass, branchFacts, node.Assign, node.Body.List, clause)
				} else {
					seedTypeSwitchCaseFacts(pass, branchFacts, node.Assign, clause)
				}
				clauseBlock := &ast.BlockStmt{List: clause.Body}
				clauseFacts := inspectFlowNodeWithFacts(pass, clauseBlock, results, branchFacts, sealedObjects, sealed, reported)
				if !stmtTerminates(clauseBlock) {
					branches = append(branches, clauseFacts)
				}
			}
			if !hasDefault {
				branches = append(branches, facts.clone())
			}
			facts = mergeFlowFacts(branches...)
			return false
		case *ast.SelectStmt:
			branches := make([]*flowFacts, 0, len(node.Body.List))
			for _, stmt := range node.Body.List {
				clause, ok := stmt.(*ast.CommClause)
				if !ok {
					continue
				}
				branchFacts := inspectFlowStmtWithFacts(pass, clause.Comm, results, facts, sealedObjects, sealed, reported)
				clauseBlock := &ast.BlockStmt{List: clause.Body}
				clauseFacts := inspectFlowNodeWithFacts(pass, clauseBlock, results, branchFacts, sealedObjects, sealed, reported)
				if !stmtTerminates(clauseBlock) {
					branches = append(branches, clauseFacts)
				}
			}
			facts = mergeFlowFacts(branches...)
			return false
		case *ast.ForStmt:
			facts = inspectFlowStmtWithFacts(pass, node.Init, results, facts, sealedObjects, sealed, reported)
			inspectExpressionCalls(pass, node.Cond, facts, sealedObjects, sealed, reported)
			facts = inspectLoopBodyWithFacts(pass, node.Body, node.Post, results, facts, sealedObjects, sealed, reported)
			return false
		case *ast.ReturnStmt:
			if len(node.Results) == 1 {
				if tuple, ok := pass.TypesInfo.TypeOf(node.Results[0]).(*types.Tuple); ok {
					for index := 0; results != nil && index < results.Len() && index < tuple.Len(); index++ {
						reportImportedSealedValueWithFactsAt(pass, node.Results[0], results.At(index).Type(), index, facts, sealedObjects, sealed, reported)
					}
					break
				}
			}
			for index, result := range node.Results {
				if results == nil || index >= results.Len() {
					break
				}
				reportImportedSealedValueWithFacts(pass, result, results.At(index).Type(), facts, sealedObjects, sealed, reported)
			}
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 {
				if tuple, ok := pass.TypesInfo.TypeOf(node.Rhs[0]).(*types.Tuple); ok {
					for index, lhs := range node.Lhs {
						if index >= tuple.Len() {
							break
						}
						inspectAssignmentTarget(pass, lhs, facts, sealedObjects, sealed, reported)
						reportImportedSealedValueWithFactsAt(pass, node.Rhs[0], pass.TypesInfo.TypeOf(lhs), index, facts, sealedObjects, sealed, reported)
						facts.record(pass, lhs, node.Rhs[0], index)
					}
					break
				}
			}
			for index, rhs := range node.Rhs {
				if index >= len(node.Lhs) {
					break
				}
				inspectAssignmentTarget(pass, node.Lhs[index], facts, sealedObjects, sealed, reported)
				reportImportedSealedValueWithFacts(pass, rhs, pass.TypesInfo.TypeOf(node.Lhs[index]), facts, sealedObjects, sealed, reported)
				facts.record(pass, node.Lhs[index], rhs, -1)
			}
		case *ast.RangeStmt:
			keyType, valueType := rangeTypes(pass.TypesInfo.TypeOf(node.X))
			bodyFacts := facts.clone()
			inspectRangeAssignmentTarget(pass, node.Key, keyType, bodyFacts, sealedObjects, sealed, reported)
			inspectRangeValueTarget(pass, node.Value, node.X, valueType, bodyFacts, sealedObjects, sealed, reported)
			bodyFacts = inspectFlowNodeWithFacts(pass, node.Body, results, bodyFacts, sealedObjects, sealed, reported)
			facts = mergeFlowFacts(facts.clone(), bodyFacts)
			return false
		case *ast.CallExpr:
			inspectCall(pass, node, facts, sealedObjects, sealed, reported)
		case *ast.CompositeLit:
			inspectCompositeLiteral(pass, node, facts, sealedObjects, sealed, reported)
		case *ast.SendStmt:
			if ch, ok := underlying(pass.TypesInfo.TypeOf(node.Chan)).(*types.Chan); ok {
				reportImportedSealedValueWithFacts(pass, node.Value, ch.Elem(), facts, sealedObjects, sealed, reported)
			}
			facts.recordChannelSend(pass, node.Chan, node.Value)
		}
		return true
	})
	return facts
}

func inspectFlowStmtWithFacts(pass *analysis.Pass, stmt ast.Stmt, results *types.Tuple, inherited *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) *flowFacts {
	if stmt == nil {
		return inherited.clone()
	}
	return inspectFlowNodeWithFacts(pass, stmt, results, inherited, sealedObjects, sealed, reported)
}

func inspectLoopBodyWithFacts(pass *analysis.Pass, body *ast.BlockStmt, post ast.Stmt, results *types.Tuple, inherited *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) *flowFacts {
	facts := inherited.clone()
	for iteration := 0; iteration < 4; iteration++ {
		bodyFacts := inspectFlowNodeWithFacts(pass, body, results, facts, sealedObjects, sealed, reported)
		bodyFacts = inspectFlowStmtWithFacts(pass, post, results, bodyFacts, sealedObjects, sealed, reported)
		merged := mergeFlowFacts(inherited.clone(), bodyFacts)
		if flowFactsEqual(facts, merged) {
			return merged
		}
		facts = merged
	}
	return facts
}

func mergeFlowFacts(branches ...*flowFacts) *flowFacts {
	merged := newFlowFacts()
	for _, branch := range branches {
		if branch == nil {
			continue
		}
		for slot, actuals := range branch.concrete {
			for _, actual := range actuals {
				merged.recordSlotActual(slot, actual)
			}
		}
		for slot, targets := range branch.aliases {
			for _, target := range targets {
				merged.aliases[slot] = appendUniqueFlowSlot(merged.aliases[slot], target)
			}
		}
		for slot, length := range branch.lengths {
			if length > merged.lengths[slot] {
				merged.lengths[slot] = length
			}
		}
	}
	return merged
}

func caseFallsThrough(clause *ast.CaseClause) bool {
	if clause == nil || len(clause.Body) == 0 {
		return false
	}
	branch, ok := clause.Body[len(clause.Body)-1].(*ast.BranchStmt)
	return ok && branch.Tok == token.FALLTHROUGH
}

func stmtTerminates(stmt ast.Stmt) bool {
	switch stmt := stmt.(type) {
	case nil:
		return false
	case *ast.BlockStmt:
		if len(stmt.List) == 0 {
			return false
		}
		return stmtTerminates(stmt.List[len(stmt.List)-1])
	case *ast.ReturnStmt:
		return true
	case *ast.IfStmt:
		return stmt.Else != nil && stmtTerminates(stmt.Body) && stmtTerminates(stmt.Else)
	}
	return false
}

func seedTypeSwitchCaseFacts(pass *analysis.Pass, facts *flowFacts, assign ast.Stmt, clause *ast.CaseClause) {
	if facts == nil || clause == nil || len(clause.List) == 0 {
		return
	}
	name, assertion := typeSwitchBinding(assign)
	if name == nil || assertion == nil {
		return
	}
	actuals, ok := facts.concreteForExpr(pass, assertion.X)
	if !ok {
		return
	}
	for _, slot := range typeSwitchCaseSlots(pass, name, clause) {
		facts.clearSlot(slot)
		for _, actual := range actuals {
			if typeSwitchCaseMatches(pass, actual, clause.List) {
				facts.recordSlotActual(slot, actual)
			}
		}
	}
}

func seedTypeSwitchDefaultFacts(pass *analysis.Pass, facts *flowFacts, assign ast.Stmt, clauses []ast.Stmt, defaultClause *ast.CaseClause) {
	if facts == nil || defaultClause == nil {
		return
	}
	name, assertion := typeSwitchBinding(assign)
	if name == nil || assertion == nil {
		return
	}
	actuals, ok := facts.concreteForExpr(pass, assertion.X)
	if !ok {
		return
	}
	caseExprs := typeSwitchCaseExprs(clauses)
	for _, slot := range typeSwitchCaseSlots(pass, name, defaultClause) {
		facts.clearSlot(slot)
		for _, actual := range actuals {
			if !typeSwitchCaseMatches(pass, actual, caseExprs) {
				facts.recordSlotActual(slot, actual)
			}
		}
	}
}

func typeSwitchCaseExprs(clauses []ast.Stmt) []ast.Expr {
	var exprs []ast.Expr
	for _, stmt := range clauses {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		exprs = append(exprs, clause.List...)
	}
	return exprs
}

func typeSwitchBinding(assign ast.Stmt) (*ast.Ident, *ast.TypeAssertExpr) {
	stmt, ok := assign.(*ast.AssignStmt)
	if !ok || len(stmt.Lhs) != 1 || len(stmt.Rhs) != 1 {
		return nil, nil
	}
	name, ok := stmt.Lhs[0].(*ast.Ident)
	if !ok {
		return nil, nil
	}
	assertion, ok := stmt.Rhs[0].(*ast.TypeAssertExpr)
	if !ok {
		return nil, nil
	}
	return name, assertion
}

func typeSwitchCaseSlots(pass *analysis.Pass, name *ast.Ident, clause *ast.CaseClause) []flowSlot {
	slots := map[flowSlot]struct{}{}
	if slot, ok := flowSlotForIdent(pass, name); ok {
		slots[slot] = struct{}{}
	}
	shadowed := map[types.Object]struct{}{}
	ast.Inspect(&ast.BlockStmt{List: clause.Body}, func(n ast.Node) bool {
		switch node := n.(type) {
		case nil:
			return true
		case *ast.FuncLit:
			return false
		case *ast.Ident:
			if node.Name != name.Name {
				return true
			}
			if obj := pass.TypesInfo.Defs[node]; obj != nil {
				shadowed[obj] = struct{}{}
				return true
			}
			if obj := pass.TypesInfo.Uses[node]; obj != nil {
				if _, ok := shadowed[obj]; ok {
					return true
				}
			}
			slot, ok := flowSlotForIdent(pass, node)
			if ok {
				slots[slot] = struct{}{}
			}
		}
		return true
	})
	result := make([]flowSlot, 0, len(slots))
	for slot := range slots {
		result = append(result, slot)
	}
	return result
}

func typeSwitchCaseMatches(pass *analysis.Pass, actual types.Type, cases []ast.Expr) bool {
	if actual == nil {
		return false
	}
	for _, expr := range cases {
		caseType := pass.TypesInfo.TypeOf(expr)
		if caseType == nil {
			continue
		}
		if types.AssignableTo(actual, caseType) {
			return true
		}
		if iface, ok := underlying(caseType).(*types.Interface); ok && types.Implements(actual, iface) {
			return true
		}
	}
	return false
}

func inspectRangeAssignmentTarget(pass *analysis.Pass, target ast.Expr, actual types.Type, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if target == nil || actual == nil {
		return
	}
	inspectAssignmentTarget(pass, target, facts, sealedObjects, sealed, reported)
	reportImportedSealedActual(pass, target, actual, pass.TypesInfo.TypeOf(target), sealedObjects, sealed, reported)
	facts.recordActual(pass, target, actual)
}

func inspectRangeValueTarget(pass *analysis.Pass, target ast.Expr, rangeExpr ast.Expr, fallback types.Type, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if target == nil {
		return
	}
	inspectAssignmentTarget(pass, target, facts, sealedObjects, sealed, reported)
	slot, hasSlot := flowSlotForExpr(pass, target)
	if actuals, ok := facts.rangeElementConcretes(pass, rangeExpr); ok {
		if hasSlot {
			facts.clearSlot(slot)
		}
		for _, actual := range actuals {
			reportImportedSealedActual(pass, target, actual, pass.TypesInfo.TypeOf(target), sealedObjects, sealed, reported)
			if hasSlot {
				facts.recordSlotActual(slot, actual)
			}
		}
		return
	}
	inspectRangeAssignmentTarget(pass, target, fallback, facts, sealedObjects, sealed, reported)
}

func rangeTypes(t types.Type) (types.Type, types.Type) {
	switch typ := underlying(t).(type) {
	case *types.Slice:
		return types.Typ[types.Int], typ.Elem()
	case *types.Array:
		return types.Typ[types.Int], typ.Elem()
	case *types.Map:
		return typ.Key(), typ.Elem()
	case *types.Chan:
		return typ.Elem(), nil
	default:
		return nil, nil
	}
}

func inspectAssignmentTarget(pass *analysis.Pass, lhs ast.Expr, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	indexExpr, ok := lhs.(*ast.IndexExpr)
	if !ok {
		return
	}
	if m, ok := underlying(pass.TypesInfo.TypeOf(indexExpr.X)).(*types.Map); ok {
		reportImportedSealedValueWithFacts(pass, indexExpr.Index, m.Key(), facts, sealedObjects, sealed, reported)
	}
}

type flowSlot struct {
	root *types.Var
	path string
}

type flowFacts struct {
	concrete map[flowSlot][]types.Type
	aliases  map[flowSlot][]flowSlot
	lengths  map[flowSlot]int
}

func newFlowFacts() *flowFacts {
	return &flowFacts{
		concrete: map[flowSlot][]types.Type{},
		aliases:  map[flowSlot][]flowSlot{},
		lengths:  map[flowSlot]int{},
	}
}

func (f *flowFacts) clone() *flowFacts {
	cloned := newFlowFacts()
	if f == nil {
		return cloned
	}
	for key, value := range f.concrete {
		cloned.concrete[key] = append([]types.Type(nil), value...)
	}
	for key, value := range f.aliases {
		cloned.aliases[key] = append([]flowSlot(nil), value...)
	}
	for key, value := range f.lengths {
		cloned.lengths[key] = value
	}
	return cloned
}

func (f *flowFacts) recordName(pass *analysis.Pass, name *ast.Ident, rhs ast.Expr, tupleIndex int) {
	if f == nil || name == nil || name.Name == "_" {
		return
	}
	slot, ok := flowSlotForIdent(pass, name)
	if !ok {
		return
	}
	f.recordSlot(pass, slot, rhs, tupleIndex)
}

func (f *flowFacts) record(pass *analysis.Pass, lhs ast.Expr, rhs ast.Expr, tupleIndex int) {
	if f == nil {
		return
	}
	slots := f.assignmentSlots(pass, lhs)
	if len(slots) == 0 {
		return
	}
	for _, slot := range slots {
		f.recordSlot(pass, slot, rhs, tupleIndex)
	}
}

func (f *flowFacts) recordActual(pass *analysis.Pass, lhs ast.Expr, actual types.Type) {
	if f == nil {
		return
	}
	slots := f.assignmentSlots(pass, lhs)
	if len(slots) == 0 {
		return
	}
	for _, slot := range slots {
		f.recordSlotActual(slot, actual)
	}
}

func (f *flowFacts) rangeElementConcretes(pass *analysis.Pass, expr ast.Expr) ([]types.Type, bool) {
	if f == nil {
		return nil, false
	}
	slot, ok := flowSlotForExpr(pass, expr)
	if !ok {
		return nil, false
	}
	prefix := slot.path + "/"
	var actuals []types.Type
	for existing, concrete := range f.concrete {
		if existing.root != slot.root || !strings.HasPrefix(existing.path, prefix) {
			continue
		}
		for _, actual := range concrete {
			actuals = appendUniqueType(actuals, actual)
		}
	}
	return actuals, len(actuals) > 0
}

func appendUniqueType(typesList []types.Type, actual types.Type) []types.Type {
	for _, existing := range typesList {
		if types.Identical(existing, actual) {
			return typesList
		}
	}
	return append(typesList, actual)
}

func appendUniqueFlowSlot(slots []flowSlot, slot flowSlot) []flowSlot {
	for _, existing := range slots {
		if existing == slot {
			return slots
		}
	}
	return append(slots, slot)
}

func flowFactsEqual(left *flowFacts, right *flowFacts) bool {
	if left == nil || right == nil {
		return left == right
	}
	if len(left.concrete) != len(right.concrete) || len(left.aliases) != len(right.aliases) || len(left.lengths) != len(right.lengths) {
		return false
	}
	for slot, actuals := range left.concrete {
		if !typeSlicesEqual(actuals, right.concrete[slot]) {
			return false
		}
	}
	for slot, aliases := range left.aliases {
		if !flowSlotSlicesEqual(aliases, right.aliases[slot]) {
			return false
		}
	}
	for slot, length := range left.lengths {
		if right.lengths[slot] != length {
			return false
		}
	}
	return true
}

func typeSlicesEqual(left []types.Type, right []types.Type) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !types.Identical(left[index], right[index]) {
			return false
		}
	}
	return true
}

func flowSlotSlicesEqual(left []flowSlot, right []flowSlot) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (f *flowFacts) recordSlot(pass *analysis.Pass, slot flowSlot, rhs ast.Expr, tupleIndex int) {
	if f.recordAppendResult(pass, slot, rhs) {
		return
	}
	if f.recordSliceResult(pass, slot, rhs) {
		return
	}
	if f.recordChildAliasResult(pass, slot, rhs) {
		return
	}
	f.clearSlot(slot)
	if targets, ok := f.pointerTargetsForExpr(pass, rhs); ok {
		f.aliases[slot] = targets
		return
	}
	actual := pass.TypesInfo.TypeOf(rhs)
	if tuple, ok := actual.(*types.Tuple); ok {
		if tupleIndex < 0 || tupleIndex >= tuple.Len() {
			return
		}
		actual = tuple.At(tupleIndex).Type()
	}
	if f.recordCompositeElements(pass, slot, rhs) {
		return
	}
	if tupleIndex <= 0 {
		if actuals, ok := f.concreteForExpr(pass, rhs); ok {
			f.concrete[slot] = append([]types.Type(nil), actuals...)
			return
		}
	}
	if namedImplementation(actual) == nil {
		if converted, ok := concreteFromConversion(pass, rhs); ok {
			actual = converted
		}
	}
	if namedImplementation(actual) == nil {
		return
	}
	f.concrete[slot] = []types.Type{actual}
}

func (f *flowFacts) recordAppendResult(pass *analysis.Pass, dstSlot flowSlot, rhs ast.Expr) bool {
	call, ok := rhs.(*ast.CallExpr)
	if !ok || !isBuiltinCall(pass, call, "append") || len(call.Args) <= 1 {
		return false
	}
	srcSlot, hasSrcSlot := flowSlotForExpr(pass, call.Args[0])
	copied := f.childFactsForExpr(pass, call.Args[0], dstSlot)
	appendIndex := f.nextAppendIndex(srcSlot, hasSrcSlot, copied)
	f.clearSlot(dstSlot)
	for slot, actuals := range copied {
		f.concrete[slot] = actuals
	}
	if call.Ellipsis != token.NoPos && len(call.Args) == 2 {
		f.recordSpreadAppend(pass, dstSlot, call.Args[1], appendIndex)
		return true
	}
	for index, arg := range call.Args[1:] {
		child := dstSlot
		child.path += "/const:" + strconv.Itoa(appendIndex+index)
		f.recordExprConcretes(pass, child, arg)
	}
	f.lengths[dstSlot] = appendIndex + len(call.Args) - 1
	return true
}

func (f *flowFacts) recordSpreadAppend(pass *analysis.Pass, dstSlot flowSlot, arg ast.Expr, appendIndex int) {
	if lit, ok := arg.(*ast.CompositeLit); ok {
		switch underlying(pass.TypesInfo.TypeOf(lit)).(type) {
		case *types.Slice, *types.Array:
			for index, elt := range lit.Elts {
				child := dstSlot
				child.path += "/const:" + strconv.Itoa(appendIndex+index)
				f.recordExprConcretes(pass, child, compositeLiteralValue(elt))
			}
			f.lengths[dstSlot] = appendIndex + len(lit.Elts)
			return
		}
	}
	copied := f.childFactsForExpr(pass, arg, dstSlot)
	if slice, ok := arg.(*ast.SliceExpr); ok {
		copied = f.childFactsForSlice(pass, slice, dstSlot)
	}
	for slot, actuals := range copied {
		shifted, ok := offsetSlotIndex(slot, appendIndex)
		if !ok {
			continue
		}
		for _, actual := range actuals {
			f.recordSlotActual(shifted, actual)
		}
	}
}

func (f *flowFacts) recordSliceResult(pass *analysis.Pass, dstSlot flowSlot, rhs ast.Expr) bool {
	slice, ok := rhs.(*ast.SliceExpr)
	if !ok {
		return false
	}
	copied := f.childFactsForSlice(pass, slice, dstSlot)
	if len(copied) == 0 {
		return false
	}
	f.clearSlot(dstSlot)
	for slot, actuals := range copied {
		f.concrete[slot] = actuals
	}
	if length, ok := sliceLength(pass, slice); ok {
		f.lengths[dstSlot] = length
	}
	return true
}

func (f *flowFacts) recordChildAliasResult(pass *analysis.Pass, dstSlot flowSlot, rhs ast.Expr) bool {
	copied := f.childFactsForExpr(pass, rhs, dstSlot)
	srcSlot, hasSrcSlot := flowSlotForExpr(pass, rhs)
	if len(copied) == 0 && (!hasSrcSlot || f.lengths[srcSlot] == 0) {
		return false
	}
	f.clearSlot(dstSlot)
	for slot, actuals := range copied {
		f.concrete[slot] = actuals
	}
	if hasSrcSlot {
		if length, ok := f.lengths[srcSlot]; ok {
			f.lengths[dstSlot] = length
		}
	}
	return true
}

func (f *flowFacts) recordExprConcretes(pass *analysis.Pass, slot flowSlot, expr ast.Expr) bool {
	if actuals, ok := f.concreteForExpr(pass, expr); ok {
		for _, actual := range actuals {
			f.recordSlotActual(slot, actual)
		}
		return true
	}
	return f.recordExprActual(pass, slot, expr)
}

func (f *flowFacts) recordSlotActual(slot flowSlot, actual types.Type) {
	if f == nil || slot.root == nil {
		return
	}
	if namedImplementation(actual) == nil {
		f.clearSlot(slot)
		return
	}
	for _, existing := range f.concrete[slot] {
		if types.Identical(existing, actual) {
			return
		}
	}
	f.concrete[slot] = append(f.concrete[slot], actual)
}

func (f *flowFacts) recordChannelSend(pass *analysis.Pass, channel ast.Expr, value ast.Expr) {
	if f == nil {
		return
	}
	slot, ok := channelValueSlot(pass, channel)
	if !ok {
		return
	}
	if actuals, ok := f.concreteForExpr(pass, value); ok {
		for _, actual := range actuals {
			f.recordSlotActual(slot, actual)
		}
		return
	}
	actual := pass.TypesInfo.TypeOf(value)
	if namedImplementation(actual) == nil {
		if converted, ok := concreteFromConversion(pass, value); ok {
			actual = converted
		}
	}
	if namedImplementation(actual) == nil {
		return
	}
	f.recordSlotActual(slot, actual)
}

func (f *flowFacts) copyIndexed(pass *analysis.Pass, dst ast.Expr, src ast.Expr) {
	if f == nil {
		return
	}
	dstSlot, dstOffset, ok := sliceWindowSlot(pass, dst)
	if !ok {
		return
	}
	srcSlot, srcOffset, ok := sliceWindowSlot(pass, src)
	if !ok {
		if !f.copyCompositeIndexed(pass, dstSlot, src) {
			f.clearSlot(dstSlot)
		}
		return
	}
	copied := map[flowSlot][]types.Type{}
	cleared := map[flowSlot]struct{}{}
	for slot, actuals := range f.concrete {
		if slot.root != srcSlot.root || !strings.HasPrefix(slot.path, srcSlot.path+"/") {
			continue
		}
		suffix := strings.TrimPrefix(slot.path, srcSlot.path)
		if srcOffset != 0 {
			var ok bool
			suffix, ok = shiftedSliceSuffix(suffix, srcOffset)
			if !ok {
				continue
			}
		}
		if dstOffset != 0 {
			var ok bool
			suffix, ok = offsetSliceSuffix(suffix, dstOffset)
			if !ok {
				continue
			}
		}
		overwritten := copiedDestinationSlot(dstSlot, suffix)
		if _, ok := cleared[overwritten]; !ok {
			f.clearSlot(overwritten)
			cleared[overwritten] = struct{}{}
		}
		child := dstSlot
		child.path += suffix
		copied[child] = append([]types.Type(nil), actuals...)
	}
	for slot, actuals := range copied {
		f.concrete[slot] = actuals
	}
}

func sliceWindowSlot(pass *analysis.Pass, expr ast.Expr) (flowSlot, int, bool) {
	if slice, ok := expr.(*ast.SliceExpr); ok {
		slot, ok := flowSlotForExpr(pass, slice.X)
		if !ok {
			return flowSlot{}, 0, false
		}
		offset, ok := constInt(pass, slice.Low)
		if !ok {
			offset = 0
		}
		return slot, offset, true
	}
	slot, ok := flowSlotForExpr(pass, expr)
	return slot, 0, ok
}

func (f *flowFacts) copyCompositeIndexed(pass *analysis.Pass, dstSlot flowSlot, src ast.Expr) bool {
	lit, ok := src.(*ast.CompositeLit)
	if !ok {
		return false
	}
	switch underlying(pass.TypesInfo.TypeOf(lit)).(type) {
	case *types.Slice, *types.Array:
	default:
		return false
	}
	for index, elt := range lit.Elts {
		child := dstSlot
		child.path += "/" + compositeElementKey(pass, elt, index)
		f.clearSlot(child)
		f.recordExprActual(pass, child, compositeLiteralValue(elt))
	}
	return true
}

func (f *flowFacts) deleteIndexed(pass *analysis.Pass, container ast.Expr, index ast.Expr) {
	if f == nil {
		return
	}
	slot, ok := flowSlotForExpr(pass, container)
	if !ok {
		return
	}
	slot.path += "/" + indexFlowKey(pass, index)
	f.clearSlot(slot)
}

func (f *flowFacts) clearContainer(pass *analysis.Pass, container ast.Expr) {
	if f == nil {
		return
	}
	slot, ok := flowSlotForExpr(pass, container)
	if !ok {
		return
	}
	length, hadLength := f.lengths[slot]
	_, isSlice := underlying(pass.TypesInfo.TypeOf(container)).(*types.Slice)
	f.clearSlot(slot)
	if isSlice && hadLength {
		f.lengths[slot] = length
	}
}

func (f *flowFacts) childFactsForExpr(pass *analysis.Pass, expr ast.Expr, dstSlot flowSlot) map[flowSlot][]types.Type {
	srcSlot, ok := flowSlotForExpr(pass, expr)
	if !ok {
		return nil
	}
	return f.childFactsForSlot(srcSlot, dstSlot)
}

func (f *flowFacts) childFactsForSlice(pass *analysis.Pass, slice *ast.SliceExpr, dstSlot flowSlot) map[flowSlot][]types.Type {
	srcSlot, ok := flowSlotForExpr(pass, slice.X)
	if !ok {
		return nil
	}
	low, lowOK := constInt(pass, slice.Low)
	copied := map[flowSlot][]types.Type{}
	for slot, actuals := range f.concrete {
		if slot.root != srcSlot.root || !strings.HasPrefix(slot.path, srcSlot.path+"/") {
			continue
		}
		suffix := strings.TrimPrefix(slot.path, srcSlot.path)
		if lowOK {
			var ok bool
			suffix, ok = shiftedSliceSuffix(suffix, low)
			if !ok {
				continue
			}
		}
		child := dstSlot
		child.path += suffix
		copied[child] = append([]types.Type(nil), actuals...)
	}
	return copied
}

func (f *flowFacts) childFactsForSlot(srcSlot flowSlot, dstSlot flowSlot) map[flowSlot][]types.Type {
	copied := map[flowSlot][]types.Type{}
	for slot, actuals := range f.concrete {
		if slot.root != srcSlot.root || !strings.HasPrefix(slot.path, srcSlot.path+"/") {
			continue
		}
		child := dstSlot
		child.path += strings.TrimPrefix(slot.path, srcSlot.path)
		copied[child] = append([]types.Type(nil), actuals...)
	}
	return copied
}

func (f *flowFacts) nextAppendIndex(srcSlot flowSlot, hasSrcSlot bool, copied map[flowSlot][]types.Type) int {
	if hasSrcSlot {
		if length, ok := f.lengths[srcSlot]; ok {
			return length
		}
	}
	return maxConstChildIndex(copied) + 1
}

func maxConstChildIndex(facts map[flowSlot][]types.Type) int {
	maxIndex := -1
	for slot := range facts {
		trimmed := strings.TrimPrefix(slot.path, "/")
		segment, _, _ := strings.Cut(trimmed, "/")
		if !strings.HasPrefix(segment, "const:") {
			continue
		}
		index, err := strconv.Atoi(strings.TrimPrefix(segment, "const:"))
		if err != nil {
			continue
		}
		if index > maxIndex {
			maxIndex = index
		}
	}
	return maxIndex
}

func offsetSlotIndex(slot flowSlot, offset int) (flowSlot, bool) {
	if offset == 0 {
		return slot, true
	}
	suffix, ok := offsetSliceSuffix(slot.path, offset)
	if !ok {
		return flowSlot{}, false
	}
	slot.path = suffix
	return slot, true
}

func shiftedSliceSuffix(suffix string, low int) (string, bool) {
	trimmed := strings.TrimPrefix(suffix, "/")
	if trimmed == "" || low == 0 {
		return suffix, true
	}
	segment, rest, _ := strings.Cut(trimmed, "/")
	if !strings.HasPrefix(segment, "const:") {
		return suffix, true
	}
	index, err := strconv.Atoi(strings.TrimPrefix(segment, "const:"))
	if err != nil {
		return suffix, true
	}
	if index < low {
		return "", false
	}
	shifted := "const:" + strconv.Itoa(index-low)
	if rest != "" {
		shifted += "/" + rest
	}
	return "/" + shifted, true
}

func offsetSliceSuffix(suffix string, offset int) (string, bool) {
	trimmed := strings.TrimPrefix(suffix, "/")
	if trimmed == "" || offset == 0 {
		return suffix, true
	}
	segment, rest, _ := strings.Cut(trimmed, "/")
	if !strings.HasPrefix(segment, "const:") {
		return suffix, true
	}
	index, err := strconv.Atoi(strings.TrimPrefix(segment, "const:"))
	if err != nil {
		return suffix, true
	}
	shifted := "const:" + strconv.Itoa(index+offset)
	if rest != "" {
		shifted += "/" + rest
	}
	return "/" + shifted, true
}

func constInt(pass *analysis.Pass, expr ast.Expr) (int, bool) {
	if expr == nil {
		return 0, true
	}
	value := pass.TypesInfo.Types[expr].Value
	if value == nil {
		return 0, false
	}
	asInt, ok := constant.Int64Val(value)
	if !ok {
		return 0, false
	}
	return int(asInt), true
}

func sliceLength(pass *analysis.Pass, slice *ast.SliceExpr) (int, bool) {
	if slice.High == nil {
		return 0, false
	}
	low, lowOK := constInt(pass, slice.Low)
	if !lowOK {
		return 0, false
	}
	high, highOK := constInt(pass, slice.High)
	if !highOK {
		return 0, false
	}
	if high < low {
		return 0, false
	}
	return high - low, true
}

func copiedDestinationSlot(dstSlot flowSlot, suffix string) flowSlot {
	child := dstSlot
	suffix = strings.TrimPrefix(suffix, "/")
	if suffix == "" {
		return child
	}
	if slash := strings.IndexByte(suffix, '/'); slash >= 0 {
		suffix = suffix[:slash]
	}
	child.path += "/" + suffix
	return child
}

func (f *flowFacts) clearSlot(slot flowSlot) {
	if f == nil || slot.root == nil {
		return
	}
	childPrefix := slot.path + "/"
	for existing := range f.concrete {
		if existing.root != slot.root {
			continue
		}
		if existing.path == slot.path || strings.HasPrefix(existing.path, childPrefix) {
			delete(f.concrete, existing)
		}
	}
	for existing := range f.aliases {
		if existing.root != slot.root {
			continue
		}
		if existing.path == slot.path || strings.HasPrefix(existing.path, childPrefix) {
			delete(f.aliases, existing)
		}
	}
	for existing := range f.lengths {
		if existing.root != slot.root {
			continue
		}
		if existing.path == slot.path || strings.HasPrefix(existing.path, childPrefix) {
			delete(f.lengths, existing)
		}
	}
}

func (f *flowFacts) recordCompositeElements(pass *analysis.Pass, slot flowSlot, rhs ast.Expr) bool {
	lit, ok := rhs.(*ast.CompositeLit)
	if !ok {
		return false
	}
	recorded := false
	switch typ := underlying(pass.TypesInfo.TypeOf(lit)).(type) {
	case *types.Slice, *types.Array:
		f.lengths[slot] = len(lit.Elts)
		for index, elt := range lit.Elts {
			value := compositeLiteralValue(elt)
			child := slot
			child.path += "/" + compositeElementKey(pass, elt, index)
			if f.recordExprActual(pass, child, value) {
				recorded = true
			}
		}
	case *types.Map:
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			child := slot
			child.path += "/" + indexFlowKey(pass, kv.Key)
			if f.recordExprActual(pass, child, kv.Value) {
				recorded = true
			}
		}
	case *types.Struct:
		for index, elt := range lit.Elts {
			value := compositeLiteralValue(elt)
			var field *types.Var
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				field = structFieldForKey(typ, kv.Key)
			} else if index < typ.NumFields() {
				field = typ.Field(index)
			}
			if field == nil {
				continue
			}
			child := slot
			child.path += "/" + flowFieldKey(field)
			if f.recordExprActual(pass, child, value) {
				recorded = true
			}
		}
	}
	return recorded
}

func (f *flowFacts) recordExprActual(pass *analysis.Pass, slot flowSlot, expr ast.Expr) bool {
	actual := pass.TypesInfo.TypeOf(expr)
	if namedImplementation(actual) == nil {
		if converted, ok := concreteFromConversion(pass, expr); ok {
			actual = converted
		}
	}
	if namedImplementation(actual) == nil {
		return false
	}
	f.concrete[slot] = []types.Type{actual}
	return true
}

func (f *flowFacts) assertedConcretes(pass *analysis.Pass, expr ast.Expr) ([]types.Type, bool) {
	if f == nil {
		return nil, false
	}
	assertion, ok := expr.(*ast.TypeAssertExpr)
	if !ok {
		return nil, false
	}
	return f.concreteForExpr(pass, assertion.X)
}

func (f *flowFacts) concreteForExpr(pass *analysis.Pass, expr ast.Expr) ([]types.Type, bool) {
	if f == nil {
		return nil, false
	}
	if deref, ok := expr.(*ast.StarExpr); ok {
		var actuals []types.Type
		for _, slot := range f.dereferencedSlots(pass, deref.X) {
			for _, actual := range f.concrete[slot] {
				actuals = appendUniqueType(actuals, actual)
			}
		}
		return actuals, len(actuals) > 0
	}
	if receive, ok := expr.(*ast.UnaryExpr); ok && receive.Op == token.ARROW {
		if slot, ok := channelValueSlot(pass, receive.X); ok {
			actuals, ok := f.concrete[slot]
			return actuals, ok
		}
	}
	if slot, ok := flowSlotForExpr(pass, expr); ok {
		actuals, ok := f.concrete[slot]
		return actuals, ok
	}
	if call, ok := expr.(*ast.CallExpr); ok && len(call.Args) == 1 && !isFunctionCall(pass, call) {
		if actuals, ok := f.concreteForExpr(pass, call.Args[0]); ok {
			return actuals, true
		}
	}
	if actual, ok := concreteFromConversion(pass, expr); ok {
		return []types.Type{actual}, true
	}
	actual := pass.TypesInfo.TypeOf(expr)
	if namedImplementation(actual) == nil {
		return nil, false
	}
	return []types.Type{actual}, true
}

func (f *flowFacts) assignmentSlots(pass *analysis.Pass, expr ast.Expr) []flowSlot {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return f.assignmentSlots(pass, node.X)
	case *ast.StarExpr:
		return f.dereferencedSlots(pass, node.X)
	default:
		slot, ok := flowSlotForExpr(pass, expr)
		if !ok {
			return nil
		}
		return []flowSlot{slot}
	}
}

func (f *flowFacts) dereferencedSlots(pass *analysis.Pass, expr ast.Expr) []flowSlot {
	if f == nil {
		return nil
	}
	if target, ok := directAddressTarget(pass, expr); ok {
		return []flowSlot{target}
	}
	slot, ok := flowSlotForExpr(pass, expr)
	if !ok {
		return nil
	}
	return append([]flowSlot(nil), f.aliases[slot]...)
}

func (f *flowFacts) pointerTargetsForExpr(pass *analysis.Pass, expr ast.Expr) ([]flowSlot, bool) {
	if f == nil {
		return nil, false
	}
	if target, ok := directAddressTarget(pass, expr); ok {
		return []flowSlot{target}, true
	}
	if slot, ok := flowSlotForExpr(pass, expr); ok {
		targets, ok := f.aliases[slot]
		if ok {
			return append([]flowSlot(nil), targets...), true
		}
	}
	return nil, false
}

func directAddressTarget(pass *analysis.Pass, expr ast.Expr) (flowSlot, bool) {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return directAddressTarget(pass, node.X)
	case *ast.UnaryExpr:
		if node.Op != token.AND {
			return flowSlot{}, false
		}
		return flowSlotForExpr(pass, node.X)
	default:
		return flowSlot{}, false
	}
}

func concreteFromConversion(pass *analysis.Pass, expr ast.Expr) (types.Type, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return nil, false
	}
	if isFunctionCall(pass, call) {
		return nil, false
	}
	actual := pass.TypesInfo.TypeOf(call.Args[0])
	if namedImplementation(actual) == nil {
		return nil, false
	}
	return actual, true
}

func isFunctionCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	_, ok := pass.TypesInfo.TypeOf(call.Fun).(*types.Signature)
	return ok
}

func isBuiltinCall(pass *analysis.Pass, call *ast.CallExpr, name string) bool {
	if call == nil {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != name {
		return false
	}
	_, ok = pass.TypesInfo.Uses[ident].(*types.Builtin)
	return ok
}

func flowSlotForExpr(pass *analysis.Pass, expr ast.Expr) (flowSlot, bool) {
	switch node := expr.(type) {
	case *ast.ParenExpr:
		return flowSlotForExpr(pass, node.X)
	case *ast.Ident:
		return flowSlotForIdent(pass, node)
	case *ast.SelectorExpr:
		slot, ok := flowSlotForExpr(pass, node.X)
		if !ok {
			return flowSlot{}, false
		}
		selection := pass.TypesInfo.Selections[node]
		if selection == nil {
			return flowSlot{}, false
		}
		field, ok := selection.Obj().(*types.Var)
		if !ok || field == nil {
			return flowSlot{}, false
		}
		slot.path += "/" + flowFieldKey(field)
		return slot, true
	case *ast.IndexExpr:
		slot, ok := flowSlotForExpr(pass, node.X)
		if !ok {
			return flowSlot{}, false
		}
		slot.path += "/" + indexFlowKey(pass, node.Index)
		return slot, true
	case *ast.SliceExpr:
		return flowSlotForExpr(pass, node.X)
	default:
		return flowSlot{}, false
	}
}

func flowSlotForIdent(pass *analysis.Pass, name *ast.Ident) (flowSlot, bool) {
	if name == nil || name.Name == "_" {
		return flowSlot{}, false
	}
	obj, ok := pass.TypesInfo.Defs[name].(*types.Var)
	if !ok || obj == nil {
		obj, ok = pass.TypesInfo.Uses[name].(*types.Var)
	}
	if !ok || obj == nil {
		return flowSlot{}, false
	}
	return flowSlot{root: obj}, true
}

func channelValueSlot(pass *analysis.Pass, expr ast.Expr) (flowSlot, bool) {
	slot, ok := flowSlotForExpr(pass, expr)
	if !ok {
		return flowSlot{}, false
	}
	slot.path += "/<-"
	return slot, true
}

func flowFieldKey(field *types.Var) string {
	if field == nil {
		return ""
	}
	pkg := ""
	if field.Pkg() != nil {
		pkg = field.Pkg().Path()
	}
	return pkg + "." + field.Name() + "@" + strconv.Itoa(int(field.Pos()))
}

func compositeElementKey(pass *analysis.Pass, expr ast.Expr, index int) string {
	if kv, ok := expr.(*ast.KeyValueExpr); ok {
		return indexFlowKey(pass, kv.Key)
	}
	return "const:" + strconv.Itoa(index)
}

func indexFlowKey(pass *analysis.Pass, expr ast.Expr) string {
	if expr == nil {
		return "nil"
	}
	if value := pass.TypesInfo.Types[expr].Value; value != nil {
		return "const:" + value.String()
	}
	if slot, ok := flowSlotForExpr(pass, expr); ok {
		return "slot:" + flowSlotKey(slot)
	}
	return "expr:" + strconv.Itoa(int(expr.Pos()))
}

func flowSlotKey(slot flowSlot) string {
	if slot.root == nil {
		return slot.path
	}
	pkg := ""
	if slot.root.Pkg() != nil {
		pkg = slot.root.Pkg().Path()
	}
	return pkg + "." + slot.root.Name() + "@" + strconv.Itoa(int(slot.root.Pos())) + slot.path
}

func inspectValueSpec(pass *analysis.Pass, valueSpec *ast.ValueSpec, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	var expected types.Type
	if valueSpec.Type != nil {
		expected = pass.TypesInfo.TypeOf(valueSpec.Type)
	}
	if len(valueSpec.Values) == 1 && len(valueSpec.Names) > 1 {
		if _, ok := pass.TypesInfo.TypeOf(valueSpec.Values[0]).(*types.Tuple); ok {
			for index, name := range valueSpec.Names {
				reportImportedSealedValueWithFactsAt(pass, valueSpec.Values[0], expected, index, facts, sealedObjects, sealed, reported)
				if facts != nil {
					facts.recordName(pass, name, valueSpec.Values[0], index)
				}
			}
			inspectExpressionCalls(pass, valueSpec.Values[0], facts, sealedObjects, sealed, reported)
			return
		}
	}
	for index, value := range valueSpec.Values {
		reportImportedSealedValueWithFacts(pass, value, expected, facts, sealedObjects, sealed, reported)
		if facts != nil && index < len(valueSpec.Names) {
			facts.recordName(pass, valueSpec.Names[index], value, -1)
		}
		inspectExpressionCalls(pass, value, facts, sealedObjects, sealed, reported)
	}
}

func inspectExpressionCalls(pass *analysis.Pass, expr ast.Expr, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if expr == nil {
		return
	}
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
			inspectFlowWithFacts(pass, node.Body, sig.Results(), facts, sealedObjects, sealed, reported)
			return false
		case *ast.CallExpr:
			inspectCall(pass, node, facts, sealedObjects, sealed, reported)
		case *ast.CompositeLit:
			inspectCompositeLiteral(pass, node, facts, sealedObjects, sealed, reported)
		}
		return true
	})
}

func inspectCall(pass *analysis.Pass, call *ast.CallExpr, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if target := sealedObjectForType(pass.TypesInfo.TypeOf(call.Fun), sealedObjects); target != nil && len(call.Args) == 1 {
		reportImportedSealedValueWithFacts(pass, call.Args[0], target.Type(), facts, sealedObjects, sealed, reported)
		return
	}
	if ident, ok := call.Fun.(*ast.Ident); ok {
		if _, ok := pass.TypesInfo.Uses[ident].(*types.Builtin); ok {
			switch ident.Name {
			case "append":
				if len(call.Args) <= 1 {
					return
				}
				if slice, ok := underlying(pass.TypesInfo.TypeOf(call.Args[0])).(*types.Slice); ok {
					for _, arg := range call.Args[1:] {
						reportImportedSealedValueWithFacts(pass, arg, slice.Elem(), facts, sealedObjects, sealed, reported)
					}
				}
				return
			case "copy":
				if len(call.Args) == 2 {
					facts.copyIndexed(pass, call.Args[0], call.Args[1])
				}
				return
			case "delete":
				if len(call.Args) == 2 {
					facts.deleteIndexed(pass, call.Args[0], call.Args[1])
				}
				return
			case "clear":
				if len(call.Args) == 1 {
					facts.clearContainer(pass, call.Args[0])
				}
				return
			}
		}
	}
	sig, ok := pass.TypesInfo.TypeOf(call.Fun).(*types.Signature)
	if !ok {
		return
	}
	params := sig.Params()
	if len(call.Args) == 1 {
		if tuple, ok := pass.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); ok {
			for index := 0; params != nil && index < tuple.Len(); index++ {
				paramIndex := index
				if sig.Variadic() && index >= params.Len()-1 {
					paramIndex = params.Len() - 1
				}
				if paramIndex < 0 || paramIndex >= params.Len() {
					break
				}
				expected := params.At(paramIndex).Type()
				if sig.Variadic() && index >= params.Len()-1 {
					if slice, ok := expected.(*types.Slice); ok {
						expected = slice.Elem()
					}
				}
				reportImportedSealedValueWithFactsAt(pass, call.Args[0], expected, index, facts, sealedObjects, sealed, reported)
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
		reportImportedSealedValueWithFacts(pass, arg, expected, facts, sealedObjects, sealed, reported)
	}
}

func inspectCompositeLiteral(pass *analysis.Pass, lit *ast.CompositeLit, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	switch typ := underlying(pass.TypesInfo.TypeOf(lit)).(type) {
	case *types.Slice:
		for _, elt := range lit.Elts {
			reportImportedSealedValueWithFacts(pass, compositeLiteralValue(elt), typ.Elem(), facts, sealedObjects, sealed, reported)
		}
	case *types.Array:
		for _, elt := range lit.Elts {
			reportImportedSealedValueWithFacts(pass, compositeLiteralValue(elt), typ.Elem(), facts, sealedObjects, sealed, reported)
		}
	case *types.Map:
		for _, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				reportImportedSealedValueWithFacts(pass, kv.Key, typ.Key(), facts, sealedObjects, sealed, reported)
				reportImportedSealedValueWithFacts(pass, kv.Value, typ.Elem(), facts, sealedObjects, sealed, reported)
			}
		}
	case *types.Struct:
		for index, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if field := structFieldForKey(typ, kv.Key); field != nil {
					reportImportedSealedValueWithFacts(pass, kv.Value, field.Type(), facts, sealedObjects, sealed, reported)
				}
				continue
			}
			if index < typ.NumFields() {
				reportImportedSealedValueWithFacts(pass, elt, typ.Field(index).Type(), facts, sealedObjects, sealed, reported)
			}
		}
	}
}

func underlying(t types.Type) types.Type {
	t = unalias(t)
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

func reportImportedSealedValueWithFacts(pass *analysis.Pass, expr ast.Expr, expected types.Type, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	reportImportedSealedValueWithFactsAt(pass, expr, expected, -1, facts, sealedObjects, sealed, reported)
}

func reportImportedSealedValueWithFactsAt(pass *analysis.Pass, expr ast.Expr, expected types.Type, tupleIndex int, facts *flowFacts, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	if actuals, ok := facts.assertedConcretes(pass, expr); ok {
		for _, actual := range actuals {
			reportImportedSealedActual(pass, expr, actual, expected, sealedObjects, sealed, reported)
		}
		return
	}
	if actuals, ok := facts.concreteForExpr(pass, expr); ok {
		for _, actual := range actuals {
			reportImportedSealedActual(pass, expr, actual, expected, sealedObjects, sealed, reported)
		}
		return
	}
	reportImportedSealedValueAt(pass, expr, expected, tupleIndex, sealedObjects, sealed, reported)
}

func reportImportedSealedValueAt(pass *analysis.Pass, expr ast.Expr, expected types.Type, tupleIndex int, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	actual := pass.TypesInfo.TypeOf(expr)
	if tuple, ok := actual.(*types.Tuple); ok {
		if tupleIndex < 0 || tupleIndex >= tuple.Len() {
			return
		}
		actual = tuple.At(tupleIndex).Type()
	}
	reportImportedSealedActual(pass, expr, actual, expected, sealedObjects, sealed, reported)
}

func reportImportedSealedActual(pass *analysis.Pass, expr ast.Expr, actual types.Type, expected types.Type, sealedObjects []*types.TypeName, sealed map[*types.TypeName]*types.Interface, reported map[token.Pos]struct{}) {
	sealedObj := sealedObjectForType(expected, sealedObjects)
	if sealedObj == nil {
		return
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
	t = unalias(t)
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
	t = unalias(t)
	if named, ok := t.(*types.Named); ok {
		return named
	}
	if ptr, ok := t.(*types.Pointer); ok {
		if named, ok := unalias(ptr.Elem()).(*types.Named); ok {
			return named
		}
	}
	return nil
}

func unalias(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	return types.Unalias(t)
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
	t = unalias(t)
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
