package graphagent

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultMaxRows           = 100
	defaultAllNodesScanLimit = 1_000_000
)

var (
	forbiddenTokenPattern = regexp.MustCompile(`(?i)\b(CREATE|MERGE|DELETE|REMOVE|SET|DROP|FOREACH)\b`)
	loadCSVPattern        = regexp.MustCompile(`(?i)\bLOAD\s+CSV\b`)
	usingPeriodicPattern  = regexp.MustCompile(`(?i)\bUSING\s+PERIODIC\b`)
	forbiddenAPOCPattern  = regexp.MustCompile(`(?i)\bCALL\s+apoc\.(trigger|periodic)\.`)
	apocPattern           = regexp.MustCompile(`(?i)\bapoc\.`)
	limitPattern          = regexp.MustCompile(`(?i)\bLIMIT\s+(\d+)\b`)
	matchClausePattern    = regexp.MustCompile(`(?i)\b(?:OPTIONAL\s+MATCH|MATCH)\b`)
	matchClauseEndPattern = regexp.MustCompile(`(?i)\b(?:WHERE|RETURN|WITH|ORDER\s+BY|LIMIT|UNWIND|CALL|UNION|CREATE|MERGE|DELETE|SET|REMOVE|DROP|FOREACH)\b`)
	nodeBodyPattern       = regexp.MustCompile(`(?is)^\s*([A-Za-z_][A-Za-z0-9_]*)?\s*((?::\s*[A-Za-z_][A-Za-z0-9_]*)*)\s*(\{[^{}]*\})?\s*$`)
	inlineTenantPattern   = regexp.MustCompile(`(?i)\btenant_id\s*:\s*\$tenant_id\b`)
	quotedLiteralPattern  = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	commentPattern        = regexp.MustCompile(`(?m)//.*$|/\*.*?\*/`)
	numberPattern         = regexp.MustCompile(`\d+(?:\.\d+)?`)
)

type nodePattern struct {
	variable   string
	labels     string
	properties string
}

type subqueryScope struct {
	outer     map[string]struct{}
	imports   map[string]struct{}
	bodyStart int
	end       int
}

type ValidatorOptions struct {
	MaxRows           int
	AllNodesScanLimit int
	Explain           bool
}

type Validator struct {
	store   ports.GraphQueryStore
	options ValidatorOptions
}

func NewValidator(store ports.GraphQueryStore, options ValidatorOptions) *Validator {
	if options.MaxRows <= 0 {
		options.MaxRows = defaultMaxRows
	}
	if options.AllNodesScanLimit <= 0 {
		options.AllNodesScanLimit = defaultAllNodesScanLimit
	}
	return &Validator{store: store, options: options}
}

func (v *Validator) validate(ctx context.Context, cypher string, params map[string]any) (ValidatorResult, int, error) {
	query := strings.TrimSpace(cypher)
	if query == "" {
		return validatorRefusal("cypher_required", "cypher is required"), 0, nil
	}
	safeQuery := scrubCypher(query)
	if forbiddenTokenPattern.MatchString(safeQuery) || loadCSVPattern.MatchString(safeQuery) || usingPeriodicPattern.MatchString(safeQuery) {
		return validatorRefusal("unsafe_clause", "write or bulk-load Cypher clauses are forbidden"), 0, nil
	}
	if forbiddenAPOCPattern.MatchString(safeQuery) {
		return validatorRefusal("unsafe_apoc", "apoc trigger and periodic procedures are forbidden"), 0, nil
	}
	if apocPattern.MatchString(safeQuery) {
		return validatorRefusal("apoc_not_allowed", "APOC functions and procedures are not available in Ask Cerebro"), 0, nil
	}
	if hasProcedureCall(safeQuery) {
		return validatorRefusal("procedure_call_not_allowed", "procedure CALL clauses are forbidden"), 0, nil
	}
	limit, ok := queryLimit(safeQuery)
	if !ok {
		return validatorRefusal("limit_required", "read Cypher must include a numeric LIMIT clause"), 0, nil
	}
	if limit > v.options.MaxRows {
		return validatorRefusal("limit_exceeded", fmt.Sprintf("LIMIT %d exceeds maximum %d", limit, v.options.MaxRows)), 0, nil
	}
	if !allNodePatternsTenantScoped(safeQuery) {
		return validatorRefusal("tenant_scope_required", "every node pattern must use Entity label and inline tenant_id"), 0, nil
	}
	if v.options.Explain && v.store != nil {
		explainer, ok := v.store.(interface {
			ExplainReadCypher(context.Context, ports.CypherQueryRequest) (*ports.CypherPlan, error)
		})
		if !ok {
			return ValidatorResult{}, 0, fmt.Errorf("%w: graph store does not support EXPLAIN", ErrRuntimeUnavailable)
		}
		plan, err := explainer.ExplainReadCypher(ctx, ports.CypherQueryRequest{Query: query, Params: params})
		if err != nil {
			return ValidatorResult{}, 0, fmt.Errorf("%w: explain cypher: %w", ErrRuntimeUnavailable, err)
		}
		if allNodesScanOverLimit(plan, v.options.AllNodesScanLimit) {
			return validatorRefusal("all_nodes_scan_over_limit", fmt.Sprintf("EXPLAIN plan contains AllNodesScan over more than %d nodes", v.options.AllNodesScanLimit)), 0, nil
		}
	}
	return ValidatorResult{OK: true}, limit, nil
}

func validatorRefusal(code string, reason string) ValidatorResult {
	return ValidatorResult{OK: false, Code: code, Reason: reason}
}

func scrubCypher(query string) string {
	noComments := commentPattern.ReplaceAllString(query, " ")
	return quotedLiteralPattern.ReplaceAllString(noComments, "''")
}

func queryLimit(query string) (int, bool) {
	matches := limitPattern.FindAllStringSubmatch(query, -1)
	if len(matches) == 0 {
		return 0, false
	}
	value := matches[len(matches)-1][1]
	limit, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return limit, true
}

func allNodePatternsTenantScoped(query string) bool {
	if !matchClausesContainOnlyNodePatterns(query) {
		return false
	}
	scopedVariables := map[string]struct{}{}
	var pendingCallImports map[string]struct{}
	var subqueries []subqueryScope
	sawNode := false
	for i := 0; i < len(query); i++ {
		if len(subqueries) > 0 && i == subqueries[len(subqueries)-1].end {
			current := subqueries[len(subqueries)-1]
			scopedVariables = mergeScopedVariables(current.outer, scopedVariablesAfterReturn(query[current.bodyStart:current.end], scopedVariables))
			subqueries = subqueries[:len(subqueries)-1]
			pendingCallImports = nil
			continue
		}
		if keywordAt(query, i, "CALL") {
			braceIndex := subqueryStartBrace(query, i+len("CALL"))
			if braceIndex < 0 {
				return false
			}
			endIndex := matchingBrace(query, braceIndex)
			if endIndex < 0 {
				return false
			}
			imports := cloneScopedVariables(scopedVariables)
			pendingCallImports = imports
			subqueries = append(subqueries, subqueryScope{
				outer:     imports,
				imports:   imports,
				bodyStart: braceIndex + 1,
				end:       endIndex,
			})
			scopedVariables = map[string]struct{}{}
			i += len("CALL") - 1
			continue
		}
		if keywordAt(query, i, "WITH") {
			baseVariables := scopedVariables
			if pendingCallImports != nil {
				baseVariables = pendingCallImports
			}
			scopedVariables = scopedVariablesAfterWith(query, i+len("WITH"), baseVariables)
			pendingCallImports = nil
			i += len("WITH") - 1
			continue
		}
		if pendingCallImports != nil && !isWhitespaceOrSubqueryStart(query[i]) {
			pendingCallImports = nil
		}
		if keywordAt(query, i, "UNION") {
			scopedVariables = map[string]struct{}{}
			pendingCallImports = nil
			if len(subqueries) > 0 {
				pendingCallImports = cloneScopedVariables(subqueries[len(subqueries)-1].imports)
			}
			i += len("UNION") - 1
			continue
		}
		pattern, ok := nodePatternAt(query, i, false)
		if !ok {
			continue
		}
		sawNode = true
		if nodePatternHasInlineTenantScope(pattern) {
			if pattern.variable != "" && !expressionLocalPattern(query, i, len(subqueries)) {
				scopedVariables[pattern.variable] = struct{}{}
			}
			continue
		}
		if pattern.isBareVariableReference() {
			if _, ok := scopedVariables[pattern.variable]; ok {
				continue
			}
		}
		return false
	}
	return sawNode
}

func hasProcedureCall(query string) bool {
	for i := 0; i < len(query); i++ {
		if keywordAt(query, i, "CALL") && subqueryStartBrace(query, i+len("CALL")) < 0 {
			return true
		}
	}
	return false
}

func subqueryStartBrace(query string, start int) int {
	for i := start; i < len(query); i++ {
		if isWhitespace(query[i]) {
			continue
		}
		if query[i] == '{' {
			return i
		}
		return -1
	}
	return -1
}

func matchingBrace(query string, start int) int {
	depth := 0
	for i := start; i < len(query); i++ {
		switch query[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func matchClausesContainOnlyNodePatterns(query string) bool {
	clauses := matchClausePattern.FindAllStringIndex(query, -1)
	for i, clause := range clauses {
		start := clause[1]
		end := len(query)
		if i+1 < len(clauses) {
			end = clauses[i+1][0]
		}
		if boundary := matchClauseEndPattern.FindStringIndex(query[start:end]); boundary != nil {
			end = start + boundary[0]
		}
		if _, ok := nodePatternsInMatchClause(query[start:end]); !ok {
			return false
		}
	}
	return true
}

func nodePatternsInMatchClause(clause string) ([]nodePattern, bool) {
	return nodePatternsInText(clause, true)
}

func nodePatternsInText(text string, requireValid bool) ([]nodePattern, bool) {
	var patterns []nodePattern
	for i := 0; i < len(text); i++ {
		if text[i] != '(' || i > 0 && isIdentifierByte(text[i-1]) {
			continue
		}
		closeIndex := strings.IndexByte(text[i+1:], ')')
		if closeIndex < 0 {
			return nil, !requireValid
		}
		pattern, ok := parseNodePattern(text[i+1 : i+1+closeIndex])
		if !ok {
			if requireValid {
				return nil, false
			}
			continue
		}
		patterns = append(patterns, pattern)
	}
	return patterns, true
}

func nodePatternAt(text string, index int, requireValid bool) (nodePattern, bool) {
	if text[index] != '(' || index > 0 && isIdentifierByte(text[index-1]) {
		return nodePattern{}, false
	}
	closeIndex := strings.IndexByte(text[index+1:], ')')
	if closeIndex < 0 {
		return nodePattern{}, false
	}
	pattern, ok := parseNodePattern(text[index+1 : index+1+closeIndex])
	if !ok && requireValid {
		return nodePattern{}, false
	}
	return pattern, ok
}

func parseNodePattern(body string) (nodePattern, bool) {
	matches := nodeBodyPattern.FindStringSubmatch(body)
	if matches == nil {
		return nodePattern{}, false
	}
	return nodePattern{variable: strings.TrimSpace(matches[1]), labels: matches[2], properties: matches[3]}, true
}

func nodePatternHasInlineTenantScope(pattern nodePattern) bool {
	return nodeHasEntityLabel(pattern.labels) && inlineTenantPattern.MatchString(pattern.properties)
}

func (p nodePattern) isBareVariableReference() bool {
	return p.variable != "" && strings.TrimSpace(p.labels) == "" && strings.TrimSpace(p.properties) == ""
}

func nodeHasEntityLabel(labels string) bool {
	for _, label := range strings.Split(labels, ":") {
		if strings.EqualFold(strings.TrimSpace(label), "Entity") {
			return true
		}
	}
	return false
}

func scopedVariablesAfterWith(query string, start int, scopedVariables map[string]struct{}) map[string]struct{} {
	clause := query[start:withProjectionEnd(query, start)]
	next := map[string]struct{}{}
	for _, item := range splitProjectionItems(clause) {
		projectScopedVariable(next, scopedVariables, strings.TrimSpace(item))
	}
	return next
}

func scopedVariablesAfterReturn(query string, scopedVariables map[string]struct{}) map[string]struct{} {
	start := lastKeywordIndex(query, "RETURN")
	if start < 0 {
		return nil
	}
	start += len("RETURN")
	clause := query[start:withProjectionEnd(query, start)]
	next := map[string]struct{}{}
	for _, item := range splitProjectionItems(clause) {
		projectScopedVariable(next, scopedVariables, strings.TrimSpace(item))
	}
	return next
}

func lastKeywordIndex(query string, keyword string) int {
	result := -1
	for i := 0; i < len(query); i++ {
		if keywordAt(query, i, keyword) {
			result = i
			i += len(keyword) - 1
		}
	}
	return result
}

func cloneScopedVariables(scopedVariables map[string]struct{}) map[string]struct{} {
	clone := make(map[string]struct{}, len(scopedVariables))
	for variable := range scopedVariables {
		clone[variable] = struct{}{}
	}
	return clone
}

func mergeScopedVariables(left map[string]struct{}, right map[string]struct{}) map[string]struct{} {
	merged := cloneScopedVariables(left)
	for variable := range right {
		merged[variable] = struct{}{}
	}
	return merged
}

func withProjectionEnd(query string, start int) int {
	depth := 0
	for i := start; i < len(query); i++ {
		switch query[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && withClauseEndAt(query, i) {
			return i
		}
	}
	return len(query)
}

func withClauseEndAt(query string, index int) bool {
	for _, keyword := range []string{"OPTIONAL MATCH", "MATCH", "RETURN", "UNION", "CALL", "WHERE", "ORDER", "LIMIT", "SKIP"} {
		if keywordAt(query, index, keyword) {
			return true
		}
	}
	return false
}

func splitProjectionItems(clause string) []string {
	var items []string
	depth := 0
	start := 0
	for i := 0; i < len(clause); i++ {
		switch clause[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				items = append(items, clause[start:i])
				start = i + 1
			}
		}
	}
	items = append(items, clause[start:])
	return items
}

func projectScopedVariable(next map[string]struct{}, scopedVariables map[string]struct{}, item string) {
	item = trimLeadingKeyword(item, "DISTINCT")
	if item == "*" {
		for variable := range scopedVariables {
			next[variable] = struct{}{}
		}
		return
	}
	fields := strings.Fields(item)
	switch {
	case len(fields) == 1:
		if _, ok := scopedVariables[fields[0]]; ok {
			next[fields[0]] = struct{}{}
		}
	case len(fields) == 3 && strings.EqualFold(fields[1], "AS"):
		if _, ok := scopedVariables[fields[0]]; ok {
			next[fields[2]] = struct{}{}
		}
	}
}

func trimLeadingKeyword(text string, keyword string) string {
	text = strings.TrimSpace(text)
	if keywordAt(text, 0, keyword) {
		return strings.TrimSpace(text[len(keyword):])
	}
	return text
}

func keywordAt(query string, index int, keyword string) bool {
	if index+len(keyword) > len(query) || !strings.EqualFold(query[index:index+len(keyword)], keyword) {
		return false
	}
	if index > 0 && isIdentifierByte(query[index-1]) {
		return false
	}
	if next := index + len(keyword); next < len(query) && isIdentifierByte(query[next]) {
		return false
	}
	return true
}

func isWhitespaceOrSubqueryStart(value byte) bool {
	return isWhitespace(value) || value == '{'
}

func isWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r':
		return true
	default:
		return false
	}
}

func squareBracketDepthAt(query string, index int) int {
	depth := 0
	for i := 0; i < index; i++ {
		switch query[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

func expressionLocalPattern(query string, index int, callSubqueryDepth int) bool {
	return squareBracketDepthAt(query, index) > 0 || braceDepthAt(query, index) > callSubqueryDepth
}

func braceDepthAt(query string, index int) int {
	depth := 0
	for i := 0; i < index; i++ {
		switch query[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return depth
}

func isIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '_'
}

func allNodesScanOverLimit(plan *ports.CypherPlan, limit int) bool {
	if plan == nil || plan.Root == nil {
		return false
	}
	return planNodeAllNodesScanOverLimit(*plan.Root, limit)
}

func planNodeAllNodesScanOverLimit(node ports.CypherPlanNode, limit int) bool {
	if strings.EqualFold(strings.TrimSpace(node.Operator), "AllNodesScan") && anyArgumentNumberOverLimit(node.Arguments, limit) {
		return true
	}
	for _, child := range node.Children {
		if planNodeAllNodesScanOverLimit(child, limit) {
			return true
		}
	}
	return false
}

func anyArgumentNumberOverLimit(value any, limit int) bool {
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if anyArgumentNumberOverLimit(child, limit) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if anyArgumentNumberOverLimit(child, limit) {
				return true
			}
		}
	case int:
		return typed > limit
	case int64:
		return typed > int64(limit)
	case float64:
		return typed > float64(limit)
	case string:
		for _, raw := range numberPattern.FindAllString(typed, -1) {
			n, err := strconv.ParseFloat(raw, 64)
			if err == nil && n > float64(limit) {
				return true
			}
		}
	default:
		text := fmt.Sprint(typed)
		for _, raw := range numberPattern.FindAllString(text, -1) {
			n, err := strconv.ParseFloat(raw, 64)
			if err == nil && n > float64(limit) {
				return true
			}
		}
	}
	return false
}
