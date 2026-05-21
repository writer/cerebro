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
	labels     string
	properties string
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
		return ValidatorResult{OK: false, Reason: "cypher is required"}, 0, nil
	}
	safeQuery := scrubCypher(query)
	if forbiddenTokenPattern.MatchString(safeQuery) || loadCSVPattern.MatchString(safeQuery) || usingPeriodicPattern.MatchString(safeQuery) {
		return ValidatorResult{OK: false, Reason: "write or bulk-load Cypher clauses are forbidden"}, 0, nil
	}
	if forbiddenAPOCPattern.MatchString(safeQuery) {
		return ValidatorResult{OK: false, Reason: "apoc trigger and periodic procedures are forbidden"}, 0, nil
	}
	limit, ok := queryLimit(safeQuery)
	if !ok {
		return ValidatorResult{OK: false, Reason: "read Cypher must include a numeric LIMIT clause"}, 0, nil
	}
	if limit > v.options.MaxRows {
		return ValidatorResult{OK: false, Reason: fmt.Sprintf("LIMIT %d exceeds maximum %d", limit, v.options.MaxRows)}, 0, nil
	}
	if !allNodePatternsTenantScoped(safeQuery) {
		return ValidatorResult{OK: false, Reason: "every node pattern must use Entity label and inline tenant_id"}, 0, nil
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
			return ValidatorResult{OK: false, Reason: fmt.Sprintf("EXPLAIN plan contains AllNodesScan over more than %d nodes", v.options.AllNodesScanLimit)}, 0, nil
		}
	}
	return ValidatorResult{OK: true}, limit, nil
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
	patterns, ok := graphNodePatterns(query)
	if !ok || len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if !nodeHasEntityLabel(pattern.labels) || !inlineTenantPattern.MatchString(pattern.properties) {
			return false
		}
	}
	return true
}

func graphNodePatterns(query string) ([]nodePattern, bool) {
	var patterns []nodePattern
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
		extracted, ok := nodePatternsInMatchClause(query[start:end])
		if !ok {
			return nil, false
		}
		patterns = append(patterns, extracted...)
	}
	return patterns, true
}

func nodePatternsInMatchClause(clause string) ([]nodePattern, bool) {
	var patterns []nodePattern
	for i := 0; i < len(clause); i++ {
		if clause[i] != '(' || isIdentifierByte(previousNonSpace(clause, i)) {
			continue
		}
		closeIndex := strings.IndexByte(clause[i+1:], ')')
		if closeIndex < 0 {
			return nil, false
		}
		body := clause[i+1 : i+1+closeIndex]
		pattern, ok := parseNodePattern(body)
		if !ok {
			return nil, false
		}
		patterns = append(patterns, pattern)
	}
	return patterns, true
}

func parseNodePattern(body string) (nodePattern, bool) {
	matches := nodeBodyPattern.FindStringSubmatch(body)
	if matches == nil {
		return nodePattern{}, false
	}
	return nodePattern{labels: matches[2], properties: matches[3]}, true
}

func nodeHasEntityLabel(labels string) bool {
	for _, label := range strings.Split(labels, ":") {
		if strings.EqualFold(strings.TrimSpace(label), "Entity") {
			return true
		}
	}
	return false
}

func previousNonSpace(text string, index int) byte {
	for i := index - 1; i >= 0; i-- {
		switch text[i] {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return text[i]
		}
	}
	return 0
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
