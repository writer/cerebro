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
	entityPattern         = regexp.MustCompile(`(?is)\(\s*([A-Za-z_][A-Za-z0-9_]*)?\s*:\s*Entity\b([^)]*)\)`)
	inlineTenantPattern   = regexp.MustCompile(`(?i)\btenant_id\s*:\s*\$tenant_id\b`)
	quotedLiteralPattern  = regexp.MustCompile(`'[^']*'|"[^"]*"`)
	commentPattern        = regexp.MustCompile(`(?m)//.*$|/\*.*?\*/`)
	numberPattern         = regexp.MustCompile(`\d+(?:\.\d+)?`)
)

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
	if !allEntityPatternsTenantScoped(safeQuery) {
		return ValidatorResult{OK: false, Reason: "every Entity pattern must filter by tenant_id"}, 0, nil
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

func allEntityPatternsTenantScoped(query string) bool {
	matches := entityPattern.FindAllStringSubmatch(query, -1)
	if len(matches) == 0 {
		return false
	}
	for _, match := range matches {
		if inlineTenantPattern.MatchString(match[2]) {
			continue
		}
		variable := strings.TrimSpace(match[1])
		if variable == "" || !variableHasTenantPredicate(query, variable) {
			return false
		}
	}
	return true
}

func variableHasTenantPredicate(query string, variable string) bool {
	escaped := regexp.QuoteMeta(variable)
	pattern := regexp.MustCompile(`(?i)(?:\b` + escaped + `\.tenant_id\s*=\s*\$tenant_id|\$tenant_id\s*=\s*\b` + escaped + `\.tenant_id)`)
	return pattern.MatchString(query)
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
