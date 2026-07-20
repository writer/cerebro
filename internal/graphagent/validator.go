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

var numberPattern = regexp.MustCompile(`\d+(?:\.\d+)?`)

var (
	runtimeLimitKeywordPattern = regexp.MustCompile(`(?i:\blimit\b)`)
	runtimeLimitClausePattern  = regexp.MustCompile(`(?i:\blimit\b)[ \t\r\n]+\$row_limit\b`)
)

type ValidatorOptions struct {
	MaxRows           int
	AllNodesScanLimit int
	Explain           bool
	DisableExplain    bool
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
	if !options.DisableExplain && store != nil {
		if _, ok := store.(interface {
			ExplainReadCypher(context.Context, ports.CypherQueryRequest) (*ports.CypherPlan, error)
		}); ok {
			options.Explain = true
		}
	}
	return &Validator{store: store, options: options}
}

// ValidateRuntimeBoundReadCypher applies the hardened static validator to a
// query whose LIMIT is supplied by the caller as $row_limit. Every LIMIT clause
// must use that exact parameter so proof and shadow callers can raise the bound
// by one to detect truncation without trusting an authored numeric cap.
func ValidateRuntimeBoundReadCypher(ctx context.Context, cypher string, maxRows int) (ValidatorResult, int, error) {
	if maxRows <= 0 {
		return validatorRefusal("runtime_limit_invalid", "runtime row limit must be positive"), 0, nil
	}
	rewritten, ok := rewriteRuntimeBoundLimits(cypher, maxRows)
	if !ok {
		return validatorRefusal("runtime_limit_required", "every LIMIT clause must use the exact $row_limit parameter"), 0, nil
	}
	return NewValidator(nil, ValidatorOptions{MaxRows: maxRows, DisableExplain: true}).validate(ctx, rewritten, nil)
}

func rewriteRuntimeBoundLimits(cypher string, maxRows int) (string, bool) {
	scrubbed := scrubCypherLiteralsAndComments(cypher)
	limitKeywords := runtimeLimitKeywordPattern.FindAllStringIndex(scrubbed, -1)
	runtimeLimits := runtimeLimitClausePattern.FindAllStringIndex(scrubbed, -1)
	if len(runtimeLimits) == 0 || len(limitKeywords) != len(runtimeLimits) {
		return "", false
	}
	rewritten := cypher
	replacement := strconv.Itoa(maxRows)
	for index := len(runtimeLimits) - 1; index >= 0; index-- {
		clause := runtimeLimits[index]
		parameterOffset := strings.LastIndex(scrubbed[clause[0]:clause[1]], "$row_limit")
		if parameterOffset < 0 {
			return "", false
		}
		start := clause[0] + parameterOffset
		end := start + len("$row_limit")
		rewritten = rewritten[:start] + replacement + rewritten[end:]
	}
	return rewritten, true
}

// scrubCypherLiteralsAndComments preserves byte offsets while hiding tokens
// that cannot be Cypher clauses. The embedded validator remains the authority
// for query safety; this scrubber only identifies the caller-bound LIMIT slots.
func scrubCypherLiteralsAndComments(query string) string {
	input := []byte(query)
	output := append([]byte(nil), input...)
	blank := func(start, end int) {
		for index := start; index < end; index++ {
			if output[index] != '\n' && output[index] != '\r' {
				output[index] = ' '
			}
		}
	}
	for index := 0; index < len(input); {
		switch {
		case input[index] == '\'' || input[index] == '"':
			quote, start := input[index], index
			index++
			for index < len(input) {
				if input[index] == '\\' && index+1 < len(input) {
					index += 2
					continue
				}
				if input[index] == quote {
					if index+1 < len(input) && input[index+1] == quote {
						index += 2
						continue
					}
					index++
					break
				}
				index++
			}
			blank(start, index)
		case input[index] == '`':
			start := index
			index++
			for index < len(input) {
				if input[index] == '`' {
					if index+1 < len(input) && input[index+1] == '`' {
						index += 2
						continue
					}
					index++
					break
				}
				index++
			}
			blank(start, index)
		case input[index] == '/' && index+1 < len(input) && input[index+1] == '/':
			start := index
			index += 2
			for index < len(input) && input[index] != '\n' && input[index] != '\r' {
				index++
			}
			blank(start, index)
		case input[index] == '/' && index+1 < len(input) && input[index+1] == '*':
			start := index
			index += 2
			for index+1 < len(input) && (input[index] != '*' || input[index+1] != '/') {
				index++
			}
			if index+1 < len(input) {
				index += 2
			} else {
				index = len(input)
			}
			blank(start, index)
		default:
			index++
		}
	}
	return string(output)
}

func (v *Validator) validate(ctx context.Context, cypher string, params map[string]any) (ValidatorResult, int, error) {
	query := strings.TrimSpace(cypher)
	static, err := runStaticValidator(ctx, query, v.options.MaxRows)
	if err != nil {
		return ValidatorResult{}, 0, err
	}
	result, limit, err := staticValidationResult(static, v.options.MaxRows)
	if err != nil || !result.OK {
		return result, limit, err
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
	return result, limit, nil
}

func validatorRefusal(code string, reason string) ValidatorResult {
	return ValidatorResult{OK: false, Code: code, Reason: reason}
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
