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
