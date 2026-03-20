package policy

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func policyConditionCELLibrary() cel.EnvOption {
	return cel.Lib(policyConditionCELLib{})
}

type policyConditionCELLib struct{}

func (policyConditionCELLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("path",
			cel.Overload("cerebro_path_dyn_string", []*cel.Type{cel.DynType, cel.StringType}, cel.DynType,
				cel.BinaryBinding(func(root, path ref.Val) ref.Val {
					return nativeToCELValue(pathValue(celRefToNative(root), celStringValue(path)))
				}))),
		cel.Function("exists_path",
			cel.Overload("cerebro_exists_path_dyn_string", []*cel.Type{cel.DynType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(root, path ref.Val) ref.Val {
					return types.Bool(existsPath(celRefToNative(root), celStringValue(path)))
				}))),
		cel.Function("list_value",
			cel.Overload("cerebro_list_value_dyn", []*cel.Type{cel.DynType}, cel.DynType,
				cel.UnaryBinding(func(value ref.Val) ref.Val {
					return nativeToCELValue(listValue(celRefToNative(value)))
				}))),
		cel.Function("contains_value",
			cel.Overload("cerebro_contains_value_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(valueContainsExpected(celRefToNative(value), celRefToNative(expected)))
				}))),
		cel.Function("matches_value",
			cel.Overload("cerebro_matches_value_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, pattern ref.Val) ref.Val {
					return types.Bool(valueMatchesPattern(celRefToNative(value), stringifyExpected(celRefToNative(pattern))))
				}))),
		cel.Function("starts_with_value",
			cel.Overload("cerebro_starts_with_value_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, prefix ref.Val) ref.Val {
					prefixStr := stringifyExpected(celRefToNative(prefix))
					actual, ok := celRefToNative(value).(string)
					return types.Bool(ok && strings.HasPrefix(actual, prefixStr))
				}))),
		cel.Function("ends_with_value",
			cel.Overload("cerebro_ends_with_value_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, suffix ref.Val) ref.Val {
					return types.Bool(valueEndsWith(celRefToNative(value), stringifyExpected(celRefToNative(suffix))))
				}))),
		cel.Function("references_public_bucket",
			cel.Overload("cerebro_references_public_bucket_dyn_string", []*cel.Type{cel.DynType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(root, path ref.Val) ref.Val {
					return types.Bool(referencesPublicBucket(celRefToNative(root), celStringValue(path)))
				}))),
		cel.Function("in_list",
			cel.Overload("cerebro_in_list_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(valueInList(celRefToNative(value), toStringList(celRefToNative(expected))))
				}))),
		cel.Function("cmp_eq",
			cel.Overload("cerebro_cmp_eq_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(compareValues(celRefToNative(value), celRefToNative(expected), "=="))
				}))),
		cel.Function("cmp_ne",
			cel.Overload("cerebro_cmp_ne_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(compareValues(celRefToNative(value), celRefToNative(expected), "!="))
				}))),
		cel.Function("cmp_gt",
			cel.Overload("cerebro_cmp_gt_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(compareValues(celRefToNative(value), celRefToNative(expected), ">"))
				}))),
		cel.Function("cmp_ge",
			cel.Overload("cerebro_cmp_ge_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(compareValues(celRefToNative(value), celRefToNative(expected), ">="))
				}))),
		cel.Function("cmp_lt",
			cel.Overload("cerebro_cmp_lt_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(compareValues(celRefToNative(value), celRefToNative(expected), "<"))
				}))),
		cel.Function("cmp_le",
			cel.Overload("cerebro_cmp_le_dyn_dyn", []*cel.Type{cel.DynType, cel.DynType}, cel.BoolType,
				cel.BinaryBinding(func(value, expected ref.Val) ref.Val {
					return types.Bool(compareValues(celRefToNative(value), celRefToNative(expected), "<="))
				}))),
	}
}

func (policyConditionCELLib) ProgramOptions() []cel.ProgramOption {
	return nil
}

func celRefToNative(value ref.Val) interface{} {
	if value == nil || value == types.NullValue {
		return nil
	}
	native, err := value.ConvertToNative(reflect.TypeOf((*interface{})(nil)).Elem())
	if err == nil {
		return normalizeCELNative(native)
	}
	return normalizeCELNative(value.Value())
}

func nativeToCELValue(value interface{}) ref.Val {
	if value == nil {
		return types.NullValue
	}
	return types.DefaultTypeAdapter.NativeToValue(normalizeCELNative(value))
}

func celStringValue(value ref.Val) string {
	if value == nil || value == types.NullValue {
		return ""
	}
	if s, ok := celRefToNative(value).(string); ok {
		return s
	}
	return fmt.Sprintf("%v", celRefToNative(value))
}

func normalizeCELNative(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			out[k] = normalizeCELNative(v)
		}
		return out
	case map[ref.Val]ref.Val:
		out := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			out[fmt.Sprintf("%v", celRefToNative(k))] = normalizeCELNative(celRefToNative(v))
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(typed))
		for k, v := range typed {
			out[fmt.Sprintf("%v", k)] = normalizeCELNative(v)
		}
		return out
	case []ref.Val:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeCELNative(celRefToNative(item)))
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeCELNative(item))
		}
		return out
	default:
		return typed
	}
}

func pathValue(root interface{}, path string) interface{} {
	root = normalizeCELNative(root)
	if path == "" {
		return root
	}

	switch typed := root.(type) {
	case map[string]interface{}:
		return getNestedValue(typed, path)
	case string:
		parsed := normalizeCELNative(tryParseJSON(typed))
		if mapped, ok := parsed.(map[string]interface{}); ok {
			return getNestedValue(mapped, path)
		}
	}

	return nil
}

func existsPath(root interface{}, path string) bool {
	return pathValue(root, path) != nil
}

func listValue(value interface{}) []interface{} {
	value = normalizeCELNative(value)
	switch typed := value.(type) {
	case []interface{}:
		return typed
	case string:
		parsed := normalizeCELNative(tryParseJSON(typed))
		if arr, ok := parsed.([]interface{}); ok {
			return arr
		}
	}
	return []interface{}{}
}

func stringifyExpected(value interface{}) string {
	switch typed := normalizeCELNative(value).(type) {
	case nil:
		return "null"
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func toStringList(value interface{}) []string {
	value = normalizeCELNative(value)
	switch typed := value.(type) {
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, stringifyExpected(item))
		}
		return out
	default:
		return nil
	}
}

func ConvertPolicyToCEL(p *Policy) (*Policy, error) {
	if p == nil {
		return nil, fmt.Errorf("policy is required")
	}
	converted := *p
	converted.ConditionFormat = normalizeConditionFormat(converted.ConditionFormat)
	if converted.ConditionFormat == ConditionFormatCEL {
		return &converted, nil
	}
	conditions, err := ConvertLegacyConditionsToCEL(converted.Conditions)
	if err != nil {
		return nil, err
	}
	converted.Conditions = conditions
	converted.ConditionFormat = ConditionFormatCEL
	return &converted, nil
}

func ConvertLegacyConditionsToCEL(conditions []string) ([]string, error) {
	converted := make([]string, 0, len(conditions))
	for i, condition := range conditions {
		expr, err := convertLegacyConditionToCEL(condition, "resource")
		if err != nil {
			return nil, fmt.Errorf("condition %d: %w", i+1, err)
		}
		converted = append(converted, expr)
	}
	return converted, nil
}

func convertLegacyConditionToCEL(condition string, root string) (string, error) {
	condition = trimOuterParens(normalizeLogicalOperators(strings.TrimSpace(condition)))
	if condition == "" {
		return "", fmt.Errorf("condition must not be empty")
	}

	if parts := splitTopLevel(condition, " OR "); len(parts) > 1 {
		return joinConvertedConditions(parts, root, "||")
	}
	if parts := splitTopLevel(condition, " AND "); len(parts) > 1 {
		return joinConvertedConditions(parts, root, "&&")
	}

	if field, inner, negated, ok := parseAnyCondition(condition); ok {
		innerExpr, err := convertLegacyConditionToCEL(inner, "item")
		if err != nil {
			return "", err
		}
		expr := fmt.Sprintf("list_value(path(%s, %s)).exists(item, %s)", root, celJSONString(field), innerExpr)
		if negated {
			return "!(" + expr + ")", nil
		}
		return expr, nil
	}

	if field, values, negated, ok := parseInCondition(condition); ok {
		expr := fmt.Sprintf("in_list(path(%s, %s), %s)", root, celJSONString(field), celJSONValue(values))
		if negated {
			return "!(" + expr + ")", nil
		}
		return expr, nil
	}

	if field, pattern, negated, ok := parseMatchesCondition(condition); ok {
		expr := fmt.Sprintf("matches_value(path(%s, %s), %s)", root, celJSONString(field), celJSONString(trimQuotes(pattern)))
		if negated {
			return "!(" + expr + ")", nil
		}
		return expr, nil
	}

	if field, expected, negated, ok := parseContainsCondition(condition); ok {
		expected = strings.TrimSpace(expected)
		var expr string
		if mapped, ok := parseLegacyObjectLiteral(expected); ok {
			expr = fmt.Sprintf("contains_value(path(%s, %s), %s)", root, celJSONString(field), celJSONValue(mapped))
		} else if !isQuoted(expected) && isOuterParens(expected) {
			inner := trimOuterParens(expected)
			if shouldTreatContainsInnerAsCondition(inner) {
				innerExpr, err := convertLegacyConditionToCEL(inner, "item")
				if err != nil {
					return "", err
				}
				expr = fmt.Sprintf("list_value(path(%s, %s)).exists(item, %s)", root, celJSONString(field), innerExpr)
			} else if mapped, ok := parseLegacyObjectLiteral(inner); ok {
				expr = fmt.Sprintf("contains_value(path(%s, %s), %s)", root, celJSONString(field), celJSONValue(mapped))
			} else {
				expr = fmt.Sprintf("contains_value(path(%s, %s), %s)", root, celJSONString(field), celLegacyLiteral(inner))
			}
		} else {
			expr = fmt.Sprintf("contains_value(path(%s, %s), %s)", root, celJSONString(field), celLegacyLiteral(expected))
		}
		if negated {
			return "!(" + expr + ")", nil
		}
		return expr, nil
	}

	if field, notNull, ok := parseNullCondition(condition); ok {
		if notNull {
			return fmt.Sprintf("exists_path(%s, %s)", root, celJSONString(field)), nil
		}
		return fmt.Sprintf("!exists_path(%s, %s)", root, celJSONString(field)), nil
	}

	if field, suffix, negated, ok := parseEndsWithCondition(condition); ok {
		expr := fmt.Sprintf("ends_with_value(path(%s, %s), %s)", root, celJSONString(field), celJSONString(trimQuotes(suffix)))
		if negated {
			return "!(" + expr + ")", nil
		}
		return expr, nil
	}

	if field, ok := parseReferenceBucketWithPublicAccessCondition(condition); ok {
		return fmt.Sprintf("references_public_bucket(%s, %s)", root, celJSONString(field)), nil
	}

	if field, expected, operator, ok := parseComparisonCondition(condition); ok {
		fn, err := comparisonOperatorFunction(operator)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s(path(%s, %s), %s)", fn, root, celJSONString(field), celLegacyOperand(expected, root)), nil
	}

	if parts := splitTopLevelFold(condition, " starts_with "); len(parts) == 2 {
		field := strings.TrimSpace(parts[0])
		prefix := trimQuotes(strings.TrimSpace(parts[1]))
		if field == "" || prefix == "" {
			return "", fmt.Errorf("unsupported starts_with condition %q", condition)
		}
		return fmt.Sprintf("starts_with_value(path(%s, %s), %s)", root, celJSONString(field), celJSONString(prefix)), nil
	}

	lower := strings.ToLower(condition)
	if strings.HasSuffix(lower, " not exists") {
		field := strings.TrimSpace(condition[:len(condition)-len(" not exists")])
		return fmt.Sprintf("!exists_path(%s, %s)", root, celJSONString(field)), nil
	}
	if strings.HasSuffix(lower, " exists") {
		field := strings.TrimSpace(condition[:len(condition)-len(" exists")])
		return fmt.Sprintf("exists_path(%s, %s)", root, celJSONString(field)), nil
	}

	return "", fmt.Errorf("unsupported legacy condition %q", condition)
}

func joinConvertedConditions(parts []string, root, operator string) (string, error) {
	converted := make([]string, 0, len(parts))
	for _, part := range parts {
		partExpr, err := convertLegacyConditionToCEL(part, root)
		if err != nil {
			return "", err
		}
		converted = append(converted, "("+partExpr+")")
	}
	return strings.Join(converted, " "+operator+" "), nil
}

func comparisonOperatorFunction(operator string) (string, error) {
	switch operator {
	case "==":
		return "cmp_eq", nil
	case "!=":
		return "cmp_ne", nil
	case ">":
		return "cmp_gt", nil
	case ">=":
		return "cmp_ge", nil
	case "<":
		return "cmp_lt", nil
	case "<=":
		return "cmp_le", nil
	default:
		return "", fmt.Errorf("unsupported comparison operator %q", operator)
	}
}

func celJSONString(value string) string {
	return celJSONValue(value)
}

func celJSONValue(value interface{}) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(encoded)
}

func celLegacyLiteral(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "null"
	}
	if isQuoted(trimmed) {
		return celJSONString(trimQuotes(trimmed))
	}

	switch strings.ToLower(trimmed) {
	case "true", "false":
		return strings.ToLower(trimmed)
	case "null", "nil":
		return "null"
	}

	if _, err := parseFloat64(trimmed); err == nil {
		return trimmed
	}

	return celJSONString(trimmed)
}

func celLegacyOperand(value string, root string) string {
	trimmed := strings.TrimSpace(value)
	if looksLikeFieldReference(trimmed) {
		return fmt.Sprintf("path(%s, %s)", root, celJSONString(trimmed))
	}
	return celLegacyLiteral(trimmed)
}
