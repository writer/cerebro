package policy

import (
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
