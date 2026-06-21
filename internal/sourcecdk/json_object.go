package sourcecdk

import (
	"encoding/json"
	"strconv"
	"strings"
)

// JSONObject is a decoded JSON object whose values are still untyped. It gives
// sources typed scalar reads over provider payloads without leaking
// map[string]any across an exported Source CDK boundary; callers convert a
// decoded object with sourcecdk.JSONObject(raw) and read fields by key.
type JSONObject map[string]any

// String returns the trimmed string at key, or "" when the value is absent or
// is not a JSON string.
func (o JSONObject) String(key string) string {
	value, ok := o[key]
	if !ok {
		return ""
	}
	stringValue, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(stringValue)
}

// ScalarString renders the scalar at key as a string: strings are trimmed,
// booleans and JSON numbers are formatted, and nested objects/arrays are
// re-encoded as JSON. Absent values and unsupported shapes return "".
func (o JSONObject) ScalarString(key string) string {
	value, ok := o[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case map[string]any, []any:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	default:
		return ""
	}
}

// Bool returns the boolean at key, or false when the value is absent or is not
// a JSON boolean.
func (o JSONObject) Bool(key string) bool {
	value, ok := o[key]
	if !ok {
		return false
	}
	boolValue, ok := value.(bool)
	if !ok {
		return false
	}
	return boolValue
}

// BoolString renders the boolean at key as "true"/"false", or "" when the value
// is absent or is not a JSON boolean.
func (o JSONObject) BoolString(key string) string {
	value, ok := o[key]
	if !ok {
		return ""
	}
	boolValue, ok := value.(bool)
	if !ok {
		return ""
	}
	return strconv.FormatBool(boolValue)
}

// Int64 reads a numeric field as int64. JSON numbers decode to float64 inside an
// untyped object, so this coerces float64/int/int64/json.Number/string forms to
// a stable int64 and returns 0 for absent, nil, or non-numeric values.
func (o JSONObject) Int64(key string) int64 {
	value, ok := o[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int:
		return int64(typed)
	case int64:
		return typed
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0
		}
		return parsed
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}
