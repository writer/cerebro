package sourcecdk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// JSONScalar boxes a decoded JSON value (as produced by encoding/json into a
// map[string]any) so it can be coerced to typed forms at a source boundary
// without exposing an untyped parameter in an exported signature.
type JSONScalar struct {
	Value any
}

// JSONArray wraps a decoded JSON array at a source boundary.
type JSONArray []any

// FieldString returns a flattened string for a dot-separated field path.
func (o JSONObject) FieldString(path string) string {
	value, ok := o.fieldValue(path)
	if !ok {
		return ""
	}
	return (JSONScalar{Value: value}).SourceString()
}

func (o JSONObject) fieldValue(path string) (any, bool) {
	var current any = map[string]any(o)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// Array returns an array field from a decoded JSON object.
func (o JSONObject) Array(key string) JSONArray {
	value, ok := o[key]
	if !ok {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	return JSONArray(items)
}

// SourceString flattens a decoded JSON value to the source-normalized string
// form used by connector boundaries, including array joins and common display
// fields from nested objects.
func (s JSONScalar) SourceString() string {
	switch typed := s.Value.(type) {
	case nil:
		return ""
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := (JSONScalar{Value: item}).SourceString(); value != "" {
				values = append(values, value)
			}
		}
		return strings.Join(values, ",")
	case map[string]any:
		for _, key := range []string{"displayName", "name", "id", "email"} {
			if value := (JSONScalar{Value: typed[key]}).SourceString(); value != "" {
				return value
			}
		}
		return ""
	default:
		return s.Flattened()
	}
}

// String coerces the boxed scalar (string, json.Number, float64, or bool) into a
// trimmed string. json.Number and string values are whitespace-trimmed, float64
// values are formatted without an exponent, and bool values become
// "true"/"false". Any other value, including nil, maps, and slices, yields "".
func (s JSONScalar) String() string {
	switch typed := s.Value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

// Time coerces the boxed scalar to a string and parses it against layouts in
// order, returning the first successful parse normalized to UTC. A zero Time is
// returned when the value is empty or matches no layout.
func (s JSONScalar) Time(layouts ...string) time.Time {
	raw := strings.TrimSpace(s.String())
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

// Flattened renders the boxed JSON value as a string. Scalar values follow the
// same rules as String; []any values become their comma-joined non-empty
// elements; any other value is rendered via fmt.Sprint and trimmed.
func (s JSONScalar) Flattened() string {
	switch v := s.Value.(type) {
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if value := (JSONScalar{Value: item}).Flattened(); value != "" {
				parts = append(parts, value)
			}
		}
		return strings.Join(parts, ",")
	case nil, string, float64, bool:
		return s.String()
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}
