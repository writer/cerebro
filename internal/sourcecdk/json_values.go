package sourcecdk

import (
	"encoding/json"
	"fmt"
	"sort"
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

// FieldTime returns the first field among keys, in order, whose flattened
// string value parses against one of layouts (see JSONScalar.Time),
// normalized to UTC. It returns a zero Time when no key is present or none
// of the present values parse, so a source can apply its own deterministic
// fallback (e.g. a fixed default or time.Now()) instead of silently picking
// an arbitrary key.
func (o JSONObject) FieldTime(layouts []string, keys ...string) time.Time {
	for _, key := range keys {
		if parsed := (JSONScalar{Value: o.FieldString(key)}).Time(layouts...); !parsed.IsZero() {
			return parsed
		}
	}
	return time.Time{}
}

// CopyFields sets attrs[attr] = FieldString(field) for each attr/field pair
// in fields whenever that flattened value is non-empty, leaving an attr
// absent from attrs when its source field is missing or blank rather than
// present with an empty value.
func (o JSONObject) CopyFields(attrs map[string]string, fields map[string]string) {
	for attr, field := range fields {
		if value := o.FieldString(field); value != "" {
			attrs[attr] = value
		}
	}
}

// FirstFieldString returns the first non-empty flattened field value among
// keys, in order.
func (o JSONObject) FirstFieldString(keys ...string) string {
	for _, key := range keys {
		if value := o.FieldString(key); value != "" {
			return value
		}
	}
	return ""
}

// JoinFieldsIfAllPresent joins the flattened values of keys, in order, with
// sep -- or returns "" the moment any key's flattened value is empty, so a
// qualified identifier built from several required fields is never emitted
// half-populated.
func (o JSONObject) JoinFieldsIfAllPresent(sep string, keys ...string) string {
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := o.FieldString(key)
		if value == "" {
			return ""
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, sep)
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

// Nested returns the nested object at key as a JSONObject, or an empty one
// when the value is absent or not a JSON object, so a caller can chain
// further Field*/Array reads on a sub-object without its own type assertion.
func (o JSONObject) Nested(key string) JSONObject {
	nested, _ := o[key].(map[string]any)
	return JSONObject(nested)
}

// JoinObjects renders each object element with format and joins the
// non-empty renderings with sep, in array order. Non-object elements are
// skipped, so a source can flatten a bounded array of records into one
// attribute without hand-rolling the iteration and type checks.
func (a JSONArray) JoinObjects(sep string, format func(JSONObject) string) string {
	parts := make([]string, 0, len(a))
	for _, item := range a {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if part := format(JSONObject(object)); part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, sep)
}

// SortedJoinObjects renders each object element with format exactly like
// JoinObjects, but lexically sorts the non-empty renderings before joining
// them with sep, so a caller needing a deterministic, order-independent
// summary (for example a provenance attribute keyed by kind:id pairs) does
// not have to sort the array itself.
func (a JSONArray) SortedJoinObjects(sep string, format func(JSONObject) string) string {
	parts := make([]string, 0, len(a))
	for _, item := range a {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if part := format(JSONObject(object)); part != "" {
			parts = append(parts, part)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, sep)
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
