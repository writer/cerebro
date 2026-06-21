package sourcecdk

import (
	"encoding/json"
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
