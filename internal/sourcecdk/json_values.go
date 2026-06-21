package sourcecdk

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// JSONScalarString coerces a decoded JSON scalar (string, json.Number, float64,
// or bool) into a trimmed string. Strings and json.Number values are trimmed of
// surrounding whitespace, float64 values are formatted without an exponent, and
// bool values become "true"/"false". Any other value, including nil, maps, and
// slices, yields the empty string.
func JSONScalarString(value interface{}) string {
	switch typed := value.(type) {
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

// ParseScalarTime coerces value to a string via JSONScalarString and parses it
// against layouts in order, returning the first successful parse normalized to
// UTC. A zero Time is returned when value is empty or matches no layout.
func ParseScalarTime(value interface{}, layouts ...string) time.Time {
	raw := strings.TrimSpace(JSONScalarString(value))
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
