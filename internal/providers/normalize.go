package providers

import (
	"strings"
	"unicode"
)

func normalizeMapKeys(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		normalized := make(map[string]interface{}, len(typed))
		for key, val := range typed {
			normalized[toSnake(key)] = normalizeMapKeys(val)
		}
		return normalized
	case []interface{}:
		items := make([]interface{}, len(typed))
		for i, item := range typed {
			items[i] = normalizeMapKeys(item)
		}
		return items
	default:
		return value
	}
}

func toSnake(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	var builder strings.Builder
	builder.Grow(len(value) + 4)
	prevUnderscore := false
	prevLower := false
	prevDigit := false

	for _, r := range value {
		switch {
		case r == '-' || r == ' ' || r == '.' || r == '/':
			if !prevUnderscore && builder.Len() > 0 {
				builder.WriteRune('_')
				prevUnderscore = true
			}
			prevLower = false
			prevDigit = false
			continue
		case r == '_':
			if !prevUnderscore && builder.Len() > 0 {
				builder.WriteRune('_')
			}
			prevUnderscore = true
			prevLower = false
			prevDigit = false
			continue
		case unicode.IsUpper(r):
			if (prevLower || prevDigit) && !prevUnderscore {
				builder.WriteRune('_')
			}
			builder.WriteRune(unicode.ToLower(r))
			prevUnderscore = false
			prevLower = true
			prevDigit = false
		case unicode.IsDigit(r):
			if prevLower && !prevUnderscore {
				builder.WriteRune('_')
			}
			builder.WriteRune(r)
			prevUnderscore = false
			prevLower = false
			prevDigit = true
		default:
			builder.WriteRune(unicode.ToLower(r))
			prevUnderscore = false
			prevLower = true
			prevDigit = false
		}
	}

	return builder.String()
}
