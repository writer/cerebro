package builders

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

var temporalNowUTC = func() time.Time {
	return time.Now().UTC()
}

const entityAssetNormalizerSourceSystem = "platform.normalizer"

func queryRowValue(row map[string]any, key string) (any, bool) {
	if row == nil {
		return nil, false
	}

	normalized := strings.ToLower(strings.TrimSpace(key))
	if normalized == "" {
		return nil, false
	}

	if value, ok := row[normalized]; ok {
		return value, true
	}
	if value, ok := row[key]; ok {
		return value, true
	}

	for rowKey, value := range row {
		if strings.EqualFold(rowKey, key) {
			return value, true
		}
	}

	return nil, false
}

func queryRowString(row map[string]any, key string) string {
	value, ok := queryRowValue(row, key)
	if !ok {
		return ""
	}
	return toString(value)
}

func queryRow(row map[string]any, key string) any {
	value, _ := queryRowValue(row, key)
	return value
}

func readString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if values == nil {
			return ""
		}
		if value, ok := values[key]; ok {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return strings.TrimSpace(typed)
				}
			case fmt.Stringer:
				return strings.TrimSpace(typed.String())
			default:
				return strings.TrimSpace(fmt.Sprintf("%v", typed))
			}
		}
	}
	return ""
}

func slugifyKnowledgeKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "unknown"
	}
	var builder strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(r)
			lastDash = false
		case !lastDash:
			builder.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(builder.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func cloneAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = cloneAny(value)
	}
	return cloned
}

func cloneAny(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneAnyMap(v)
	case []any:
		cloned := make([]any, len(v))
		for i := range v {
			cloned[i] = cloneAny(v[i])
		}
		return cloned
	case []string:
		return append([]string(nil), v...)
	default:
		return value
	}
}
