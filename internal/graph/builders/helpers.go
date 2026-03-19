package builders

import (
	"strings"
	"time"
)

var temporalNowUTC = func() time.Time {
	return time.Now().UTC()
}

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
