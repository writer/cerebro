package tools

import (
	"strconv"
	"strings"
	"time"
)

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstPresent(snapshot map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := nestedValue(snapshot, key); ok {
			return value
		}
	}
	return nil
}

func nestedValue(snapshot map[string]any, path string) (any, bool) {
	current := any(snapshot)
	for _, part := range strings.Split(path, ".") {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := asMap[part]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func parseTimeValue(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return typed.UTC(), true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02"} {
			if ts, err := time.Parse(layout, trimmed); err == nil {
				return ts.UTC(), true
			}
		}
		if unix, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return unixToTime(unix), true
		}
		return time.Time{}, false
	case int:
		return unixToTime(int64(typed)), true
	case int64:
		return unixToTime(typed), true
	case float64:
		return unixToTime(int64(typed)), true
	default:
		return time.Time{}, false
	}
}

func unixToTime(unix int64) time.Time {
	if unix > 1_000_000_000_000 {
		return time.UnixMilli(unix).UTC()
	}
	return time.Unix(unix, 0).UTC()
}

func mapFromAny(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	default:
		return map[string]any{}
	}
}

func toInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0
		}
		return parsed
	default:
		return 0
	}
}

func StringValue(value any) string {
	return stringValue(value)
}
