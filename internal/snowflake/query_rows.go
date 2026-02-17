package snowflake

import (
	"strings"
	"time"
)

func queryRowValue(row map[string]interface{}, key string) (interface{}, bool) {
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

func queryRowString(row map[string]interface{}, key string) string {
	value, ok := queryRowValue(row, key)
	if !ok {
		return ""
	}
	return toString(value)
}

func queryRowTime(row map[string]interface{}, key string) time.Time {
	value, ok := queryRowValue(row, key)
	if !ok {
		return time.Time{}
	}
	return toTime(value)
}
