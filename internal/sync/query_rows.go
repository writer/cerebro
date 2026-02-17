package sync

import "strings"

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
	return stringValue(value)
}

func queryRow(row map[string]interface{}, key string) interface{} {
	value, _ := queryRowValue(row, key)
	return value
}

func decodeExistingHashes(rows []map[string]interface{}) map[string]string {
	result := make(map[string]string, len(rows))
	for _, row := range rows {
		id := queryRowString(row, "_cq_id")
		if id == "" {
			continue
		}
		result[id] = queryRowString(row, "_cq_hash")
	}
	return result
}
