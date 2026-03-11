package sync

import "strings"

const queryRowLookupCacheKey = "\x00cerebro_query_row_lookup_cache"

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

	lookup := queryRowLookupCache(row)
	if rowKey, ok := lookup[normalized]; ok {
		value, exists := row[rowKey]
		return value, exists
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

func queryRowLookupCache(row map[string]interface{}) map[string]string {
	if cache, ok := row[queryRowLookupCacheKey].(map[string]string); ok {
		return cache
	}

	cache := make(map[string]string, len(row))
	for rowKey := range row {
		if rowKey == queryRowLookupCacheKey {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(rowKey))
		if normalized == "" {
			continue
		}
		if _, exists := cache[normalized]; !exists {
			cache[normalized] = rowKey
		}
	}

	row[queryRowLookupCacheKey] = cache
	return cache
}
