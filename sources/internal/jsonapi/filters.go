package jsonapi

import "strings"

func RecordFilterAnyPrefix(paths []string, prefixes ...string) RecordFilter {
	normalizedPrefixes := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		if trimmed := strings.ToUpper(strings.TrimSpace(prefix)); trimmed != "" {
			normalizedPrefixes = append(normalizedPrefixes, trimmed)
		}
	}
	normalizedPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		if trimmed := strings.TrimSpace(path); trimmed != "" {
			normalizedPaths = append(normalizedPaths, trimmed)
		}
	}
	return func(values map[string]any) bool {
		for _, path := range normalizedPaths {
			value := strings.ToUpper(valueString(valueAt(values, path)))
			for _, prefix := range normalizedPrefixes {
				if strings.HasPrefix(value, prefix) {
					return true
				}
			}
		}
		return false
	}
}
