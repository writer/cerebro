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

// RecordFilterAnyPrefixOrNonEmpty matches records with a prefixed identifier or an explicit non-empty field.
func RecordFilterAnyPrefixOrNonEmpty(prefixPaths []string, nonEmptyPaths []string, prefixes ...string) RecordFilter {
	prefixFilter := RecordFilterAnyPrefix(prefixPaths, prefixes...)
	normalizedNonEmptyPaths := make([]string, 0, len(nonEmptyPaths))
	for _, path := range nonEmptyPaths {
		if trimmed := strings.TrimSpace(path); trimmed != "" {
			normalizedNonEmptyPaths = append(normalizedNonEmptyPaths, trimmed)
		}
	}
	return func(values map[string]any) bool {
		if prefixFilter(values) {
			return true
		}
		for _, path := range normalizedNonEmptyPaths {
			if strings.TrimSpace(valueString(valueAt(values, path))) != "" {
				return true
			}
		}
		return false
	}
}
