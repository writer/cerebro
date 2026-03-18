package reports

import "strings"

// SchemaRequiredKeys normalizes a JSON-schema required list into trimmed keys.
func SchemaRequiredKeys(raw any) []string {
	keys := make([]string, 0)
	switch typed := raw.(type) {
	case []string:
		for _, key := range typed {
			key = strings.TrimSpace(key)
			if key != "" {
				keys = append(keys, key)
			}
		}
	case []any:
		for _, rawKey := range typed {
			key, _ := rawKey.(string)
			key = strings.TrimSpace(key)
			if key != "" {
				keys = append(keys, key)
			}
		}
	}
	return keys
}
