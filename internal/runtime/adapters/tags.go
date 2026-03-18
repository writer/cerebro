package adapters

import "strings"

// CompactTags trims empty values, preserves first-seen order, and avoids duplicates.
func CompactTags(values ...string) []string {
	tags := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		tags = append(tags, trimmed)
	}
	return tags
}
