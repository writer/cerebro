package sync

import "strings"

func columnsMissingFromSchema(existing []string, desired []string) []string {
	existingSet := make(map[string]struct{}, len(existing))
	for _, col := range existing {
		normalized := strings.ToUpper(strings.TrimSpace(col))
		if normalized == "" {
			continue
		}
		existingSet[normalized] = struct{}{}
	}

	seenDesired := make(map[string]struct{}, len(desired))
	missing := make([]string, 0, len(desired))
	for _, col := range desired {
		normalized := strings.ToUpper(strings.TrimSpace(col))
		if normalized == "" {
			continue
		}
		if _, seen := seenDesired[normalized]; seen {
			continue
		}
		seenDesired[normalized] = struct{}{}
		if _, exists := existingSet[normalized]; !exists {
			missing = append(missing, normalized)
		}
	}

	return missing
}
