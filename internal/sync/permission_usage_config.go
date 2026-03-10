package sync

import "strings"

const (
	defaultPermissionUsageLookbackDays = 180
	minPermissionUsageLookbackDays     = 1
	maxPermissionUsageLookbackDays     = 400
)

func clampPermissionUsageLookbackDays(days int) int {
	if days < minPermissionUsageLookbackDays {
		return defaultPermissionUsageLookbackDays
	}
	if days > maxPermissionUsageLookbackDays {
		return maxPermissionUsageLookbackDays
	}
	return days
}

func normalizeIdentityFilterSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

func identityFilterMatches(set map[string]struct{}, candidates ...string) bool {
	if len(set) == 0 {
		return true
	}
	for _, candidate := range candidates {
		normalized := strings.ToLower(strings.TrimSpace(candidate))
		if normalized == "" {
			continue
		}
		if _, ok := set[normalized]; ok {
			return true
		}
	}
	return false
}
