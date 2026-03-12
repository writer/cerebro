package sync

import "strings"

const (
	defaultPermissionUsageWindowDays      = 90
	defaultPermissionRemovalThresholdDays = 180
	minPermissionUsageDays                = 1
	maxPermissionUsageDays                = 400
	defaultPermissionUsageLookbackDays    = defaultPermissionUsageWindowDays
)

func clampPermissionUsageWindowDays(days int) int {
	if days < minPermissionUsageDays {
		return defaultPermissionUsageWindowDays
	}
	if days > maxPermissionUsageDays {
		return maxPermissionUsageDays
	}
	return days
}

func clampPermissionRemovalThresholdDays(days int) int {
	if days < minPermissionUsageDays {
		return defaultPermissionRemovalThresholdDays
	}
	if days > maxPermissionUsageDays {
		return maxPermissionUsageDays
	}
	return days
}

func clampPermissionUsageLookbackDays(days int) int {
	return clampPermissionUsageWindowDays(days)
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
