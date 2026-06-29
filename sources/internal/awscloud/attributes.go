package awscloud

import (
	"sort"
	"strings"
)

func AssetAttributes(accountID string, defaultRegion string, region string, family string, resourceID string, resourceName string, resourceType string, tags map[string]string) map[string]string {
	env := tagLookup(tags, "environment", "env", "stage")
	return map[string]string{
		"domain":            accountID,
		"env":               env,
		"environment":       env,
		"family":            family,
		"owner":             tagLookup(tags, "owner", "application_owner", "business_owner", "service_owner"),
		"region":            firstNonEmpty(region, defaultRegion),
		"resource_id":       resourceID,
		"resource_name":     resourceName,
		"resource_provider": "aws",
		"resource_type":     resourceType,
		"tags":              encodeTags(tags),
		"team":              tagLookup(tags, "team", "squad", "group"),
	}
}

func tagLookup(tags map[string]string, keys ...string) string {
	if len(tags) == 0 {
		return ""
	}
	normalized := make(map[string]string, len(tags))
	for key, value := range tags {
		normalized[normalizeTagKey(key)] = value
	}
	for _, key := range keys {
		if value := strings.TrimSpace(normalized[normalizeTagKey(key)]); value != "" {
			return value
		}
	}
	return ""
}

func normalizeTagKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.Trim(value, "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func encodeTags(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+tags[key])
	}
	return strings.Join(pairs, ",")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
