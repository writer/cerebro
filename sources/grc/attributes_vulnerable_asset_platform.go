package grc

import (
	"encoding/json"
	"strings"
)

type vulnerableAssetPlatformReference struct {
	Provider          string `json:"provider,omitempty"`
	ResourceID        string `json:"resource_id,omitempty"`
	ResourceName      string `json:"resource_name,omitempty"`
	ResourceType      string `json:"resource_type,omitempty"`
	ScannerResourceID string `json:"scanner_resource_id,omitempty"`
	Hostnames         string `json:"hostnames,omitempty"`
	IPs               string `json:"ips,omitempty"`
}

func copyVulnerableAssetPlatformReferences(attrs map[string]string, values map[string]any) {
	refs := vulnerableAssetPlatformReferences(values)
	if len(refs) == 0 {
		return
	}
	if raw, err := json.Marshal(refs); err == nil {
		attrs["platform_asset_refs"] = string(raw)
	}
	first := refs[0]
	addAttrIfMissing(attrs, "platform_provider", first.Provider)
	addAttrIfMissing(attrs, "platform_resource_id", first.ResourceID)
	addAttrIfMissing(attrs, "platform_resource_name", first.ResourceName)
	addAttrIfMissing(attrs, "platform_resource_type", first.ResourceType)
	addAttrIfMissing(attrs, "scanner_resource_id", first.ScannerResourceID)
	hostnames := joinedUniqueDelimitedValues(refs, func(ref vulnerableAssetPlatformReference) string { return ref.Hostnames })
	ips := joinedUniqueDelimitedValues(refs, func(ref vulnerableAssetPlatformReference) string { return ref.IPs })
	if hostnames != "" {
		attrs["hostnames"] = hostnames
		addAttrIfMissing(attrs, "hostname", firstDelimitedValue(hostnames))
	}
	if ips != "" {
		attrs["ip_addresses"] = ips
		addAttrIfMissing(attrs, "ip", firstDelimitedValue(ips))
	}
}

func vulnerableAssetPlatformReferences(values map[string]any) []vulnerableAssetPlatformReference {
	items := arrayValue(values, "scanners")
	refs := make([]vulnerableAssetPlatformReference, 0, len(items))
	seen := map[string]struct{}{}
	resourceName := firstNonEmptyString(fieldString(values, "displayName"), fieldString(values, "name"), fieldString(values, "hostname"), fieldString(values, "host"))
	resourceType := firstNonEmptyString(fieldString(values, "resourceType"), fieldString(values, "assetType"), fieldString(values, "type"))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		provider := firstNonEmptyString(fieldString(object, "integrationId"), fieldString(object, "integration.id"), fieldString(object, "provider"))
		resourceID := firstNonEmptyString(fieldString(object, "targetId"), fieldString(object, "resourceArn"), fieldString(object, "arn"))
		scannerResourceID := fieldString(object, "resourceId")
		if resourceID == "" && platformResourceIDLikelyExternal(scannerResourceID) {
			resourceID = scannerResourceID
		}
		hostnames := joinedPlatformObjectFieldValues(object, "hostnames", "fqdns", "hostname", "fqdn")
		ips := joinedPlatformObjectFieldValues(object, "ipv4s", "ipv6s", "ipAddresses", "ipAddress", "publicIp", "publicIP")
		if provider == "" && resourceID == "" && scannerResourceID == "" && hostnames == "" && ips == "" {
			continue
		}
		ref := vulnerableAssetPlatformReference{
			Provider:          provider,
			ResourceID:        resourceID,
			ResourceName:      resourceName,
			ResourceType:      firstNonEmptyString(fieldString(object, "resourceType"), fieldString(object, "assetType"), resourceType),
			ScannerResourceID: scannerResourceID,
			Hostnames:         normalizeDelimitedValues(hostnames),
			IPs:               normalizeDelimitedValues(ips),
		}
		key := strings.Join([]string{ref.Provider, ref.ResourceID, ref.ScannerResourceID, ref.Hostnames, ref.IPs}, "\x00")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func addAttrIfMissing(attrs map[string]string, key string, value string) {
	if strings.TrimSpace(attrs[key]) == "" {
		if value = strings.TrimSpace(value); value != "" {
			attrs[key] = value
		}
	}
}

func platformResourceIDLikelyExternal(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "arn:") || strings.Contains(value, "://") || strings.Contains(value, "/")
}

func joinedPlatformObjectFieldValues(object map[string]any, names ...string) string {
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, splitDelimitedValues(fieldString(object, name))...)
	}
	return strings.Join(uniqueStrings(values), ",")
}

func joinedUniqueDelimitedValues(refs []vulnerableAssetPlatformReference, selectValue func(vulnerableAssetPlatformReference) string) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		values = append(values, splitDelimitedValues(selectValue(ref))...)
	}
	return strings.Join(uniqueStrings(values), ",")
}

func normalizeDelimitedValues(value string) string {
	return strings.Join(uniqueStrings(splitDelimitedValues(value)), ",")
}

func splitDelimitedValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func firstDelimitedValue(value string) string {
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
