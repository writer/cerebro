package azurearm

import "strings"

func ProviderFromType(value string) string {
	parts := strings.Split(strings.TrimSpace(value), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func ProviderFromID(value string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(value), "/"), "/")
	for i, part := range parts {
		if strings.EqualFold(part, "providers") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ResourceGroupFromID(value string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(value), "/"), "/")
	for i, part := range parts {
		if strings.EqualFold(part, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func ResourceNameFromID(value string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(value), "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func ResourceTypeFromID(value string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(value), "/"), "/")
	for i, part := range parts {
		if strings.EqualFold(part, "providers") && i+2 < len(parts) {
			return parts[i+1] + "/" + parts[i+2]
		}
	}
	if len(parts) >= 2 && strings.EqualFold(parts[0], "subscriptions") {
		if len(parts) == 2 {
			return "subscription"
		}
		if len(parts) >= 4 && strings.EqualFold(parts[2], "resourceGroups") {
			return "resource_group"
		}
	}
	return "azure_resource"
}
