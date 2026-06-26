package grc

import (
	"encoding/json"
	"strings"
)

func copyVulnerableAssetReferences(attrs map[string]string, values map[string]any) {
	if ids := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "id", "vulnerabilityId"),
		fieldString(values, "vulnerabilityIds"),
	); ids != "" {
		attrs["vulnerability_ids"] = ids
	}
	if names := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "name", "title"),
		fieldString(values, "vulnerabilityNames"),
	); names != "" {
		attrs["vulnerability_names"] = names
	}
	if packages := firstNonEmptyString(
		joinedObjectFieldValues(values, "vulnerabilities", "packageIdentifier", "package", "packagePurl"),
		fieldString(values, "packageIdentifiers"),
		fieldString(values, "packages"),
	); packages != "" {
		attrs["package_identifiers"] = packages
	}
	if references := joinedVulnerableAssetReferences(values); references != "" {
		attrs["vulnerability_package_refs"] = references
	}
}

func joinedVulnerableAssetReferences(values map[string]any) string {
	items := arrayValue(values, "vulnerabilities")
	refs := make([]map[string]string, 0, len(items))
	seen := map[string]struct{}{}
	vulnerabilityIDs := splitDelimitedValues(fieldString(values, "vulnerabilityIds"))
	vulnerabilityNames := splitDelimitedValues(fieldString(values, "vulnerabilityNames"))
	packageIdentifiers := splitDelimitedValues(firstNonEmptyString(fieldString(values, "packageIdentifiers"), fieldString(values, "packages")))
	for i, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		refs = appendVulnerableAssetReference(refs, seen,
			firstNonEmptyString(valueString(object["id"]), valueString(object["vulnerabilityId"]), valueAt(vulnerabilityIDs, i)),
			firstNonEmptyString(valueString(object["name"]), valueString(object["title"]), valueAt(vulnerabilityNames, i)),
			firstNonEmptyString(valueString(object["packageIdentifier"]), valueString(object["package"]), valueString(object["packagePurl"]), valueAt(packageIdentifiers, i)),
		)
	}
	for i, ref := range refs {
		if ref["vulnerability_id"] == "" {
			if vulnerabilityID := valueAt(vulnerabilityIDs, i); vulnerabilityID != "" {
				ref["vulnerability_id"] = vulnerabilityID
			}
		}
		if ref["vulnerability_name"] == "" {
			if vulnerabilityName := valueAt(vulnerabilityNames, i); vulnerabilityName != "" {
				ref["vulnerability_name"] = vulnerabilityName
			}
		}
		if ref["package_identifier"] == "" {
			if packageIdentifier := valueAt(packageIdentifiers, i); packageIdentifier != "" {
				ref["package_identifier"] = packageIdentifier
			}
		}
	}
	for i := len(refs); i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
		refs = appendVulnerableAssetReference(refs, seen, valueAt(vulnerabilityIDs, i), valueAt(vulnerabilityNames, i), valueAt(packageIdentifiers, i))
	}
	if len(refs) == 0 {
		for i := 0; i < maxInt(len(vulnerabilityIDs), len(vulnerabilityNames), len(packageIdentifiers)); i++ {
			refs = appendVulnerableAssetReference(refs, seen, valueAt(vulnerabilityIDs, i), valueAt(vulnerabilityNames, i), valueAt(packageIdentifiers, i))
		}
	}
	if len(refs) == 0 {
		return ""
	}
	raw, err := json.Marshal(refs)
	if err != nil {
		return ""
	}
	return string(raw)
}

func appendVulnerableAssetReference(refs []map[string]string, seen map[string]struct{}, vulnerabilityID string, vulnerabilityName string, packageIdentifier string) []map[string]string {
	if vulnerabilityID == "" && vulnerabilityName == "" && packageIdentifier == "" {
		return refs
	}
	key := strings.Join([]string{vulnerabilityID, vulnerabilityName, packageIdentifier}, "\x00")
	if _, exists := seen[key]; exists {
		return refs
	}
	seen[key] = struct{}{}
	ref := map[string]string{}
	for key, value := range map[string]string{
		"vulnerability_id":   vulnerabilityID,
		"vulnerability_name": vulnerabilityName,
		"package_identifier": packageIdentifier,
	} {
		if value != "" {
			ref[key] = value
		}
	}
	return append(refs, ref)
}

func valueAt(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}

func maxInt(values ...int) int {
	max := 0
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func joinedObjectFieldValues(values map[string]any, arrayKey string, fields ...string) string {
	items := arrayValue(values, arrayKey)
	collected := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range fields {
			value := valueString(object[field])
			if value == "" {
				continue
			}
			if _, exists := seen[value]; !exists {
				collected = append(collected, value)
				seen[value] = struct{}{}
			}
			break
		}
	}
	return strings.Join(collected, ",")
}
