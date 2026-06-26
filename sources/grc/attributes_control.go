package grc

import (
	"strings"
)

func copyControlReferenceFields(attrs map[string]string, values map[string]any) {
	copyFirstField(attrs, values, "control_id", "controlID", "control.id")
	copyFirstField(attrs, values, "control_external_id", "controlExternalID", "control.externalId", "control.externalID")
	if references := joinedControlReferences(values, "controls"); references != "" {
		attrs["control_references"] = references
	}
	if ids := joinedObjectFieldValues(values, "controls", "id"); ids != "" {
		attrs["control_ids"] = ids
		if strings.TrimSpace(attrs["control_id"]) == "" {
			attrs["control_id"] = firstDelimitedValue(ids)
		}
	}
	if externalIDs := joinedObjectFieldValues(values, "controls", "externalId", "externalID"); externalIDs != "" {
		attrs["control_external_ids"] = externalIDs
		if strings.TrimSpace(attrs["control_external_id"]) == "" {
			attrs["control_external_id"] = firstDelimitedValue(externalIDs)
		}
	}
}

func joinedControlReferences(values map[string]any, arrayKey string) string {
	items := arrayValue(values, arrayKey)
	collected := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := valueString(object["id"])
		externalID := firstNonEmptyString(valueString(object["externalId"]), valueString(object["externalID"]))
		if id == "" && externalID == "" {
			continue
		}
		if id == "" {
			id = externalID
		}
		pair := id + "=" + externalID
		if _, exists := seen[pair]; exists {
			continue
		}
		seen[pair] = struct{}{}
		collected = append(collected, pair)
	}
	return strings.Join(collected, ";")
}
