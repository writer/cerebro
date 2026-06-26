package grc

import (
	"strings"
)

func eventLogTargets(values map[string]any) string {
	items := arrayValue(values, "targets")
	if len(items) == 0 {
		return ""
	}
	targets := make([]string, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			continue
		}
		targetID := valueString(object["id"])
		if targetID == "" {
			continue
		}
		targetType := valueString(object["type"])
		if targetType == "" {
			targets = append(targets, targetID)
			continue
		}
		targets = append(targets, targetType+":"+targetID)
	}
	return strings.Join(targets, ";")
}
