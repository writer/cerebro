package grc

import (
	"strings"
)

func countConnections(values map[string]any, disabled bool, errored bool) int {
	count := 0
	for _, item := range arrayValue(values, "connections") {
		connection, ok := item.(map[string]any)
		if !ok {
			continue
		}
		isDisabled, _ := connection["isDisabled"].(bool)
		hasError := strings.TrimSpace(valueString(connection["connectionErrorMessage"])) != ""
		if disabled && isDisabled {
			count++
		}
		if errored && hasError {
			count++
		}
	}
	return count
}
