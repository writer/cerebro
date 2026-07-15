package connectorpresentation

import (
	"fmt"
	"strings"
)

func ParseLibraryView(value string) (string, error) {
	view := strings.TrimSpace(value)
	if view == "" {
		return "full", nil
	}
	if view != "full" && view != "summary" {
		return "", fmt.Errorf("connector library view must be full or summary")
	}
	return view, nil
}

func SourceListed(values []string, sourceID string) bool {
	normalized := strings.TrimSpace(sourceID)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), normalized) {
			return true
		}
	}
	return false
}

func ActivityID(runtimeID, kind, occurredAt string) string {
	return strings.Trim(strings.Join([]string{strings.TrimSpace(runtimeID), strings.TrimSpace(kind), strings.TrimSpace(occurredAt)}, ":"), ":")
}
