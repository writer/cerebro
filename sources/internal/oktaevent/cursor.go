package oktaevent

import "strings"

func AssignmentCursor(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if phase, cursor, ok := strings.Cut(value, ":"); ok {
		switch strings.TrimSpace(phase) {
		case "users", "groups":
			return strings.TrimSpace(phase), strings.TrimSpace(cursor)
		}
	}
	return "users", value
}

func PhasedCursor(phase string, cursor string) string {
	value := strings.TrimSpace(cursor)
	if value == "" {
		return ""
	}
	return strings.TrimSpace(phase) + ":" + value
}
