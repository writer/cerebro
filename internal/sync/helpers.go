package sync

import "time"

// timeToString converts a *time.Time to a string, returning empty string if nil
func timeToString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
