package builders

import (
	"strconv"
	"time"
)

func intPropertyValue(properties map[string]any, key string) int {
	if properties == nil {
		return 0
	}
	value, ok := properties[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case float32:
		return int(typed)
	case string:
		out, _ := strconv.Atoi(typed)
		return out
	default:
		return 0
	}
}

func maxRFC3339String(current, candidate string) string {
	if current == "" {
		return candidate
	}
	if candidate == "" {
		return current
	}
	currentTime, currentOK := parseRFC3339String(current)
	candidateTime, candidateOK := parseRFC3339String(candidate)
	if currentOK && candidateOK {
		if candidateTime.After(currentTime) {
			return candidate
		}
		return current
	}
	if candidate > current {
		return candidate
	}
	return current
}

func parseRFC3339String(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
