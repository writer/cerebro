package graphquery

import (
	"fmt"
	"strings"
)

func cypherMapString(item any, key string) string {
	values, ok := item.(map[string]any)
	if !ok {
		return ""
	}
	value, ok := values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}
