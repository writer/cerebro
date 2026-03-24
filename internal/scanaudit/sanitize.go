package scanaudit

import (
	"net/url"
	"regexp"
	"strings"
)

const redactedPathValue = "<redacted-path>"

var (
	embeddedURLPattern  = regexp.MustCompile(`(?:https?|ssh)://[^\s"'<>]+`)
	absolutePathPattern = regexp.MustCompile(`(^|[\s=(\["'])(/[^\s)\]"']+)`)
)

func sanitizeMessage(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}
	sanitized := embeddedURLPattern.ReplaceAllStringFunc(trimmed, sanitizeEmbeddedURL)
	return absolutePathPattern.ReplaceAllString(sanitized, `${1}`+redactedPathValue)
}

func sanitizeEmbeddedURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if parsed, err := url.Parse(raw); err == nil {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

func sanitizeAny(value any) any {
	switch typed := value.(type) {
	case string:
		return sanitizeMessage(typed)
	case map[string]any:
		if len(typed) == 0 {
			return nil
		}
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = sanitizeAny(item)
		}
		return out
	case []any:
		if len(typed) == 0 {
			return nil
		}
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeAny(item))
		}
		return out
	case []string:
		if len(typed) == 0 {
			return nil
		}
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, sanitizeMessage(item))
		}
		return out
	default:
		return value
	}
}
