package jobpayload

import (
	"encoding/json"
	"strconv"
	"strings"
)

type Payload map[string]any

func String(payload Payload, key string, fallback string) string {
	if value, ok := payload[key]; ok {
		if typed, ok := value.(string); ok && strings.TrimSpace(typed) != "" {
			return strings.TrimSpace(typed)
		}
	}
	return strings.TrimSpace(fallback)
}

func Uint32(payload Payload, key string) uint32 {
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		if typed > 0 {
			return uint32(typed)
		}
	case json.Number:
		parsed, _ := strconv.ParseUint(string(typed), 10, 32)
		return uint32(parsed)
	case string:
		parsed, _ := strconv.ParseUint(strings.TrimSpace(typed), 10, 32)
		return uint32(parsed)
	}
	return 0
}

func StringSlice(payload Payload, key string) []string {
	value, ok := payload[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				values = append(values, strings.TrimSpace(text))
			}
		}
		return values
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	default:
		return nil
	}
}

func StringMap(payload Payload, key string) map[string]string {
	result := map[string]string{}
	value, ok := payload[key]
	if !ok {
		return result
	}
	switch typed := value.(type) {
	case map[string]string:
		for k, v := range typed {
			result[k] = v
		}
	case map[string]any:
		for k, v := range typed {
			if text, ok := v.(string); ok {
				result[k] = text
			}
		}
	}
	return result
}
