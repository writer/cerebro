package vulnpipeline

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	maxPathSegments   = 12
	maxFlattenDepth   = 6
	maxFlattenValues  = 64
	maxResolvedValues = 256
)

type pathSegment struct {
	key      string
	index    int
	hasIndex bool
	wildcard bool
}

// parsePath parses the mapping path dialect: dot-separated object keys, with
// optional [n] index or [*] fan-out suffixes, for example
// "results[*].vulnerabilities[0].id". An empty path addresses the value itself.
func parsePath(raw string) ([]pathSegment, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "$"))
	raw = strings.TrimPrefix(raw, ".")
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) > maxPathSegments {
		return nil, fmt.Errorf("path %q has more than %d segments", raw, maxPathSegments)
	}
	segments := []pathSegment{}
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("path %q has an empty segment", raw)
		}
		key := part
		suffixes := ""
		if open := strings.Index(part, "["); open >= 0 {
			key = part[:open]
			suffixes = part[open:]
		}
		if strings.ContainsAny(key, "[]") {
			return nil, fmt.Errorf("path %q has a malformed segment", raw)
		}
		if key != "" {
			segments = append(segments, pathSegment{key: key})
		}
		for suffixes != "" {
			end := strings.Index(suffixes, "]")
			if !strings.HasPrefix(suffixes, "[") || end < 0 {
				return nil, fmt.Errorf("path %q has a malformed index", raw)
			}
			inner := suffixes[1:end]
			suffixes = suffixes[end+1:]
			if inner == "*" {
				segments = append(segments, pathSegment{wildcard: true})
				continue
			}
			index, err := strconv.Atoi(inner)
			if err != nil || index < 0 {
				return nil, fmt.Errorf("path %q has an invalid index %q", raw, inner)
			}
			segments = append(segments, pathSegment{index: index, hasIndex: true})
		}
	}
	return segments, nil
}

func resolvePath(value any, segments []pathSegment) []any {
	current := []any{value}
	for _, segment := range segments {
		next := []any{}
		for _, item := range current {
			switch {
			case segment.wildcard:
				if list, ok := item.([]any); ok {
					next = append(next, list...)
				}
			case segment.hasIndex:
				if list, ok := item.([]any); ok && segment.index < len(list) {
					next = append(next, list[segment.index])
				}
			default:
				if object, ok := item.(map[string]any); ok {
					if child, exists := object[segment.key]; exists {
						next = append(next, child)
					}
				}
			}
			if len(next) > maxResolvedValues {
				next = next[:maxResolvedValues]
				break
			}
		}
		current = next
		if len(current) == 0 {
			return nil
		}
	}
	return current
}

func resolveStrings(value any, raw string) []string {
	segments, err := parsePath(raw)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, item := range resolvePath(value, segments) {
		out = append(out, scalarStrings(item)...)
	}
	return out
}

func resolveFirstString(value any, raw string) string {
	for _, candidate := range resolveStrings(value, raw) {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate)
		}
	}
	return ""
}

// scalarStrings renders a JSON scalar, or a list of scalars, as strings.
func scalarStrings(value any) []string {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{typed}
	case json.Number:
		return []string{typed.String()}
	case float64:
		return []string{strconv.FormatFloat(typed, 'f', -1, 64)}
	case bool:
		return []string{strconv.FormatBool(typed)}
	case []any:
		out := []string{}
		for _, item := range typed {
			switch item.(type) {
			case map[string]any, []any:
				continue
			}
			out = append(out, scalarStrings(item)...)
		}
		return out
	default:
		return nil
	}
}

// flattenRecord lists every addressable scalar path in a record with its
// values. Arrays fan out with [*] so list-valued fields keep one path.
func flattenRecord(record any) map[string][]string {
	out := map[string][]string{}
	flattenInto(out, "", record, 0)
	return out
}

func flattenInto(out map[string][]string, prefix string, value any, depth int) {
	if depth > maxFlattenDepth || len(out) > 4*maxFlattenValues {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if key == "" || strings.ContainsAny(key, ".[]") {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			flattenInto(out, path, typed[key], depth+1)
		}
	case []any:
		path := prefix + "[*]"
		for i, item := range typed {
			if i >= maxFlattenValues {
				break
			}
			flattenInto(out, path, item, depth+1)
		}
	default:
		if prefix == "" {
			return
		}
		values := scalarStrings(typed)
		if len(values) == 0 {
			return
		}
		existing := out[prefix]
		if len(existing) < maxFlattenValues {
			out[prefix] = append(existing, values...)
		}
	}
}

func lastPathKey(path string) string {
	segments, err := parsePath(path)
	if err != nil {
		return ""
	}
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i].key != "" {
			return segments[i].key
		}
	}
	return ""
}

// normalizeKey lowercases a key and removes separators so camelCase, snake_case
// and kebab-case variants compare equal.
func normalizeKey(key string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(key) {
		if r == '_' || r == '-' || r == ' ' {
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}
