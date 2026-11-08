package cloudidentitysource

import (
	"strconv"
	"strings"
)

// Generic, allocation-light accessors into the map[string]any shape produced
// by YAML/JSON decoding. Shared by the Helm, Argo, and Crossplane expanders.

func manifestAsMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func manifestAsSlice(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

func manifestAsString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func manifestStringField(obj map[string]any, key string) string {
	v, _ := manifestAsString(obj[key])
	return v
}

func manifestNestedMap(obj map[string]any, path ...string) (map[string]any, bool) {
	cur := obj
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return nil, false
		}
		m, ok := manifestAsMap(v)
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return m, true
		}
		cur = m
	}
	return cur, true
}

func manifestNestedSlice(obj map[string]any, path ...string) ([]any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	parent, ok := manifestNestedMap(obj, path[:len(path)-1]...)
	if !ok {
		return nil, false
	}
	return manifestAsSlice(parent[path[len(path)-1]])
}

func manifestNestedString(obj map[string]any, path ...string) (string, bool) {
	if len(path) == 0 {
		return "", false
	}
	parent, ok := manifestNestedMap(obj, path[:len(path)-1]...)
	if !ok {
		return "", false
	}
	return manifestAsString(parent[path[len(path)-1]])
}

// manifestFieldPathSegment is one parsed step of a Crossplane/Helm-parameter
// style field path: a map key, optionally followed by a slice index.
type manifestFieldPathSegment struct {
	key      string
	hasIndex bool
	index    int
}

// manifestParseFieldPath parses dot-separated field paths with optional
// "[n]" slice indices, e.g. "spec.forProvider.tags[0].value".
func manifestParseFieldPath(path string) []manifestFieldPathSegment {
	var segments []manifestFieldPathSegment
	for _, raw := range strings.Split(path, ".") {
		key := raw
		for {
			open := strings.IndexByte(key, '[')
			if open < 0 {
				segments = append(segments, manifestFieldPathSegment{key: key})
				break
			}
			close := strings.IndexByte(key[open:], ']')
			if close < 0 {
				segments = append(segments, manifestFieldPathSegment{key: key})
				break
			}
			close += open
			head := key[:open]
			idxStr := key[open+1 : close]
			idx, err := strconv.Atoi(idxStr)
			if head != "" || len(segments) == 0 || segments[len(segments)-1].hasIndex {
				segments = append(segments, manifestFieldPathSegment{key: head})
			}
			if err == nil {
				segments[len(segments)-1].hasIndex = true
				segments[len(segments)-1].index = idx
			}
			key = key[close+1:]
			if key == "" {
				break
			}
		}
	}
	return segments
}

// manifestGetFieldPath resolves path against obj, returning ok=false for any
// missing intermediate segment rather than panicking.
func manifestGetFieldPath(obj map[string]any, path string) (any, bool) {
	segments := manifestParseFieldPath(path)
	var cur any = obj
	for _, seg := range segments {
		m, ok := manifestAsMap(cur)
		if !ok {
			return nil, false
		}
		v, ok := m[seg.key]
		if !ok {
			return nil, false
		}
		if seg.hasIndex {
			s, ok := manifestAsSlice(v)
			if !ok || seg.index < 0 || seg.index >= len(s) {
				return nil, false
			}
			cur = s[seg.index]
			continue
		}
		cur = v
	}
	return cur, true
}

// manifestSetFieldPath writes value at path within obj, creating
// intermediate maps as needed. Slice indices may only address existing
// elements (we never fabricate array length); a missing index is a no-op
// reported by the caller via its own gap if it cares.
func manifestSetFieldPath(obj map[string]any, path string, value any) {
	segments := manifestParseFieldPath(path)
	if len(segments) == 0 {
		return
	}
	cur := obj
	for i, seg := range segments {
		last := i == len(segments)-1
		if seg.hasIndex {
			s, ok := manifestAsSlice(cur[seg.key])
			if !ok || seg.index < 0 || seg.index >= len(s) {
				return
			}
			if last {
				s[seg.index] = value
				return
			}
			next, ok := manifestAsMap(s[seg.index])
			if !ok {
				return
			}
			cur = next
			continue
		}
		if last {
			cur[seg.key] = value
			return
		}
		next, ok := manifestAsMap(cur[seg.key])
		if !ok {
			next = map[string]any{}
			cur[seg.key] = next
		}
		cur = next
	}
}
