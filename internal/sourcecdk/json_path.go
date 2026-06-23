package sourcecdk

import "strings"

// ValueAtPath traverses a nested map[string]any using a dot-separated path and
// returns the value at that location, or nil if any segment is missing or not a
// map. This replaces the per-source valueAt helper for JSON object traversal.
func ValueAtPath(values map[string]any, path string) any {
	current := any(values)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}
