package cloudidentity

// manifestInventory* helpers give deterministic, allocation-light access into
// the generic map[string]any shape produced by YAML/JSON decoding of a
// rendered Kubernetes manifest. They never perform I/O and never panic on
// malformed input; callers treat a false/zero result as "field absent" and
// decide whether that is a gap.

func manifestInventoryAsMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func manifestInventoryAsSlice(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

func manifestInventoryAsString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func manifestInventoryNestedMap(obj map[string]any, path ...string) (map[string]any, bool) {
	cur := obj
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return nil, false
		}
		m, ok := manifestInventoryAsMap(v)
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

func manifestInventoryNestedSlice(obj map[string]any, path ...string) ([]any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	parent, ok := manifestInventoryNestedMap(obj, path[:len(path)-1]...)
	if !ok {
		return nil, false
	}
	v, ok := parent[path[len(path)-1]]
	if !ok {
		return nil, false
	}
	return manifestInventoryAsSlice(v)
}

func manifestInventoryNestedString(obj map[string]any, path ...string) (string, bool) {
	if len(path) == 0 {
		return "", false
	}
	parent, ok := manifestInventoryNestedMap(obj, path[:len(path)-1]...)
	if !ok {
		return "", false
	}
	v, ok := parent[path[len(path)-1]]
	if !ok {
		return "", false
	}
	return manifestInventoryAsString(v)
}

func manifestInventoryStringField(obj map[string]any, key string) string {
	v, _ := manifestInventoryAsString(obj[key])
	return v
}
