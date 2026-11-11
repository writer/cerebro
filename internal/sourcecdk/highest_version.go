package sourcecdk

// KeepHighestVersion deduplicates items by a caller-defined key, keeping
// only the highest-ranked item per key according to greater (reported true
// when a outranks b). The first-seen order of distinct keys is preserved in
// the result; items whose key is empty are dropped. It exists for feeds that
// can legitimately repeat a record (e.g. across a read-resume lookback
// window) with a newer version, where an older version must never win.
func KeepHighestVersion[T any](items []T, key func(T) string, greater func(a, b T) bool) []T {
	byKey := make(map[string]T, len(items))
	order := make([]string, 0, len(items))
	for _, item := range items {
		k := key(item)
		if k == "" {
			continue
		}
		existing, seen := byKey[k]
		if !seen {
			order = append(order, k)
			byKey[k] = item
			continue
		}
		if greater(item, existing) {
			byKey[k] = item
		}
	}
	result := make([]T, 0, len(order))
	for _, k := range order {
		result = append(result, byKey[k])
	}
	return result
}
