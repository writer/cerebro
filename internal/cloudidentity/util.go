package cloudidentity

import "sort"

// sortedCopy returns a sorted copy of values, leaving the input untouched.
func sortedCopy(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

// dedupSorted returns the unique values in values, sorted.
func dedupSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// dedupeGaps removes exact duplicate Gaps (same code/scope/message) while
// preserving the first occurrence's order.
func dedupeGaps(gaps []Gap) []Gap {
	seen := make(map[string]bool, len(gaps))
	out := make([]Gap, 0, len(gaps))
	for _, g := range gaps {
		key := g.Code + "|" + g.Scope + "|" + g.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, g)
	}
	return out
}

// hasGapCode reports whether gaps contains an entry with the given Code.
func hasGapCode(gaps []Gap, code string) bool {
	for _, g := range gaps {
		if g.Code == code {
			return true
		}
	}
	return false
}
