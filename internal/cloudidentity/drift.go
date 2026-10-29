package cloudidentity

import "sort"

// normalizedGrant strips identity-irrelevant fields (ID, References, which
// carry timestamps and source digests) before a Grant is compared for
// drift, per contract: "Drift semantically compares declared/live grants
// without timestamps/reference digests."
type normalizedGrant struct {
	Effect       string
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Conditions   []Condition
	Role         string
	Members      []string
}

func normalizeGrantForDrift(g Grant) normalizedGrant {
	conditions := append([]Condition{}, g.Conditions...)
	for i := range conditions {
		conditions[i].Values = sortedCopy(conditions[i].Values)
	}
	sort.Slice(conditions, func(i, j int) bool {
		if conditions[i].Operator != conditions[j].Operator {
			return conditions[i].Operator < conditions[j].Operator
		}
		if conditions[i].Key != conditions[j].Key {
			return conditions[i].Key < conditions[j].Key
		}
		return conditions[i].Expression < conditions[j].Expression
	})
	return normalizedGrant{
		Effect:       g.Effect,
		Actions:      sortedCopy(g.Actions),
		NotActions:   sortedCopy(g.NotActions),
		Resources:    sortedCopy(g.Resources),
		NotResources: sortedCopy(g.NotResources),
		Conditions:   conditions,
		Role:         g.Role,
		Members:      sortedCopy(g.Members),
	}
}

func normalizeGrantsForDrift(grants []Grant) []normalizedGrant {
	out := make([]normalizedGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, normalizeGrantForDrift(g))
	}
	sort.Slice(out, func(i, j int) bool { return Digest(out[i]) < Digest(out[j]) })
	return out
}

func normalizeGrantDigest(grants []Grant) string {
	return Digest(normalizeGrantsForDrift(grants))
}

func normalizeBoundaryDigest(boundaries [][]Grant) string {
	norm := make([][]normalizedGrant, 0, len(boundaries))
	for _, b := range boundaries {
		norm = append(norm, normalizeGrantsForDrift(b))
	}
	sort.Slice(norm, func(i, j int) bool { return Digest(norm[i]) < Digest(norm[j]) })
	return Digest(norm)
}

// computeDrift reports whether the declared and observed grant surfaces
// differ, ignoring timestamps and reference digests. Drift is only ever
// asserted between two KNOWN sides (binding semantic 5): an absent or
// incomplete side can neither open nor close a drift finding, since there
// is nothing confirmed on that side to compare against. When both sides
// ARE confirmed complete, a complete-empty side next to a complete-nonempty
// side is still genuine drift — Complete alone never suppresses a real
// difference, only an unknown/incomplete side does.
func computeDrift(declared, observed PolicyState) bool {
	if !declared.Complete || !observed.Complete {
		return false
	}
	if len(declared.Grants) == 0 && len(observed.Grants) == 0 &&
		len(declared.Boundaries) == 0 && len(observed.Boundaries) == 0 {
		return false
	}
	return normalizeGrantDigest(declared.Grants) != normalizeGrantDigest(observed.Grants) ||
		normalizeBoundaryDigest(declared.Boundaries) != normalizeBoundaryDigest(observed.Boundaries)
}
