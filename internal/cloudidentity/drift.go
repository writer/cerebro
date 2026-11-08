package cloudidentity

import (
	"sort"
)

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

// normalizedGrantDigest pairs a normalized grant with its content digest so
// sort.Slice can order by digest without calling the (now fallible) Digest
// function from inside the comparator.
type normalizedGrantDigest struct {
	grant  normalizedGrant
	digest string
}

func normalizeGrantsForDrift(grants []Grant) ([]normalizedGrant, error) {
	paired := make([]normalizedGrantDigest, 0, len(grants))
	for _, g := range grants {
		normalized := normalizeGrantForDrift(g)
		digest, err := digestJSON(normalized)
		if err != nil {
			return nil, err
		}
		paired = append(paired, normalizedGrantDigest{grant: normalized, digest: digest})
	}
	sort.Slice(paired, func(i, j int) bool { return paired[i].digest < paired[j].digest })
	out := make([]normalizedGrant, len(paired))
	for i, p := range paired {
		out[i] = p.grant
	}
	return out, nil
}
