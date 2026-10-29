package cloudidentity

import (
	"fmt"
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

func normalizeGrantDigest(grants []Grant) (string, error) {
	normalized, err := normalizeGrantsForDrift(grants)
	if err != nil {
		return "", err
	}
	return digestJSON(normalized)
}

// normalizedBoundaryDigest pairs a normalized boundary's grants with its
// content digest for the same reason as normalizedGrantDigest above.
type normalizedBoundaryDigest struct {
	grants []normalizedGrant
	digest string
}

func normalizeBoundaryDigest(boundaries [][]Grant) (string, error) {
	paired := make([]normalizedBoundaryDigest, 0, len(boundaries))
	for _, b := range boundaries {
		normalized, err := normalizeGrantsForDrift(b)
		if err != nil {
			return "", err
		}
		digest, err := digestJSON(normalized)
		if err != nil {
			return "", err
		}
		paired = append(paired, normalizedBoundaryDigest{grants: normalized, digest: digest})
	}
	sort.Slice(paired, func(i, j int) bool { return paired[i].digest < paired[j].digest })
	norm := make([][]normalizedGrant, len(paired))
	for i, p := range paired {
		norm[i] = p.grants
	}
	return digestJSON(norm)
}

// computeDrift compares known grant surfaces without timestamps or reference
// digests. An incomplete side or an encoding failure cannot establish drift.
func computeDrift(declared, observed PolicyState) (bool, error) {
	if !declared.Complete || !observed.Complete {
		return false, nil
	}
	if len(declared.Grants) == 0 && len(observed.Grants) == 0 &&
		len(declared.Boundaries) == 0 && len(observed.Boundaries) == 0 {
		return false, nil
	}
	declaredGrantDigest, err := normalizeGrantDigest(declared.Grants)
	if err != nil {
		return false, fmt.Errorf("digest declared grants: %w", err)
	}
	observedGrantDigest, err := normalizeGrantDigest(observed.Grants)
	if err != nil {
		return false, fmt.Errorf("digest observed grants: %w", err)
	}
	declaredBoundaryDigest, err := normalizeBoundaryDigest(declared.Boundaries)
	if err != nil {
		return false, fmt.Errorf("digest declared boundaries: %w", err)
	}
	observedBoundaryDigest, err := normalizeBoundaryDigest(observed.Boundaries)
	if err != nil {
		return false, fmt.Errorf("digest observed boundaries: %w", err)
	}
	return declaredGrantDigest != observedGrantDigest || declaredBoundaryDigest != observedBoundaryDigest, nil
}
