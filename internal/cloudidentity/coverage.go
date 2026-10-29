package cloudidentity

import (
	"fmt"
	"sort"
)

// assessConsumerCoverage enforces that every reviewed consumer in
// Evidence.Consumers is backed by exactly one Investigation, that no
// Investigation's Requirements leak into the requirement union from a
// ConsumerID outside that reviewed inventory, and that each matched
// Investigation is actually bound to the consumer it claims to cover: its
// Source (Repository/Revision/Root/Digest) must match the consumer's own
// pinned Source, and its Validation.SourceDigest must match that same
// Source.Digest. Without this, a requirement investigation computed against
// an unrelated/stale/wrong source — or against a consumer that doesn't
// exist in the reviewed inventory at all — could "justify" grants it never
// actually validated.
//
// It returns the subset of Investigations that passed every check; callers
// MUST build the requirement union from this subset, never from
// Evidence.Investigations directly.
func assessConsumerCoverage(e Evidence) (bool, []Gap, []Investigation) {
	ok := true
	var gaps []Gap

	consumersByID := make(map[string]Workload, len(e.Consumers))
	for _, c := range e.Consumers {
		consumersByID[c.ID] = c
	}

	countsByConsumer := make(map[string]int, len(e.Investigations))
	for _, inv := range e.Investigations {
		countsByConsumer[inv.ConsumerID]++
	}

	var bound []Investigation
	for _, inv := range e.Investigations {
		consumer, known := consumersByID[inv.ConsumerID]
		if !known {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.unmatched_investigation_consumer",
				Scope:   inv.ConsumerID,
				Message: fmt.Sprintf("investigation references consumer %q, which is not in the reviewed consumer inventory; its requirements are excluded from the union", inv.ConsumerID),
			})
			continue
		}
		if countsByConsumer[inv.ConsumerID] > 1 {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.duplicate_consumer_investigation",
				Scope:   inv.ConsumerID,
				Message: fmt.Sprintf("consumer %q has more than one investigation; the authoritative one is ambiguous, so none are used", inv.ConsumerID),
			})
			continue
		}
		if !sourcePinMatches(inv.Source, consumer.Source) {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.investigation_source_mismatch",
				Scope:   inv.ConsumerID,
				Message: fmt.Sprintf("investigation source (repository/revision/root/digest) does not match consumer %q's own pinned source", inv.ConsumerID),
			})
			continue
		}
		if inv.Validation.SourceDigest == "" || inv.Validation.SourceDigest != inv.Source.Digest {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.investigation_source_digest_mismatch",
				Scope:   inv.ConsumerID,
				Message: fmt.Sprintf("investigation Validation.SourceDigest does not match its own Source.Digest for consumer %q", inv.ConsumerID),
			})
			continue
		}
		bound = append(bound, inv)
	}

	for _, c := range e.Consumers {
		if countsByConsumer[c.ID] == 0 {
			ok = false
			gaps = append(gaps, Gap{
				Code:    "cloudidentity.missing_consumer_investigation",
				Scope:   c.ID,
				Message: fmt.Sprintf("reviewed consumer %q has no investigation; its required-permission coverage is unknown", c.ID),
			})
		}
	}

	return ok, gaps, bound
}

// sourcePinMatches reports whether two SourcePins identify the same
// immutable source material. Root is included: an investigation that looked
// at a different subtree within the same repository/revision than the
// consumer's own pin is not bound to that consumer's actual source.
func sourcePinMatches(a, b SourcePin) bool {
	return a.Repository == b.Repository && a.Revision == b.Revision && a.Root == b.Root && a.Digest == b.Digest
}

// sourcePinExact reports whether a SourcePin is both marked Exact and
// actually identifies a concrete repository/revision. Exact=true alone is
// not sufficient — a zero-value SourcePin with Exact set would otherwise
// pass a boolean-only check despite pointing nowhere.
func sourcePinExact(p SourcePin) bool {
	return p.Exact && p.Repository != "" && p.Revision != ""
}

// definitionsDigestConsistent reports whether a populated Definitions.Digest
// matches the canonical digest of its own content (Actions/Operations/
// Roles/Policies, each sorted by stable key — the same canonicalization
// MergeDefinitions uses when it computes a merged Digest). The Digest field
// itself is necessarily excluded from what gets hashed; hashing a struct
// containing its own hash would be circular. An empty Digest is not treated
// as inconsistent (some callers may not populate one), but a populated one
// that doesn't match its own content is a tamper/staleness signal.
func definitionsDigestConsistent(d Definitions) bool {
	if d.Digest == "" {
		return true
	}
	d.Actions = sortedActionDefinitions(d.Actions)
	d.Operations = sortedOperationDefinitions(d.Operations)
	d.Roles = sortedRoleDefinitions(d.Roles)
	d.Policies = sortedPolicyDefinitions(d.Policies)
	computed, err := definitionsContentDigest(d)
	return err == nil && computed == d.Digest
}

func sortedActionDefinitions(in []ActionDefinition) []ActionDefinition {
	out := append([]ActionDefinition(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedOperationDefinitions(in []OperationDefinition) []OperationDefinition {
	out := append([]OperationDefinition(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		return string(out[i].Provider)+"|"+out[i].Service+"|"+out[i].Operation < string(out[j].Provider)+"|"+out[j].Service+"|"+out[j].Operation
	})
	return out
}

func sortedRoleDefinitions(in []RoleDefinition) []RoleDefinition {
	out := append([]RoleDefinition(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sortedPolicyDefinitions(in []ManagedPolicy) []ManagedPolicy {
	out := append([]ManagedPolicy(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ARN < out[j].ARN })
	return out
}
