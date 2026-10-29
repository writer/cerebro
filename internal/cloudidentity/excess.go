package cloudidentity

import (
	"fmt"
	"sort"
	"strings"
)

const (
	gapMissingRoleDefinition        = "cloudidentity.missing_role_definition"
	gapUnscopedResource             = "cloudidentity.unscoped_resource"
	gapUnknownActionSurface         = "cloudidentity.unknown_action_surface"
	gapUnresolvedResourceComplement = "cloudidentity.unresolved_resource_complement"
	gapUnknownEffectiveAccess       = "cloudidentity.unknown_effective_access"
	gapUnknownGrantCondition        = "cloudidentity.unknown_grant_condition"
	gapUnresolvedEffectiveResource  = "cloudidentity.unresolved_effective_resource"
)

// unionInvestigationRequirements flattens every consumer's investigated
// Requirements across all Investigations in Evidence, per contract: declared
// and observed are each assessed against the union of every consumer
// requirement, not a single consumer's view.
func unionInvestigationRequirements(investigations []Investigation) []Requirement {
	var out []Requirement
	for _, inv := range investigations {
		out = append(out, inv.Requirements...)
	}
	return out
}

// requirementsByActionForProvider groups the requirement union by action
// name (case-insensitively), scoped to one provider, for fast lookup during
// excess computation.
func requirementsByActionForProvider(provider Provider, requirements []Requirement) map[string][]Requirement {
	out := map[string][]Requirement{}
	for _, r := range requirements {
		if r.Provider != provider {
			continue
		}
		key := strings.ToLower(r.Action)
		out[key] = append(out[key], r)
	}
	return out
}

// computeExcess evaluates one side's PolicyState (declared or observed)
// against the known requirement union, producing supported Excess findings
// (actions never required, or required only at a narrower resource scope
// than granted) plus any Gaps raised while resolving the policy surface.
// Trust statements live in PolicyState.Trust, never in Grants/Boundaries, so
// this never needs to special-case Grant.Members: a Grants/Boundaries entry
// that happens to carry Members (e.g. a live GCP IAM binding scoped to the
// matched members) is still a permission grant and must be evaluated like
// any other. A grant is only ever skipped (never guessed) when its
// action/resource scope is ambiguous.
func computeExcess(provider Provider, policy PolicyState, defs Definitions, requirementsByAction map[string][]Requirement, knownActionsByService map[string][]string, resolvedIdentifiers map[string]string) ([]Excess, []Gap) {
	ep := expandPolicyState(provider, policy, defs)
	gaps := append([]Gap{}, ep.gaps...)
	var excess []Excess
	seen := map[string]bool{}

	for _, g := range ep.layers[0] {
		if g.Effect != "Allow" {
			continue
		}

		switch grantConditionEffectiveness(g.Conditions) {
		case matchNo:
			// CEL literal `false` (or any other condition proven
			// self-contradictory): the binding never applies. Inert, not
			// excess — no gap either.
			continue
		case matchUnknown:
			gaps = append(gaps, Gap{
				Code:       gapUnknownGrantCondition,
				Scope:      g.ID,
				Message:    fmt.Sprintf("grant %q has a condition cloudidentity cannot resolve (a principal-bound key, an unsupported operator, or a non-literal CEL expression); its applicability is unknown, so no excess can be asserted from it", g.ID),
				References: g.References,
			})
			continue
		}

		actions, ok := concreteActionsForGrant(provider, g, knownActionsByService, defs.AWSServiceCatalogComplete)
		if !ok {
			gaps = append(gaps, Gap{
				Code:       gapUnknownActionSurface,
				Scope:      g.ID,
				Message:    fmt.Sprintf("grant %q uses actions with no catalog entry in Definitions; its action scope cannot be assessed", g.ID),
				References: g.References,
			})
			continue
		}
		if len(g.Resources) == 0 {
			if len(g.NotResources) > 0 {
				// A pure NotResource allow still grants everything outside
				// its exclusion list; that positive complement cannot be
				// enumerated from NotResources alone, so it is never
				// silently treated as zero patterns (which would hide real
				// excess) — surface it as an incomplete grant scope instead.
				gaps = append(gaps, Gap{
					Code:       gapUnresolvedResourceComplement,
					Scope:      g.ID,
					Message:    fmt.Sprintf("grant %q only specifies NotResource; its positive resource complement cannot be enumerated and is treated as an incomplete surface", g.ID),
					References: g.References,
				})
				continue
			}
			gaps = append(gaps, Gap{
				Code:       gapUnscopedResource,
				Scope:      g.ID,
				Message:    fmt.Sprintf("grant %q omits Resource; its scope is unknown and cannot be asserted as excess", g.ID),
				References: g.References,
			})
			continue
		}

		for _, action := range actions {
			for _, pattern := range g.Resources {
				switch effectiveAllow(provider, ep.layers, action, pattern, g.Conditions, resolvedIdentifiers) {
				case matchNo:
					continue
				case matchUnknown:
					gaps = append(gaps, Gap{
						Code:       gapUnknownEffectiveAccess,
						Scope:      g.ID,
						Message:    fmt.Sprintf("grant %q action %q resource %q has an effective access state (deny/boundary condition) that cannot be resolved; excess cannot be asserted for this pattern", g.ID, action, pattern),
						References: g.References,
					})
					continue
				}

				key := g.ID + "|" + action + "|" + pattern
				if seen[key] {
					continue
				}

				effectivePattern := pattern
				if len(ep.layers) > 1 {
					narrowed, ok := effectiveResourcePattern(provider, ep.layers, action, pattern, g.Conditions, resolvedIdentifiers)
					if !ok {
						seen[key] = true
						gaps = append(gaps, Gap{
							Code:       gapUnresolvedEffectiveResource,
							Scope:      g.ID,
							Message:    fmt.Sprintf("grant %q action %q resource %q intersects a boundary whose provable overlap cannot be reduced to a single effective resource scope; excess cannot be asserted for this pattern", g.ID, action, pattern),
							References: g.References,
						})
						continue
					}
					effectivePattern = narrowed
				}

				reqs := requirementsByAction[strings.ToLower(action)]
				covering := filterCoveringRequirements(provider, effectivePattern, g, reqs, resolvedIdentifiers)

				if len(covering) == 0 {
					seen[key] = true
					reason := "action is not required by any known consumer"
					if len(reqs) > 0 {
						reason = "action is required by a known consumer, but not for this grant's resource scope or under its conditions"
					}
					excess = append(excess, Excess{
						GrantID:    g.ID,
						Action:     action,
						Resources:  []string{pattern},
						Reason:     reason,
						References: append([]Reference{}, g.References...),
					})
					continue
				}

				if narrower := narrowRecommendation(provider, effectivePattern, covering); narrower != nil {
					seen[key] = true
					refs := append([]Reference{}, g.References...)
					refs = append(refs, requirementReferences(covering)...)
					excess = append(excess, Excess{
						GrantID:           g.ID,
						Action:            action,
						Resources:         []string{pattern},
						RequiredResources: narrower,
						Reason:            "action is required only for a narrower resource scope than granted",
						References:        refs,
					})
				}
			}
		}
	}

	return dedupeExcess(excess), gaps
}

// filterCoveringRequirements returns the requirements that this grant could
// plausibly be serving for one of its resource patterns: requirements are
// excluded only when a supported condition operator has proven the grant's
// own condition incompatible, OR when every one of the requirement's
// declared resources is a well-formed, canonical identifier that
// demonstrably does not overlap this pattern. A requirement with no
// declared resources, or with even one non-canonical/malformed resource
// token (a raw literal like "bucket" rather than an ARN or GCP canonical
// name), is never treated as disjoint — unknown resource scope
// conservatively covers every grant pattern rather than being asserted
// excess. This is evaluated per requirement/action, so one malformed or
// unknown-resource requirement never blocks excess detection for other,
// well-formed requirements or actions.
func filterCoveringRequirements(provider Provider, pattern string, g Grant, reqs []Requirement, resolved map[string]string) []Requirement {
	var out []Requirement
	for _, r := range reqs {
		if conditionsCompatible(g.Conditions, r.Conditions) == matchNo {
			continue
		}
		if !requirementResourceOverlaps(provider, pattern, r, resolved) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// isCanonicalResource reports whether a Requirement-declared resource token
// looks like a real provider resource identifier rather than a raw/generic
// field name a less careful extractor might emit (e.g. "bucket", "key").
// AWS requires an ARN or the literal wildcard "*"; GCP requires one of its
// canonical hierarchical resource-name prefixes or the full-resource-name
// "//" form.
func isCanonicalResource(provider Provider, resource string) bool {
	if resource == "" {
		return false
	}
	if resource == "*" {
		return true
	}
	if provider == AWS {
		return strings.HasPrefix(resource, "arn:")
	}
	for _, prefix := range []string{"projects/", "organizations/", "folders/", "//"} {
		if strings.HasPrefix(resource, prefix) {
			return true
		}
	}
	return false
}

// requirementResourceOverlaps reports whether a requirement's declared
// resources could plausibly be served by a grant's resource pattern. An
// empty resource list, or any single non-canonical resource token, is
// treated as unknown scope and conservatively overlaps everything.
func requirementResourceOverlaps(provider Provider, pattern string, r Requirement, resolved map[string]string) bool {
	if len(r.Resources) == 0 {
		return true
	}
	for _, res := range r.Resources {
		if !isCanonicalResource(provider, res) {
			return true
		}
		if resourcePatternsOverlap(provider, pattern, res, resolved) {
			return true
		}
	}
	return false
}

func requirementReferences(reqs []Requirement) []Reference {
	var refs []Reference
	for _, r := range reqs {
		refs = append(refs, r.References...)
	}
	return refs
}

// narrowRecommendation returns a concrete narrower resource list when a
// granted wildcard pattern is only ever exercised by covering requirements
// that each declare a concrete (non-wildcard), canonical resource set. It
// returns nil when the grant is already concrete, when any covering
// requirement's resource scope is itself unknown, malformed/non-canonical,
// or wildcarded, or when nothing would change — a malformed resource token
// is never used as a narrowing target.
//
// GCP is categorically excluded: a GCP Grant.Resources entry names the
// resource the IAM binding is attached to, not a filterable glob pattern
// the way an AWS ARN is. Recommending "narrow this project-level binding
// down to just these buckets" would imply moving the binding to a
// different attachment point via a different API/mechanism entirely, not
// an equivalent same-shape narrowing — never emit that blindly.
func narrowRecommendation(provider Provider, grantedPattern string, covering []Requirement) []string {
	if provider == GCP {
		return nil
	}
	if !strings.ContainsAny(grantedPattern, "*?") {
		return nil
	}
	unique := map[string]bool{}
	for _, r := range covering {
		if len(r.Resources) == 0 {
			return nil
		}
		for _, res := range r.Resources {
			if !isCanonicalResource(provider, res) {
				return nil
			}
			if strings.ContainsAny(res, "*?") || res == grantedPattern {
				return nil
			}
			unique[res] = true
		}
	}
	if len(unique) == 0 {
		return nil
	}
	out := make([]string, 0, len(unique))
	for r := range unique {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// dedupeExcess removes exact duplicate Excess entries (same grant, action,
// and resource scopes) and returns a stably ordered slice.
func dedupeExcess(items []Excess) []Excess {
	seen := map[string]bool{}
	out := make([]Excess, 0, len(items))
	for _, it := range items {
		key := it.GrantID + "|" + it.Action + "|" + strings.Join(sortedCopy(it.Resources), ",") + "|" + strings.Join(sortedCopy(it.RequiredResources), ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GrantID != out[j].GrantID {
			return out[i].GrantID < out[j].GrantID
		}
		return out[i].Action < out[j].Action
	})
	return out
}
