package cloudidentity

import (
	"fmt"
	"sort"
	"strings"
)

// awsActionService extracts the lowercase service prefix from an AWS action
// pattern (e.g. "s3" from "s3:Get*"). ok is false when the pattern has no
// colon or the service component itself is wildcarded, meaning it spans
// every service cloudidentity knows about. Collection requests a
// cross-service catalog page for such patterns (see
// collectionDefinitionRequest in collection_policy.go).
func awsActionService(pattern string) (string, bool) {
	idx := strings.Index(pattern, ":")
	if idx < 0 {
		return "", false
	}
	service := strings.ToLower(pattern[:idx])
	if strings.ContainsAny(service, "*?") {
		return "", false
	}
	return service, true
}

// normalizeActionDefinition strips References so two ActionDefinitions for
// the same action name can be compared on content alone.
func normalizeActionDefinition(a ActionDefinition) ActionDefinition {
	return ActionDefinition{Name: a.Name, ResourceTypes: sortedCopy(a.ResourceTypes)}
}

// normalizeOperationDefinition deliberately excludes SDKServices: SDK
// namespace aliasing (which alias a provider SDK happens to expose the same
// operation under) is cosmetic metadata, not policy content, so a changed
// alias set alone must never trip the conflicting_definition path. Callers
// merge SDKServices separately as a unioned set regardless of whether the
// rest of the body agrees. DependenciesComplete IS included: it's a
// documented-upper-bound-proof claim about the Permissions set, so two
// inputs disagreeing on it for the same operation is a real semantic
// conflict (one claims the dependency set is conservative/proven, the
// other doesn't), not cosmetic metadata like SDKServices.
func normalizeOperationDefinition(o OperationDefinition) OperationDefinition {
	return OperationDefinition{
		Provider:               o.Provider,
		Service:                o.Service,
		Operation:              o.Operation,
		SDKMethods:             sortedCopy(o.SDKMethods),
		Permissions:            sortedCopy(o.Permissions),
		ConditionalPermissions: sortedCopy(o.ConditionalPermissions),
		DependenciesComplete:   o.DependenciesComplete,
	}
}

func normalizeRoleDefinition(r RoleDefinition) RoleDefinition {
	return RoleDefinition{Name: r.Name, Permissions: sortedCopy(r.Permissions)}
}

// definitionEntry tracks the first-seen body (for output) alongside a
// content digest (for conflict detection) and accumulated References.
type definitionEntry[T any] struct {
	value      T
	bodyDigest string
}

// MergeDefinitions combines Definitions collected from multiple
// CloudReader.Define calls (for example AWS and GCP, incremental catalog
// pages, or repeated calls across a scan) into one set, keyed by stable
// identity: action Name, operation Provider+Service+Operation, role Name,
// policy ARN.
//
// A duplicate key is only safely mergeable when its semantic body is
// identical across inputs (ignoring References and list order, which may
// legitimately differ by source) — in that case References are unioned and
// the first body is kept. A duplicate key whose permissions, resource
// types, conditional permissions, or (for managed policies) grants actually
// differ is a conflicting_definition Gap: MergeDefinitions never silently
// trusts whichever input happened to arrive first, and Complete becomes
// false for the whole merge, since a conflicting definition means at least
// one cloud response was stale, paginated differently, or otherwise
// unreliable.
func MergeDefinitions(all ...Definitions) Definitions {
	var merged Definitions
	merged.Complete = len(all) > 0
	conflict := false
	awsServiceCatalogComplete := false

	actions := map[string]*definitionEntry[ActionDefinition]{}
	var actionOrder []string
	ops := map[string]*definitionEntry[OperationDefinition]{}
	var opOrder []string
	roles := map[string]*definitionEntry[RoleDefinition]{}
	var roleOrder []string
	policies := map[string]*definitionEntry[ManagedPolicy]{}
	var policyOrder []string

	conflictGap := func(kind, key string) Gap {
		return Gap{
			Code:    "cloudidentity.conflicting_definition",
			Scope:   kind + ":" + key,
			Message: fmt.Sprintf("%s definition %q has conflicting content across merged Definitions inputs; neither is trusted", kind, key),
		}
	}
	digestGap := func(kind, key string, err error) Gap {
		return Gap{
			Code:    "cloudidentity.definition_digest_unavailable",
			Scope:   kind + ":" + key,
			Message: fmt.Sprintf("%s definition %q could not be fingerprinted for conflict detection: %v", kind, key, err),
		}
	}

	for _, d := range all {
		merged.Complete = merged.Complete && d.Complete
		merged.Gaps = append(merged.Gaps, d.Gaps...)
		awsServiceCatalogComplete = awsServiceCatalogComplete || d.AWSServiceCatalogComplete

		for _, a := range d.Actions {
			digest, err := digestJSON(normalizeActionDefinition(a))
			if err != nil {
				conflict = true
				merged.Gaps = append(merged.Gaps, digestGap("action", a.Name, err))
				continue
			}
			if existing, ok := actions[a.Name]; ok {
				if existing.bodyDigest != digest {
					conflict = true
					merged.Gaps = append(merged.Gaps, conflictGap("action", a.Name))
					continue
				}
				existing.value.References = append(existing.value.References, a.References...)
				continue
			}
			actions[a.Name] = &definitionEntry[ActionDefinition]{value: a, bodyDigest: digest}
			actionOrder = append(actionOrder, a.Name)
		}

		for _, o := range d.Operations {
			key := string(o.Provider) + "|" + o.Service + "|" + o.Operation
			digest, err := digestJSON(normalizeOperationDefinition(o))
			if err != nil {
				conflict = true
				merged.Gaps = append(merged.Gaps, digestGap("operation", key, err))
				continue
			}
			if existing, ok := ops[key]; ok {
				existing.value.SDKServices = dedupSorted(append(existing.value.SDKServices, o.SDKServices...))
				if existing.bodyDigest != digest {
					conflict = true
					merged.Gaps = append(merged.Gaps, conflictGap("operation", key))
					continue
				}
				existing.value.References = append(existing.value.References, o.References...)
				continue
			}
			ops[key] = &definitionEntry[OperationDefinition]{value: o, bodyDigest: digest}
			opOrder = append(opOrder, key)
		}

		for _, r := range d.Roles {
			digest, err := digestJSON(normalizeRoleDefinition(r))
			if err != nil {
				conflict = true
				merged.Gaps = append(merged.Gaps, digestGap("role", r.Name, err))
				continue
			}
			if existing, ok := roles[r.Name]; ok {
				if existing.bodyDigest != digest {
					conflict = true
					merged.Gaps = append(merged.Gaps, conflictGap("role", r.Name))
					continue
				}
				existing.value.References = append(existing.value.References, r.References...)
				continue
			}
			roles[r.Name] = &definitionEntry[RoleDefinition]{value: r, bodyDigest: digest}
			roleOrder = append(roleOrder, r.Name)
		}

		for _, p := range d.Policies {
			normalizedGrants, normalizeErr := normalizeGrantsForDrift(p.Grants)
			var digest string
			var err error
			if normalizeErr != nil {
				err = normalizeErr
			} else {
				digest, err = digestJSON(normalizedGrants)
			}
			if err != nil {
				conflict = true
				merged.Gaps = append(merged.Gaps, digestGap("policy", p.ARN, err))
				continue
			}
			if existing, ok := policies[p.ARN]; ok {
				if existing.bodyDigest != digest {
					conflict = true
					merged.Gaps = append(merged.Gaps, conflictGap("policy", p.ARN))
					continue
				}
				existing.value.References = append(existing.value.References, p.References...)
				continue
			}
			policies[p.ARN] = &definitionEntry[ManagedPolicy]{value: p, bodyDigest: digest}
			policyOrder = append(policyOrder, p.ARN)
		}
	}

	if conflict {
		merged.Complete = false
	}
	// AWSServiceCatalogComplete is only true when some input asserted it
	// AND the merge had no content conflicts: a conflicting duplicate
	// definition means at least one input's data is untrustworthy, which
	// could just as easily be the full-catalog claim itself.
	merged.AWSServiceCatalogComplete = awsServiceCatalogComplete && !conflict

	sort.Strings(actionOrder)
	for _, k := range actionOrder {
		merged.Actions = append(merged.Actions, actions[k].value)
	}
	sort.Strings(opOrder)
	for _, k := range opOrder {
		merged.Operations = append(merged.Operations, ops[k].value)
	}
	sort.Strings(roleOrder)
	for _, k := range roleOrder {
		merged.Roles = append(merged.Roles, roles[k].value)
	}
	sort.Strings(policyOrder)
	for _, k := range policyOrder {
		merged.Policies = append(merged.Policies, policies[k].value)
	}

	contentDigest, digestErr := definitionsContentDigest(merged)
	if digestErr != nil {
		merged.Complete = false
		merged.AWSServiceCatalogComplete = false
		merged.Gaps = append(merged.Gaps, digestGap("merged", "content", digestErr))
	}
	merged.Digest = contentDigest

	return merged
}

// definitionsContentDigest consumes key-sorted slices. Empty categories use
// nil in both merge and validation so a serialized snapshot keeps its digest.
func definitionsContentDigest(d Definitions) (string, error) {
	return digestJSON(struct {
		Actions    []ActionDefinition
		Operations []OperationDefinition
		Roles      []RoleDefinition
		Policies   []ManagedPolicy
	}{d.Actions, d.Operations, d.Roles, d.Policies})
}
