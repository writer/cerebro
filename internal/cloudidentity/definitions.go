package cloudidentity

import (
	"fmt"
	"sort"
	"strings"
)

// expandedPolicy is a PolicyState whose Role-referencing Grants have been
// resolved against Definitions, in evaluation order: layer 0 is the identity
// Grants, the rest are PolicyState.Boundaries (each intersects the identity
// layer per AWS permissions-boundary / GCP IAM-condition semantics).
type expandedPolicy struct {
	layers [][]Grant
	gaps   []Gap
}

func expandPolicyState(provider Provider, policy PolicyState, defs Definitions) expandedPolicy {
	var ep expandedPolicy
	identity, gaps := expandGrantLayer(provider, policy.Grants, defs)
	ep.layers = append(ep.layers, identity)
	ep.gaps = append(ep.gaps, gaps...)
	for _, boundary := range policy.Boundaries {
		layer, layerGaps := expandGrantLayer(provider, boundary, defs)
		ep.layers = append(ep.layers, layer)
		ep.gaps = append(ep.gaps, layerGaps...)
	}
	return ep
}

// expandGrantLayer resolves each Role-referencing Grant (an unexpanded
// AWS managed-policy ARN or GCP role name) against Definitions. A Grant
// without Role passes through unchanged. A Role that cannot be resolved is
// dropped from the effective surface entirely (never assumed broad or
// narrow) and recorded as a missing-definition Gap.
func expandGrantLayer(provider Provider, grants []Grant, defs Definitions) ([]Grant, []Gap) {
	var out []Grant
	var gaps []Gap
	for _, g := range grants {
		if g.Role == "" {
			out = append(out, g)
			continue
		}
		expanded, ok := expandRoleGrant(provider, g, defs)
		if !ok {
			gaps = append(gaps, Gap{
				Code:       "cloudidentity.missing_role_definition",
				Scope:      g.Role,
				Message:    fmt.Sprintf("no definition found for role/policy %q; its effective permissions are unknown", g.Role),
				References: g.References,
			})
			continue
		}
		out = append(out, expanded...)
	}
	return out, gaps
}

func expandRoleGrant(provider Provider, g Grant, defs Definitions) ([]Grant, bool) {
	if provider == AWS {
		for _, policy := range defs.Policies {
			if policy.ARN != g.Role {
				continue
			}
			merged := make([]Grant, 0, len(policy.Grants))
			for _, pg := range policy.Grants {
				cp := pg
				cp.References = append(append([]Reference{}, g.References...), pg.References...)
				merged = append(merged, cp)
			}
			return merged, true
		}
		return nil, false
	}
	for _, role := range defs.Roles {
		if role.Name != g.Role {
			continue
		}
		if len(role.Permissions) == 0 {
			// A known role/custom-role definition with zero Permissions
			// (e.g. a disabled/deleted GCP custom role) is a KNOWN inactive
			// binding: it is resolved (not a missing definition), but
			// expands to no grant at all — never a Grant with empty
			// Actions, which concreteActionsForGrant would otherwise treat
			// as an unknown action surface and gap on.
			return nil, true
		}
		cp := g
		cp.Role = ""
		cp.Actions = append([]string{}, role.Permissions...)
		cp.References = append(append([]Reference{}, g.References...), role.References...)
		return []Grant{cp}, true
	}
	return nil, false
}

// concreteActionsForGrant resolves a Grant's Actions/NotActions pattern into
// the concrete action/permission names it covers. For GCP, Actions after
// role expansion already enumerate exact permission strings. For AWS, it
// expands wildcard patterns against the known-action catalog in Definitions,
// scoped to the pattern's service prefix. A NotAction-only grant (no
// Action patterns at all) and any pattern whose service component is
// itself wildcarded (including a bare "*") are cross-service: their
// positive complement spans every AWS service, not just the services
// named in the pattern text, per AWS NotAction semantics. Exact expansion
// of a cross-service pattern requires awsServiceCatalogComplete (the full
// AWS Service Reference catalog was acquired, not just the services this
// grant happens to mention); without it the action surface is unknown. ok
// is false when cloudidentity has no catalog entries to resolve against,
// or a cross-service pattern cannot be exactly expanded — callers must not
// assume excess in that case, only that the scope is unknown.
func concreteActionsForGrant(provider Provider, g Grant, knownActionsByService map[string][]string, awsServiceCatalogComplete bool) ([]string, bool) {
	if provider != AWS {
		if len(g.Actions) == 0 {
			return nil, false
		}
		return dedupSorted(g.Actions), true
	}

	patterns := g.Actions
	// A NotAction-only grant's complement is inherently cross-service: it
	// is never scoped by the services its own NotAction patterns happen to
	// name (that would compute the complement service-locally, hiding
	// excess in every other service the grant actually reaches).
	crossService := len(patterns) == 0 && len(g.NotActions) > 0
	if len(patterns) == 0 {
		patterns = g.NotActions
	}

	services := map[string]bool{}
	for _, p := range patterns {
		svc, ok := awsActionService(p)
		if !ok {
			crossService = true
			continue
		}
		services[svc] = true
	}
	if crossService {
		if !awsServiceCatalogComplete {
			return nil, false
		}
		for s := range knownActionsByService {
			services[s] = true
		}
	}

	resolvedAny := false
	var out []string
	for svc := range services {
		known := knownActionsByService[svc]
		if len(known) == 0 {
			continue
		}
		resolvedAny = true
		for _, action := range known {
			if matchActionAgainstGrant(provider, g, action) == matchYes {
				out = append(out, action)
			}
		}
	}
	if !resolvedAny {
		return nil, false
	}
	return dedupSorted(out), true
}

// awsActionService extracts the lowercase service prefix from an AWS action
// pattern (e.g. "s3" from "s3:Get*"). ok is false when the pattern has no
// colon or the service component itself is wildcarded, meaning it spans
// every service cloudidentity knows about.
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

func buildKnownActionsByService(defs Definitions) map[string][]string {
	out := map[string][]string{}
	for _, a := range defs.Actions {
		svc, ok := awsActionService(a.Name)
		if !ok {
			svc = strings.ToLower(a.Name)
		}
		out[svc] = append(out[svc], a.Name)
	}
	return out
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

	for _, d := range all {
		merged.Complete = merged.Complete && d.Complete
		merged.Gaps = append(merged.Gaps, d.Gaps...)
		awsServiceCatalogComplete = awsServiceCatalogComplete || d.AWSServiceCatalogComplete

		for _, a := range d.Actions {
			digest := Digest(normalizeActionDefinition(a))
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
			digest := Digest(normalizeOperationDefinition(o))
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
			digest := Digest(normalizeRoleDefinition(r))
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
			digest := Digest(normalizeGrantsForDrift(p.Grants))
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

	merged.Digest = definitionsContentDigest(merged)

	return merged
}

// definitionsContentDigest consumes key-sorted slices. Empty categories use
// nil in both merge and validation so a serialized snapshot keeps its digest.
func definitionsContentDigest(d Definitions) string {
	return Digest(struct {
		Actions    []ActionDefinition
		Operations []OperationDefinition
		Roles      []RoleDefinition
		Policies   []ManagedPolicy
	}{d.Actions, d.Operations, d.Roles, d.Policies})
}
