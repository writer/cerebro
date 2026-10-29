package cloudidentity

import (
	"slices"
	"sort"
	"strings"
)

func collectionPrincipalKey(principal Principal) string {
	id := principal.ID
	if principal.Provider == GCP {
		id = strings.TrimPrefix(id, "serviceAccount:")
	}
	return string(principal.Provider) + ":" + id
}

func collectionCohorts(workloads []Workload) map[string]Evidence {
	cohorts := make(map[string]Evidence)
	seen := make(map[string]map[string]struct{})
	digests := make(map[string]string, len(workloads))
	conflicts := make(map[string]bool)
	for _, workload := range workloads {
		digest := collectionConsumerDigest(workload)
		if previous, ok := digests[workload.ID]; ok && previous != digest {
			conflicts[workload.ID] = true
		}
		digests[workload.ID] = digest
	}
	for _, workload := range workloads {
		for _, principal := range workload.Principals {
			key := collectionPrincipalKey(principal)
			cohort, exists := cohorts[key]
			if !exists {
				cohort.Principal = principal
				cohort.ConsumerInventoryComplete = true
				seen[key] = make(map[string]struct{})
			}
			if _, exists := seen[key][workload.ID]; exists {
				continue
			}
			seen[key][workload.ID] = struct{}{}
			if conflicts[workload.ID] {
				cohort.ConsumerInventoryComplete = false
				cohort.Gaps = append(cohort.Gaps, collectionGap("consumer_declaration_conflict", workload.ID, "The same consumer has conflicting pinned declarations"))
			}
			cohort.Consumers = append(cohort.Consumers, workload)
			cohorts[key] = cohort
		}
	}
	for key, cohort := range cohorts {
		sort.Slice(cohort.Consumers, func(i, j int) bool { return cohort.Consumers[i].ID < cohort.Consumers[j].ID })
		cohorts[key] = cohort
	}
	return cohorts
}

func collectionConsumerDigest(workload Workload) string {
	workload.References = nil
	return Digest(workload)
}

func collectionDeclaration(principal Principal, declarations []Declaration, gaps []Gap) PolicyState {
	policy := PolicyState{Complete: true, Grants: []Grant{}}
	found := false
	seen := make(map[string]struct{})
	for _, declaration := range declarations {
		if collectionPrincipalKey(principal) != collectionPrincipalKey(declaration.Principal) {
			continue
		}
		key := Digest(declaration)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		found = true
		policy.Complete = policy.Complete && declaration.Policy.Complete
		policy.Grants = append(policy.Grants, declaration.Policy.Grants...)
		policy.Boundaries = append(policy.Boundaries, declaration.Policy.Boundaries...)
		policy.Trust = append(policy.Trust, declaration.Policy.Trust...)
		policy.References = append(policy.References, declaration.Policy.References...)
		policy.Gaps = append(policy.Gaps, declaration.Policy.Gaps...)
	}
	if !found {
		policy.Complete = false
		policy.Gaps = append(policy.Gaps, collectionGap("declaration_not_resolved", principal.ID, "No complete owning IaC declaration was resolved for this Kubernetes-used principal"))
	}
	// Evaluation gaps may hide a grant or attachment. Keep observations available,
	// but do not interpret absent unresolved declarations as an empty policy.
	if len(gaps) != 0 {
		policy.Complete = false
		policy.Gaps = append(policy.Gaps, gaps...)
	}
	return policy
}

// collectionDefinitionRequest gathers every Role/managed-policy reference
// and AWS action-service prefix across Grants, Boundaries, AND Trust (GCP
// trust classification needs Evidence.Definitions.Roles populated for the
// roles bound in PolicyState.Trust — see gcpGrantIsTrustCapable — so trust
// roles must be requested here too, not just permission-grant roles).
func collectionDefinitionRequest(policies ...PolicyState) DefinitionRequest {
	services, roles, managed := make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
	for _, policy := range policies {
		grants := slices.Clone(policy.Grants)
		for _, boundary := range policy.Boundaries {
			grants = append(grants, boundary...)
		}
		grants = append(grants, policy.Trust...)
		for _, grant := range grants {
			if strings.HasPrefix(grant.Role, "arn:") {
				managed[grant.Role] = struct{}{}
			} else if grant.Role != "" {
				roles[grant.Role] = struct{}{}
			}
			// A NotAction-only grant's positive complement spans every AWS
			// service, not just the services its own NotAction patterns
			// happen to name (AWS NotAction semantics), and so does any
			// individual pattern whose service component is itself
			// wildcarded (including a bare "*"). Both must request the
			// bare "*" service so a complete catalog can be acquired and
			// concreteActionsForGrant can compute an exact, not
			// service-local, action surface for them.
			crossService := len(grant.Actions) == 0 && len(grant.NotActions) > 0
			for _, actions := range [][]string{grant.Actions, grant.NotActions} {
				for _, action := range actions {
					if svc, ok := awsActionService(action); ok {
						services[svc] = struct{}{}
						continue
					}
					if action == "*" || strings.Contains(action, ":") {
						crossService = true
					}
				}
			}
			if crossService {
				services["*"] = struct{}{}
			}
		}
	}
	return DefinitionRequest{AWSServices: collectionSortedKeys(services), AWSPolicies: collectionSortedKeys(managed), GCPRoles: collectionSortedKeys(roles)}
}

func collectionSortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
