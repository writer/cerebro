package cloudidentity

import (
	"maps"
	"slices"
	"sort"
	"strings"
)

// Alias resolution precedes investigation: two KSAs resolving to one role must
// never independently suggest removing permissions required by the other KSA.
func collectionResolvedCohorts(observed []Evidence) []Evidence {
	cohorts := make(map[string]Evidence, len(observed))
	for _, evidence := range observed {
		old := evidence.Principal
		if principal, resolved := collectionResolvedPrincipal(evidence); resolved {
			evidence.Principal = principal
			for index := range evidence.Consumers {
				consumer := &evidence.Consumers[index]
				consumer.Principals = slices.Clone(consumer.Principals)
				for i, principal := range consumer.Principals {
					if collectionPrincipalKey(principal) == collectionPrincipalKey(old) {
						consumer.Principals[i] = evidence.Principal
					}
				}
			}
		}
		key := collectionPrincipalKey(evidence.Principal)
		if previous, ok := cohorts[key]; ok {
			evidence = collectionMergeCohort(previous, evidence)
		}
		cohorts[key] = evidence
	}
	keys := make([]string, 0, len(cohorts))
	for key := range cohorts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Evidence, 0, len(keys))
	for _, key := range keys {
		result = append(result, cohorts[key])
	}
	return result
}

func collectionResolvedPrincipal(evidence Evidence) (Principal, bool) {
	principal := evidence.Principal
	switch principal.Provider {
	case AWS:
		role := evidence.ResolvedIdentifiers["aws_pod_identity_role:"+principal.ID]
		parts := strings.SplitN(role, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[4] != principal.Account || !strings.HasPrefix(parts[5], "role/") {
			return principal, false
		}
		principal.ID, principal.Kind = role, "aws_iam_role"
	case GCP:
		identity := evidence.ResolvedIdentifiers["gcp_ksa_principal:"+principal.ID]
		prefix := "principal://iam.googleapis.com/projects/" + evidence.ResolvedIdentifiers["project_number"] + "/locations/global/workloadIdentityPools/" + principal.Project + ".svc.id.goog/subject/ns/"
		if !strings.HasPrefix(identity, prefix) || evidence.ResolvedIdentifiers["project_number"] == "" {
			return principal, false
		}
		principal.ID, principal.Kind = identity, "gcp_workload_identity_principal"
	default:
		return principal, false
	}
	return principal, true
}

func collectionMergeCohort(left, right Evidence) Evidence {
	left.ConsumerInventoryComplete = left.ConsumerInventoryComplete && right.ConsumerInventoryComplete
	consumers := make(map[string]Workload, len(left.Consumers)+len(right.Consumers))
	for _, consumer := range left.Consumers {
		consumers[consumer.ID] = consumer
	}
	for _, consumer := range right.Consumers {
		if previous, ok := consumers[consumer.ID]; ok && collectionConsumerDigest(previous) != collectionConsumerDigest(consumer) {
			left.ConsumerInventoryComplete = false
			left.Gaps = append(left.Gaps, collectionGap("consumer_declaration_conflict", consumer.ID, "The same consumer has conflicting pinned declarations"))
		}
		consumers[consumer.ID] = consumer
	}
	left.Consumers = make([]Workload, 0, len(consumers))
	for _, consumer := range consumers {
		left.Consumers = append(left.Consumers, consumer)
	}
	sort.Slice(left.Consumers, func(i, j int) bool { return left.Consumers[i].ID < left.Consumers[j].ID })
	if collectionPolicyDigest(left.Observed) != collectionPolicyDigest(right.Observed) {
		left.Observed.Complete = false
		left.Observed.Gaps = append(left.Observed.Gaps, collectionGap("observed_policy_conflict", left.Principal.ID, "Repeated observations of the resolved principal disagree within this collection"))
	}
	left.Observed.Complete = left.Observed.Complete && right.Observed.Complete
	left.Observed.Gaps = append(left.Observed.Gaps, right.Observed.Gaps...)
	left.Observed.References = append(left.Observed.References, right.Observed.References...)
	left.Declared.Gaps = append(left.Declared.Gaps, right.Declared.Gaps...)
	left.Definitions = MergeDefinitions(left.Definitions, right.Definitions)
	left.Gaps = append(left.Gaps, right.Gaps...)
	left.ResolvedIdentifiers = maps.Clone(left.ResolvedIdentifiers)
	if left.ResolvedIdentifiers == nil {
		left.ResolvedIdentifiers = make(map[string]string)
	}
	for key, value := range right.ResolvedIdentifiers {
		if previous, ok := left.ResolvedIdentifiers[key]; ok && previous != value {
			left.ConsumerInventoryComplete = false
			left.Gaps = append(left.Gaps, collectionGap("identity_resolution_conflict", left.Principal.ID, "Live identity identifiers disagree within this collection"))
		}
		left.ResolvedIdentifiers[key] = value
	}
	return left
}

func collectionPolicyDigest(policy PolicyState) string {
	boundaries := make([]string, 0, len(policy.Boundaries))
	for _, boundary := range policy.Boundaries {
		boundaries = append(boundaries, Digest(collectionGrantDigests(boundary)))
	}
	sort.Strings(boundaries)
	return Digest(struct{ Grants, Boundaries, Trust []string }{collectionGrantDigests(policy.Grants), boundaries, collectionGrantDigests(policy.Trust)})
}

func collectionGrantDigests(grants []Grant) []string {
	result := make([]string, 0, len(grants))
	for _, grant := range grants {
		grant.ID, grant.References = "", nil
		result = append(result, Digest(grant))
	}
	sort.Strings(result)
	return slices.Compact(result)
}
