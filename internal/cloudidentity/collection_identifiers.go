package cloudidentity

import (
	"fmt"
	"strings"
)

// Only independently resolved, target-bound identifiers cross into HCL. Live
// grants never become desired policy, and conflicting observations stay unknown.
func collectionTargetIdentifiers(observed []Evidence, target ScanTarget) map[string]string {
	identifiers := make(map[string]string)
	conflicts := make(map[string]bool)
	for _, evidence := range observed {
		belongs := false
		for _, consumer := range evidence.Consumers {
			if consumer.Cluster == target.Cluster && consumer.Environment == target.Environment && consumer.CloudAccount == target.Account && consumer.CloudProject == target.Project {
				belongs = true
				break
			}
		}
		if !belongs {
			continue
		}
		for key, value := range evidence.ResolvedIdentifiers {
			if key != "aws_eks_oidc_issuer:"+target.Cluster && !strings.HasPrefix(key, "gcp_project_number:") {
				continue
			}
			if previous, exists := identifiers[key]; exists && previous != value {
				conflicts[key] = true
			}
			identifiers[key] = value
		}
	}
	for key := range conflicts {
		delete(identifiers, key)
	}
	return identifiers
}

// collectionWorkloadScopedGapCodes are inventory gap codes where the
// affected workload and its principal(s) are already fully, individually
// known; the gap describes uncertainty about that one workload's service
// grouping/configuration, never about whether other workloads or
// identities exist or are hidden.
var collectionWorkloadScopedGapCodes = map[string]bool{
	"cloud_identity.inventory.unmapped_service":          true,
	"cloud_identity.inventory.ambiguous_service_mapping": true,
	"cloud_identity.inventory.unresolved_config":         true,
}

// collectionServiceAccountNotRenderedGapCode is Inventory's gap for a
// ServiceAccount referenced by a known workload that was not among the
// rendered manifests. It hides only WHICH principal that one
// already-identified Kubernetes subject (namespace/ServiceAccount)
// configures, never whether other workloads or subjects exist, so it gets
// its own subject-scoped treatment rather than the blanket target-scoped
// one: collectionApplySubjectScopedGaps scopes it, after observation, to
// only the resolved cohorts whose live trust could plausibly admit that
// exact subject (see subjectMayAssumePrincipal in trust.go).
const collectionServiceAccountNotRenderedGapCode = "cloud_identity.inventory.service_account_not_rendered"

var collectionSubjectScopedGapCodes = map[string]bool{
	collectionServiceAccountNotRenderedGapCode: true,
}

// collectionUnresolvedValueInObjectGapCode is the renderer's object-scoped
// gap (sources/internal/cloudidentity/manifest_renderer.go) for a rendered
// object carrying an unresolved Terraform-contract value marker. Unlike
// every other gap code, its scope (workload- vs target-scoped) depends on
// the touched object itself, not the code alone -- see
// collectionGapIsIdentityBearingObject.
const collectionUnresolvedValueInObjectGapCode = "cloud_identity.manifest.unresolved_value_in_object"

// collectionIdentityBearingAPIGroups are the Crossplane IAM-declaration
// (DeclarationsFromManifests) and ACK (DeclarationsFromACK) API groups
// whose every recognized -- and every unrecognized, still-gapped -- kind
// declares or binds a cloud identity.
var collectionIdentityBearingAPIGroups = map[string]bool{
	"iam.aws.upbound.io": true, "iam.aws.crossplane.io": true, "iam.aws.m.upbound.io": true,
	"iam.cnrm.cloud.google.com": true, "cloudplatform.gcp.upbound.io": true, "iam.gcp.upbound.io": true, "cloudplatform.gcp.m.upbound.io": true,
	ackIAMAPIGroup: true, ackEKSAPIGroup: true,
}

// collectionGapIsIdentityBearingObject classifies a
// collectionUnresolvedValueInObjectGapCode gap's own Scope
// ("<apiVersion>|<kind>|<namespace>|<name>", the renderer's object-scoped
// format) by whether the touched object itself can bear or declare a
// cloud identity: a ServiceAccount (annotations), a workload kind
// Inventory reads spec.serviceAccountName from
// (manifestInventorySupportedKinds, plus Argo Rollout), or any Crossplane/
// ACK IAM-declaration object. An unresolved Terraform-contract value
// reaching any OTHER object (a ConfigMap, a non-identity env var, a
// karpenter NodeClass, ...) never hides a principal or a consumer, so it
// must never demote collection/cohort completeness on its own (review
// finding #4).
func collectionGapIsIdentityBearingObject(scope string) bool {
	parts := strings.SplitN(scope, "|", 4)
	if len(parts) != 4 {
		return true // Unrecognized scope shape: conservative.
	}
	apiVersion, kind := parts[0], parts[1]
	if kind == "ServiceAccount" || kind == "Rollout" || manifestInventorySupportedKinds[kind] {
		return true
	}
	return collectionIdentityBearingAPIGroups[manifestInventoryAPIGroup(apiVersion)]
}

func collectionGapIsWorkloadScoped(g Gap) bool {
	if g.Code == collectionUnresolvedValueInObjectGapCode {
		return !collectionGapIsIdentityBearingObject(g.Scope)
	}
	return collectionWorkloadScopedGapCodes[g.Code]
}

func collectionGapIsSubjectScoped(g Gap) bool {
	return collectionSubjectScopedGapCodes[g.Code]
}

// collectionGapIsTargetScoped reports whether g can hide workloads or
// their identities anywhere in a target's identity domain -- as opposed to
// merely narrowing one already fully identified workload's service
// grouping/configuration (workload-scoped), or hiding only which principal
// one already-identified ServiceAccount subject configures
// (subject-scoped). Codes this package does not recognize default
// target-scoped: render, repository, composition and identity-resolution
// failures can hide anything, so unknown codes stay conservative rather
// than silently narrowing scope.
func collectionGapIsTargetScoped(g Gap) bool {
	return !collectionGapIsWorkloadScoped(g) && !collectionGapIsSubjectScoped(g)
}

// collectionHasTargetScopedGap reports whether any gap in gaps can hide
// workloads or their identities (as opposed to merely narrowing one already
// fully identified workload's service grouping, or one already-identified
// subject's unknown principal).
func collectionHasTargetScopedGap(gaps []Gap) bool {
	for _, g := range gaps {
		if collectionGapIsTargetScoped(g) {
			return true
		}
	}
	return false
}

// collectionHasNonWorkloadScopedGap reports whether gaps contains a
// target-scoped or subject-scoped gap -- anything beyond uncertainty about
// one already-identified workload's own service grouping/configuration.
// Collection.InventoryComplete, the global summary, goes false for either.
func collectionHasNonWorkloadScopedGap(gaps []Gap) bool {
	for _, g := range gaps {
		if !collectionGapIsWorkloadScoped(g) {
			return true
		}
	}
	return false
}

// collectionCohortTargetScopedGaps returns one gap per target whose
// target-scoped inventory gaps could affect cohort, decided AFTER
// observation (cohort.Observed must already be populated) via
// cohortMayBeAffectedByTargetGap in trust.go: a known consumer actually
// collected from that target, cohort's own Principal is an unresolved KSA
// placeholder for that target's cluster, or cohort's own positively
// observed trust could admit some unknown workload belonging to that
// target's cluster/project (or that trust is itself unknown/incomplete).
// Bare account/project equality is no longer sufficient: a role whose
// consumers and exact observed trust are confined to a different cluster
// in the same account/project must never be demoted by a gap in a target
// it has no relationship to. A non-empty result demotes the cohort's
// ConsumerInventoryComplete and says which target did it.
func collectionCohortTargetScopedGaps(cohort Evidence, targets []targetCollection) []Gap {
	var gaps []Gap
	for _, t := range targets {
		if !collectionHasTargetScopedGap(t.inventoryGaps) || !cohortMayBeAffectedByTargetGap(cohort, t.target) {
			continue
		}
		gaps = append(gaps, collectionGap("target_inventory_incomplete", t.target.Name, "A target sharing this principal's identity domain has unresolved inventory; unseen workloads there could use this principal"))
	}
	return gaps
}

func collectionConsumerDeclarationGaps(consumers []Workload, targets []targetCollection) []Gap {
	ids := make(map[string]struct{}, len(consumers))
	for _, consumer := range consumers {
		ids[consumer.ID] = struct{}{}
	}
	var gaps []Gap
	for _, target := range targets {
		for _, workload := range target.workloads {
			if _, belongs := ids[workload.ID]; belongs {
				gaps = append(gaps, target.declarationGaps...)
				break
			}
		}
	}
	return dedupeGaps(gaps)
}

// collectionSubjectGap pairs a subject-scoped inventory gap (today, only
// cloud_identity.inventory.service_account_not_rendered) with the target
// it came from, so the exact Kubernetes subject it hides -- (target's
// cluster/account/project/region, namespace, ServiceAccount) -- can be
// checked against each resolved cohort's live trust.
type collectionSubjectGap struct {
	target         ScanTarget
	namespace      string
	serviceAccount string
}

// collectionSubjectGapsFromTargets extracts one collectionSubjectGap per
// subject-scoped gap recorded against each target, parsing the gap's
// "<namespace>/<serviceAccount>" Scope -- the form Inventory emits for
// cloud_identity.inventory.service_account_not_rendered.
func collectionSubjectGapsFromTargets(targets []targetCollection) []collectionSubjectGap {
	var subjects []collectionSubjectGap
	for _, t := range targets {
		for _, g := range t.inventoryGaps {
			if !collectionGapIsSubjectScoped(g) {
				continue
			}
			namespace, serviceAccount, ok := strings.Cut(g.Scope, "/")
			if !ok {
				continue
			}
			subjects = append(subjects, collectionSubjectGap{target: t.target, namespace: namespace, serviceAccount: serviceAccount})
		}
	}
	return subjects
}

// collectionApplySubjectScopedGaps demotes cohort.ConsumerInventoryComplete,
// with a gap naming the affected target and hidden subject, for every
// recorded subject-scoped gap whose hidden ServiceAccount's live trust
// (per subjectMayAssumePrincipal in trust.go) could plausibly configure
// cohort's own principal. It never touches a cohort whose own positively
// observed trust provably admits only a different subject.
func collectionApplySubjectScopedGaps(cohort Evidence, subjects []collectionSubjectGap) Evidence {
	for _, s := range subjects {
		if !subjectMayAssumePrincipal(cohort, s.target, s.namespace, s.serviceAccount) {
			continue
		}
		cohort.ConsumerInventoryComplete = false
		cohort.Gaps = append(cohort.Gaps, collectionGap("unrendered_service_account_trust", cohort.Principal.ID, fmt.Sprintf("ServiceAccount %q in namespace %q (target %q) was not among the rendered manifests; this principal's live trust cannot rule out that it configures that ServiceAccount's identity", s.serviceAccount, s.namespace, s.target.Name)))
	}
	return cohort
}
