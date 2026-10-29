package cloudidentitysource

import (
	"fmt"
	"regexp"
	"strings"
)

// Principal.Kind values this reader observes. Any other kind is out of scope
// and produces a gap rather than a guess.
const (
	gcpKindServiceAccount           = "gcp_service_account"
	gcpKindKubernetesServiceAccount = "gcp_kubernetes_service_account"
)

const gcpServiceAccountEmailSuffix = ".iam.gserviceaccount.com"

// gcpProjectFromServiceAccountEmail extracts the project id embedded in a GSA
// email address, e.g. "deploy@my-project.iam.gserviceaccount.com" -> "my-project".
func gcpProjectFromServiceAccountEmail(email string) (string, bool) {
	email = strings.TrimSpace(email)
	at := strings.LastIndex(email, "@")
	if at < 0 || !strings.HasSuffix(email, gcpServiceAccountEmailSuffix) {
		return "", false
	}
	domain := email[at+1:]
	project := strings.TrimSuffix(domain, gcpServiceAccountEmailSuffix)
	if project == "" {
		return "", false
	}
	return project, true
}

// gcpKSAIdentity is a parsed "k8s://<cluster>/<namespace>/sa/<name>" principal
// id, the shape Manifest Inventory emits for direct Workload Identity
// Federation KSA principals.
type gcpKSAIdentity struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
}

func gcpParseKSAIdentity(id string) (gcpKSAIdentity, bool) {
	const prefix = "k8s://"
	id = strings.TrimSpace(id)
	if !strings.HasPrefix(id, prefix) {
		return gcpKSAIdentity{}, false
	}
	segments := strings.Split(strings.TrimPrefix(id, prefix), "/")
	if len(segments) != 4 || segments[2] != "sa" {
		return gcpKSAIdentity{}, false
	}
	cluster, namespace, name := segments[0], segments[1], segments[3]
	if cluster == "" || namespace == "" || name == "" {
		return gcpKSAIdentity{}, false
	}
	return gcpKSAIdentity{Cluster: cluster, Namespace: namespace, ServiceAccount: name}, true
}

// gcpWorkloadIdentityPool returns GKE's fixed default Workload Identity pool
// id for a project, documented at
// https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity.
func gcpWorkloadIdentityPool(projectID string) string {
	return projectID + ".svc.id.goog"
}

// gcpApplicablePrincipal is one principal/principalSet identifier that would
// grant access to a specific KSA, paired with how specific the grant is so
// callers can explain *why* a binding applies (exact identity vs. namespace-
// wide vs. cluster-wide vs. pool-wide vs. resource-hierarchy-wide), per
// https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity
// and https://docs.cloud.google.com/iam/docs/principal-identifiers.
type gcpApplicablePrincipal struct {
	Member      string
	Specificity string // "exact" | "namespace" | "cluster" | "pool" | "hierarchy"
}

// gcpKSAApplicableMembers lists every documented GCP principal identifier
// form that grants access to a given KSA through GKE's default Workload
// Identity pool EXCEPT the cluster-scoped principalSet: the exact subject,
// the legacy exact bracket form, the namespace-wide principalSet, and the
// pool-wide wildcard principalSet. There is no cluster-scoped form here
// because building it requires the cluster's region/zone, which is not
// available from a bare Principal/Workload pair; callers that need the
// cluster-scoped form must build it separately with
// gcpKSAClusterScopedMember once a region is known.
func gcpKSAApplicableMembers(projectNumber string, projectID string, namespace string, serviceAccount string) []gcpApplicablePrincipal {
	pool := gcpWorkloadIdentityPool(projectID)
	base := fmt.Sprintf("iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s", projectNumber, pool)
	return []gcpApplicablePrincipal{
		{Member: fmt.Sprintf("principal://%s/subject/ns/%s/sa/%s", base, namespace, serviceAccount), Specificity: "exact"},
		{Member: gcpLegacyKSAMember(projectID, namespace, serviceAccount), Specificity: "exact"},
		{Member: fmt.Sprintf("principalSet://%s/namespace/%s", base, namespace), Specificity: "namespace"},
		{Member: fmt.Sprintf("principalSet://%s/*", base), Specificity: "pool"},
	}
}

// gcpLegacyKSAMember is the deprecated but still-honored exact member form
// documented at
// https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity#identifying_namespace_and_service_account.
func gcpLegacyKSAMember(projectID string, namespace string, serviceAccount string) string {
	return fmt.Sprintf("serviceAccount:%s[%s/%s]", gcpWorkloadIdentityPool(projectID), namespace, serviceAccount)
}

// gcpKSAClusterScopedMember builds the cluster-scoped principalSet that
// applies to every workload (regardless of namespace/service account)
// running on one specific GKE cluster, per
// https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity#cluster_identifiers.
// Unlike gcpKSAApplicableMembers' other forms this requires the cluster's
// location (region/zone) and name, which are only available from the
// Workload that carries this KSA, not from a bare Principal.
func gcpKSAClusterScopedMember(projectNumber string, projectID string, region string, cluster string) string {
	base := fmt.Sprintf("iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s", projectNumber, gcpWorkloadIdentityPool(projectID))
	return fmt.Sprintf("principalSet://%s/kubernetes.cluster/https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s", base, projectID, region, cluster)
}

// gcpAncestorResourceName converts one Resource Manager ancestor entry into
// its "projects/<n>" | "folders/<n>" | "organizations/<n>" resource name.
// An unrecognized ancestor type returns "", so callers can surface an
// explicit gap instead of silently skipping an ancestor they cannot name.
func gcpAncestorResourceName(ancestor gcpAncestor) string {
	switch ancestor.ResourceID.Type {
	case "project":
		return "projects/" + ancestor.ResourceID.ID
	case "folder":
		return "folders/" + ancestor.ResourceID.ID
	case "organization":
		return "organizations/" + ancestor.ResourceID.ID
	default:
		return ""
	}
}

// gcpHierarchyServiceAccountPrincipalSets lists the
// principalSet://cloudresourcemanager.googleapis.com/<ancestor>/type/ServiceAccount
// candidates documented at
// https://cloud.google.com/iam/docs/principal-identifiers, one per resolved
// ancestor of a GSA's project (the project itself, its folders, and its
// organization). These grant to EVERY service account under that ancestor,
// so matching bindings never carry the GSA's own email as a member.
func gcpHierarchyServiceAccountPrincipalSets(ancestors []gcpAncestor) []gcpApplicablePrincipal {
	var candidates []gcpApplicablePrincipal
	for _, ancestor := range ancestors {
		name := gcpAncestorResourceName(ancestor)
		if name == "" {
			continue
		}
		candidates = append(candidates, gcpApplicablePrincipal{
			Member:      "principalSet://cloudresourcemanager.googleapis.com/" + name + "/type/ServiceAccount",
			Specificity: "hierarchy",
		})
	}
	return candidates
}

// gcpServiceAccountMember is the exact IAM member string for a GSA.
func gcpServiceAccountMember(email string) string {
	return "serviceAccount:" + strings.TrimSpace(email)
}

// gcpMatchingMembers returns the subset of a binding's members that exactly
// match one of the candidate applicable members, alongside the broadest
// specificity among matches. An empty result means this binding does not
// apply to the principal under evaluation; callers must not include it.
func gcpMatchingMembers(bindingMembers []string, candidates []gcpApplicablePrincipal) ([]string, string) {
	index := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		index[candidate.Member] = candidate.Specificity
	}
	var matched []string
	specificity := ""
	for _, member := range bindingMembers {
		level, ok := index[member]
		if !ok {
			continue
		}
		matched = append(matched, member)
		if specificity == "" || gcpSpecificityRank(level) < gcpSpecificityRank(specificity) {
			specificity = level
		}
	}
	return matched, specificity
}

func gcpSpecificityRank(level string) int {
	switch level {
	case "exact":
		return 0
	case "namespace":
		return 1
	case "cluster":
		return 2
	case "pool":
		return 3
	case "hierarchy":
		return 4
	default:
		return 5
	}
}

// gcpKSASubjectPattern, gcpKSANamespaceSetPattern, gcpKSAPoolSetPattern,
// gcpKSALegacyPattern, and gcpKSAClusterSetPattern recognize every
// documented pool-scoped GKE Workload Identity principal/principalSet form
// (https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity#principal_identifiers),
// so gcpKSAMemberCouldApply can tell an unsupported/unverifiable form that
// might still apply to this KSA apart from a form that unambiguously
// addresses a DIFFERENT namespace/service-account/cluster and therefore
// never could.
var (
	gcpKSASubjectPattern      = regexp.MustCompile(`^principal://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+\.svc\.id\.goog/subject/ns/([^/]+)/sa/([^/]+)$`)
	gcpKSANamespaceSetPattern = regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+\.svc\.id\.goog/namespace/([^/]+)$`)
	gcpKSAPoolSetPattern      = regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+\.svc\.id\.goog/\*$`)
	gcpKSALegacyPattern       = regexp.MustCompile(`^serviceAccount:[^.]+\.svc\.id\.goog\[([^/]+)/([^\]]+)\]$`)
	gcpKSAClusterSetPattern   = regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+\.svc\.id\.goog/kubernetes\.cluster/https://container\.googleapis\.com/v1/projects/[^/]+/locations/[^/]+/clusters/([^/]+)$`)
)

// gcpKSAMemberCouldApply reports whether a binding member that already
// matched this KSA's workload identity pool substring in the org-wide
// search, but did NOT exactly match any built candidate, could still
// plausibly apply to this exact namespace/service-account and must
// therefore be treated as an incomplete/unresolved surface rather than
// silently ignored. A member unambiguously scoped to a different namespace,
// service account, or cluster is never flagged: GKE's own pool is shared by
// every KSA in the project, so most pool-substring matches are routine noise
// from unrelated service accounts.
func gcpKSAMemberCouldApply(member string, namespace string, serviceAccount string, clusterKnown bool, cluster string) bool {
	switch {
	case gcpKSASubjectPattern.MatchString(member):
		match := gcpKSASubjectPattern.FindStringSubmatch(member)
		return match[1] == namespace && match[2] == serviceAccount
	case gcpKSALegacyPattern.MatchString(member):
		match := gcpKSALegacyPattern.FindStringSubmatch(member)
		return match[1] == namespace && match[2] == serviceAccount
	case gcpKSANamespaceSetPattern.MatchString(member):
		match := gcpKSANamespaceSetPattern.FindStringSubmatch(member)
		return match[1] == namespace
	case gcpKSAClusterSetPattern.MatchString(member):
		if !clusterKnown {
			return true
		}
		match := gcpKSAClusterSetPattern.FindStringSubmatch(member)
		return match[1] == cluster
	case gcpKSAPoolSetPattern.MatchString(member):
		return true
	default:
		// A pool-substring match in a shape none of the documented forms
		// recognize: could be a future/undocumented identifier form,
		// never silently dropped.
		return true
	}
}

// gcpCanonicalKSAPrincipalPattern matches the fully-qualified cloud principal
// identifier for a KSA under GKE's default Workload Identity pool:
// https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity.
// This is the canonical cloud identity: the same namespace/service-account
// name in two different clusters that share the same pool (i.e. the same GCP
// project) is the SAME principal to IAM ("identity sameness"), regardless of
// cluster.
var gcpCanonicalKSAPrincipalPattern = regexp.MustCompile(`^principal://iam\.googleapis\.com/projects/([0-9]+)/locations/global/workloadIdentityPools/([a-z0-9-]+)\.svc\.id\.goog/subject/ns/([^/]+)/sa/([^/]+)$`)

// gcpCanonicalKSAURI builds the canonical principal:// identifier for a KSA.
func gcpCanonicalKSAURI(projectNumber string, projectID string, namespace string, serviceAccount string) string {
	return fmt.Sprintf("principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/ns/%s/sa/%s", projectNumber, gcpWorkloadIdentityPool(projectID), namespace, serviceAccount)
}

// gcpParseCanonicalKSAPrincipal parses an already-canonical principal:// KSA
// identifier. Unlike gcpParseKSAIdentity it needs no live project-number
// resolution: the project number and project id are embedded in the URI
// itself, so Observe can search immediately without an extra Resource
// Manager call (avoiding redundant resolution when a cohort was already
// regrouped onto its canonical identifier upstream).
func gcpParseCanonicalKSAPrincipal(id string) (projectNumber string, projectID string, namespace string, serviceAccount string, ok bool) {
	match := gcpCanonicalKSAPrincipalPattern.FindStringSubmatch(strings.TrimSpace(id))
	if match == nil {
		return "", "", "", "", false
	}
	return match[1], match[2], match[3], match[4], true
}
