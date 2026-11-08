package cloudidentity

import (
	"regexp"
	"strings"
)

// gcpImpersonationPermissions lists the GCP permissions that grant the
// ability to impersonate (assume) a service account's identity.
// iam.serviceAccounts.actAs is deliberately excluded — it lets a caller
// attach the service account to a resource it creates, analogous to AWS
// iam:PassRole, not assume the identity directly — a documented bounded
// limitation, not an oversight.
var gcpImpersonationPermissions = map[string]bool{
	"iam.serviceAccounts.getAccessToken":     true,
	"iam.serviceAccounts.getOpenIdToken":     true,
	"iam.serviceAccounts.signBlob":           true,
	"iam.serviceAccounts.signJwt":            true,
	"iam.serviceAccounts.implicitDelegation": true,
}

// gcpGrantIsTrustCapable reports whether a GCP PolicyState.Trust Grant's
// bound IAM role is actually capable of impersonation, using
// Evidence.Definitions.Roles. A service account's own IAM policy
// (gcpTrustFromServiceAccountPolicy) is converted entirely into Trust
// regardless of role, including roles that only let a caller view or
// administer metadata (e.g. roles/iam.serviceAccountViewer) without ever
// being able to assume the identity; those are not trust relationships at
// all and must be ignored by the trust gate. A role unknown to Definitions
// is treated conservatively as impersonation-capable (never silently
// cleared); a role with no Role field (should not occur for GCP trust) is
// also treated conservatively as capable.
func gcpGrantIsTrustCapable(g Grant, defs Definitions) bool {
	if g.Role == "" {
		return true
	}
	for _, r := range defs.Roles {
		if r.Name != g.Role {
			continue
		}
		for _, p := range r.Permissions {
			if gcpImpersonationPermissions[p] {
				return true
			}
		}
		return false
	}
	return true
}

// resolvedIdentifier keys, as documented by the AWS/GCP collection agents.
// Collectors key EKS OIDC provider ARNs and the EKS Pod Identity service
// principal here; other resolvedIdentifier keys collectors write (for
// example GCP project numbers) are consumed by collection-time trust
// scoping elsewhere in this file, not by a decision function in this
// block.
const (
	resolvedAWSOIDCProviderARNPrefix = "aws_eks_oidc_provider_arn:"

	awsPodIdentityServicePrincipal = "Service:pods.eks.amazonaws.com"
)

// awsFederatedSubjects extracts exact (StringEquals) "...:sub" condition
// values from a trust grant's Conditions. exact is false when there is no
// such condition (unrestricted) or only a wildcard/unsupported one
// (StringLike or anything else), since neither can be safely enumerated
// against known consumers.
func awsFederatedSubjects(conditions []Condition) ([]string, bool) {
	var subjects []string
	foundRestriction := false
	for _, c := range conditions {
		if !strings.HasSuffix(strings.ToLower(c.Key), ":sub") {
			continue
		}
		foundRestriction = true
		if c.Operator != "StringEquals" {
			return nil, false
		}
		subjects = append(subjects, c.Values...)
	}
	if !foundRestriction {
		return nil, false
	}
	return subjects, true
}

// awsPodIdentitySessionTagRestriction extracts the StringEquals session-tag
// values that restrict an EKS Pod Identity assumption to specific
// cluster/namespace/service-account combinations. ok is false unless all
// three keys are present with the StringEquals operator — any other
// operator, or a missing key, leaves the assumption unrestricted and must
// never be treated as scoped.
func awsPodIdentitySessionTagRestriction(conditions []Condition) (clusters, namespaces, serviceAccounts []string, ok bool) {
	sawCluster, sawNamespace, sawSA := false, false, false
	for _, c := range conditions {
		key := strings.ToLower(c.Key)
		switch key {
		case "aws:requesttag/eks-cluster-name", "aws:requesttag/eks-cluster-arn":
			if c.Operator != "StringEquals" {
				return nil, nil, nil, false
			}
			clusters = append(clusters, c.Values...)
			sawCluster = true
		case "aws:requesttag/kubernetes-namespace":
			if c.Operator != "StringEquals" {
				return nil, nil, nil, false
			}
			namespaces = append(namespaces, c.Values...)
			sawNamespace = true
		case "aws:requesttag/kubernetes-service-account":
			if c.Operator != "StringEquals" {
				return nil, nil, nil, false
			}
			serviceAccounts = append(serviceAccounts, c.Values...)
			sawSA = true
		}
	}
	if !sawCluster || !sawNamespace || !sawSA {
		return nil, nil, nil, false
	}
	return clusters, namespaces, serviceAccounts, true
}

func stringValueMatches(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// clusterValuesMatch compares EKS Pod Identity session-tag cluster values
// (which may be a bare cluster name or a full cluster ARN) against a
// Workload's own Cluster field (a bare name).
func clusterValuesMatch(values []string, cluster string) bool {
	for _, v := range values {
		if v == cluster {
			return true
		}
		if idx := strings.LastIndex(v, "cluster/"); idx >= 0 && v[idx+len("cluster/"):] == cluster {
			return true
		}
	}
	return false
}

// parseGCPBracketBinding parses "PROJECT.svc.id.goog[NAMESPACE/SA]" (the
// text following "serviceAccount:"). PROJECT is the Workload Identity
// pool's hosting project.
func parseGCPBracketBinding(rest string) (project, namespace, sa string, ok bool) {
	open := strings.Index(rest, "[")
	closeIdx := strings.Index(rest, "]")
	if !strings.Contains(rest, ".svc.id.goog") || open < 0 || closeIdx <= open {
		return "", "", "", false
	}
	project = strings.TrimSuffix(rest[:open], ".svc.id.goog")
	subject := rest[open+1 : closeIdx]
	parts := strings.SplitN(subject, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return project, parts[0], parts[1], true
}

// parseGCPPrincipalSubject parses the modern Workload Identity Federation
// principal form:
// "principal://iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/POOLPROJECT.svc.id.goog/subject/ns/NAMESPACE/sa/SA".
// poolProject is the Workload Identity pool's hosting project (the text
// before ".svc.id.goog" in the workloadIdentityPools segment).
func parseGCPPrincipalSubject(member string) (namespace, sa, poolProject string, ok bool) {
	const subjectMarker = "/subject/"
	subjectIdx := strings.Index(member, subjectMarker)
	if subjectIdx < 0 {
		return "", "", "", false
	}
	fields := strings.Split(member[subjectIdx+len(subjectMarker):], "/")
	if len(fields) != 4 || fields[0] != "ns" || fields[2] != "sa" || fields[1] == "" || fields[3] == "" {
		return "", "", "", false
	}

	const poolMarker = "/workloadIdentityPools/"
	poolIdx := strings.Index(member, poolMarker)
	if poolIdx < 0 {
		return "", "", "", false
	}
	poolSegment := member[poolIdx+len(poolMarker) : subjectIdx]
	poolProject = strings.TrimSuffix(poolSegment, ".svc.id.goog")
	if poolProject == "" || poolProject == poolSegment {
		return "", "", "", false
	}

	return fields[1], fields[3], poolProject, true
}

// subjectMayAssumePrincipal reports whether e's resolved principal could
// plausibly be the identity an un-rendered ServiceAccount configures: the
// ServiceAccount named serviceAccount, in namespace, within target (the
// scan target whose manifest render could not see that ServiceAccount's
// own identity annotations). It is the trust-based gate for
// cloud_identity.inventory.service_account_not_rendered: that gap hides
// only WHICH principal this one already-identified Kubernetes subject
// configures, never whether other workloads/subjects exist, so it must
// never demote every cohort in the target's identity domain -- only
// cohorts whose own positively observed (live) trust could actually admit
// this exact subject. It is deliberately conservative: unresolved
// observation, an empty observed Trust set, or a trust member this
// package cannot parse all count as "may admit" rather than silently
// excluding the hidden subject.
func subjectMayAssumePrincipal(e Evidence, target ScanTarget, namespace, serviceAccount string) bool {
	if e.Principal.Provider != target.Provider {
		return false
	}
	// A direct KSA placeholder for this exact cluster/namespace/SA IS the
	// hidden subject itself -- affected by definition. A placeholder for
	// any other subject is untouched by this gate (stays as today).
	if isUnresolvedCloudPrincipal(e.Principal) {
		return e.Principal.ID == manifestInventoryKSASubject(target.Cluster, namespace, serviceAccount)
	}
	if !e.Observed.Complete || len(e.Observed.Trust) == 0 {
		return true
	}
	switch e.Principal.Provider {
	case AWS:
		return awsSubjectMayAssume(e, target.Cluster, namespace, serviceAccount)
	case GCP:
		return gcpSubjectMayAssume(e, target.Project, target.Cluster, namespace, serviceAccount)
	default:
		return true
	}
}

// awsSubjectMayAssume checks e's Observed.Trust for an AWS role against the
// Kubernetes OIDC subject "system:serviceaccount:<namespace>:<serviceAccount>",
// mirroring the member forms assessAWSPodIdentityTrust/awsTrustMemberLinks
// already recognize: a Federated member whose StringEquals ":sub" condition
// exactly lists this subject (or carries no exact restriction at all) and
// whose OIDC provider ARN matches the target cluster's resolved provider or
// is itself unresolved; or the EKS Pod Identity service principal unless
// its StringEquals session-tag conditions provably exclude this exact
// cluster/namespace/service-account combination.
func awsSubjectMayAssume(e Evidence, cluster, namespace, serviceAccount string) bool {
	subject := "system:serviceaccount:" + namespace + ":" + serviceAccount
	expectedProviderARN := e.ResolvedIdentifiers[resolvedAWSOIDCProviderARNPrefix+cluster]
	for _, g := range e.Observed.Trust {
		if g.Effect != "Allow" {
			continue
		}
		for _, member := range g.Members {
			switch {
			case member == awsPodIdentityServicePrincipal:
				clusters, namespaces, serviceAccounts, ok := awsPodIdentitySessionTagRestriction(g.Conditions)
				if !ok {
					return true
				}
				if clusterValuesMatch(clusters, cluster) && stringValueMatches(namespaces, namespace) && stringValueMatches(serviceAccounts, serviceAccount) {
					return true
				}
			case strings.HasPrefix(member, "Federated:"):
				providerARN := strings.TrimPrefix(member, "Federated:")
				if expectedProviderARN != "" && providerARN != expectedProviderARN {
					continue
				}
				subjects, exact := awsFederatedSubjects(g.Conditions)
				if !exact {
					return true
				}
				if stringValueMatches(subjects, subject) {
					return true
				}
			}
		}
	}
	return false
}

// gcpSubjectMayAssume checks e's Observed.Trust for a GCP service account
// against the Kubernetes Workload Identity Federation subject (project,
// cluster, namespace, serviceAccount), skipping Trust grants whose bound
// role is confirmed not impersonation-capable the same way the trust gate
// elsewhere does.
func gcpSubjectMayAssume(e Evidence, project, cluster, namespace, serviceAccount string) bool {
	for _, g := range e.Observed.Trust {
		if g.Effect != "Allow" {
			continue
		}
		if !gcpGrantIsTrustCapable(g, e.Definitions) {
			continue
		}
		for _, member := range g.Members {
			if gcpMemberMayAdmitSubject(member, project, cluster, namespace, serviceAccount) {
				return true
			}
		}
	}
	return false
}

var (
	gcpPrincipalSetNamespacePattern = regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[^/]+/locations/global/workloadIdentityPools/([^/]+)\.svc\.id\.goog/namespace/([^/]+)$`)
	gcpPrincipalSetPoolPattern      = regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[^/]+/locations/global/workloadIdentityPools/([^/]+)\.svc\.id\.goog/\*$`)
	gcpPrincipalSetClusterPattern   = regexp.MustCompile(`^principalSet://iam\.googleapis\.com/projects/[^/]+/locations/global/workloadIdentityPools/([^/]+)\.svc\.id\.goog/kubernetes\.cluster/https://container\.googleapis\.com/v1/projects/[^/]+/locations/[^/]+/clusters/([^/]+)$`)
)

// gcpMemberMayAdmitSubject reports whether one GCP Trust Grant member could
// admit the Kubernetes Workload Identity Federation subject identified by
// project/cluster/namespace/serviceAccount. Only member forms that bind a
// Kubernetes Workload Identity pool subject are considered; an unparseable
// instance of one of those forms is conservative (may admit), but an
// entirely unrelated IAM member form (a human user, group, domain, or a
// GSA's own email) can never represent a Kubernetes ServiceAccount subject.
func gcpMemberMayAdmitSubject(member, project, cluster, namespace, serviceAccount string) bool {
	switch {
	case strings.HasPrefix(member, "principal://"):
		ns, sa, poolProject, ok := parseGCPPrincipalSubject(member)
		if !ok {
			return true
		}
		return poolProject == project && ns == namespace && sa == serviceAccount
	case strings.HasPrefix(member, "serviceAccount:"):
		poolProject, ns, sa, ok := parseGCPBracketBinding(strings.TrimPrefix(member, "serviceAccount:"))
		if !ok {
			return true
		}
		return poolProject == project && ns == namespace && sa == serviceAccount
	case strings.HasPrefix(member, "principalSet://"):
		if m := gcpPrincipalSetNamespacePattern.FindStringSubmatch(member); m != nil {
			return m[1] == project && m[2] == namespace
		}
		if m := gcpPrincipalSetPoolPattern.FindStringSubmatch(member); m != nil {
			return m[1] == project
		}
		if m := gcpPrincipalSetClusterPattern.FindStringSubmatch(member); m != nil {
			return m[1] == project && m[2] == cluster
		}
		return true
	default:
		return false
	}
}

// cohortMayBeAffectedByTargetGap reports whether cohort could plausibly be
// impacted by a target-scoped inventory gap in target: either a known
// consumer was actually collected from target, cohort's own Principal IS an
// unresolved KSA placeholder for target's cluster, or cohort's positively
// observed trust could admit some UNKNOWN workload belonging to target's
// cluster/project -- the hidden identities a failed render in a DIFFERENT
// target can never rule out. Account/project equality on its own is no
// longer sufficient: a role whose consumers and exact observed trust are
// confined to a different cluster in the same account/project must never
// be demoted by a gap in a target it has no relationship to. Gating is on
// which of target's Account/Project fields are populated and cohort's own
// Principal.Provider, never on target.Provider alone: a cluster's
// single AWS-provider ScanTarget also carries its paired GCP
// Project, so a resolved GCP cohort IS linked to that cluster's own
// render/contract gaps too (review finding #1b), while a target missing
// the complementary Account/Project field never spuriously matches a
// cohort in that other domain.
func cohortMayBeAffectedByTargetGap(cohort Evidence, target ScanTarget) bool {
	for _, consumer := range cohort.Consumers {
		if target.Account != "" && consumer.Cluster == target.Cluster && consumer.CloudAccount == target.Account {
			return true
		}
		if target.Project != "" && consumer.CloudProject == target.Project {
			return true
		}
	}
	if isUnresolvedCloudPrincipal(cohort.Principal) {
		// An unrendered/unresolved KSA placeholder for THIS target's
		// cluster is itself a hidden subject the failed render could not
		// identify; a placeholder for any other cluster is untouched.
		return target.Cluster != "" && strings.HasPrefix(cohort.Principal.ID, "k8s://"+target.Cluster+"/")
	}
	switch cohort.Principal.Provider {
	case AWS:
		if target.Account == "" || cohort.Principal.Account != target.Account {
			return false
		}
		if !cohort.Observed.Complete || len(cohort.Observed.Trust) == 0 {
			// Trust itself is unknown/incomplete: stay conservative rather
			// than silently excluding this target's hidden workloads.
			return true
		}
		return awsObservedTrustMayAdmitCluster(cohort, target.Cluster)
	case GCP:
		if target.Project == "" || cohort.Principal.Project != target.Project {
			return false
		}
		if !cohort.Observed.Complete || len(cohort.Observed.Trust) == 0 {
			return true
		}
		return gcpObservedTrustMayAdmitCluster(cohort, target.Project, target.Cluster)
	default:
		return true
	}
}

// awsObservedTrustMayAdmitCluster reports whether cohort's Observed.Trust
// could admit SOME unknown Kubernetes workload belonging to cluster -- no
// specific namespace/ServiceAccount subject is known, unlike
// awsSubjectMayAssume. A Federated member admits the cluster when its
// provider ARN matches cluster's resolved OIDC provider, or that provider
// is itself unresolved (conservative). The Pod Identity service principal
// admits the cluster unless its StringEquals session-tag conditions
// restrict assumption to a set of clusters that provably excludes it.
func awsObservedTrustMayAdmitCluster(e Evidence, cluster string) bool {
	expectedProviderARN := e.ResolvedIdentifiers[resolvedAWSOIDCProviderARNPrefix+cluster]
	for _, g := range e.Observed.Trust {
		if g.Effect != "Allow" {
			continue
		}
		for _, member := range g.Members {
			switch {
			case member == awsPodIdentityServicePrincipal:
				clusters, _, _, ok := awsPodIdentitySessionTagRestriction(g.Conditions)
				if !ok || clusterValuesMatch(clusters, cluster) {
					return true
				}
			case strings.HasPrefix(member, "Federated:"):
				providerARN := strings.TrimPrefix(member, "Federated:")
				if expectedProviderARN == "" || providerARN == expectedProviderARN {
					return true
				}
			}
		}
	}
	return false
}

// gcpObservedTrustMayAdmitCluster reports whether cohort's Observed.Trust
// could admit SOME unknown Kubernetes workload belonging to project/cluster,
// skipping grants whose bound role is confirmed not impersonation-capable
// (gcpGrantIsTrustCapable, the same conservative possibly-capable gate used
// elsewhere -- an unresolved role stays capable).
func gcpObservedTrustMayAdmitCluster(e Evidence, project, cluster string) bool {
	for _, g := range e.Observed.Trust {
		if g.Effect != "Allow" {
			continue
		}
		if !gcpGrantIsTrustCapable(g, e.Definitions) {
			continue
		}
		for _, member := range g.Members {
			if gcpMemberMayAdmitClusterWorkloads(member, project, cluster) {
				return true
			}
		}
	}
	return false
}

// gcpMemberMayAdmitClusterWorkloads reports whether one GCP Trust Grant
// member could admit SOME unknown Kubernetes Workload Identity Federation
// subject within project/cluster. Unlike gcpMemberMayAdmitSubject, there is
// no concrete namespace/ServiceAccount to check: a legacy
// "serviceAccount:PROJECT.svc.id.goog[ns/sa]" or modern "principal://...
// workloadIdentityPools/PROJECT.svc.id.goog/subject/ns/SA" member naming an
// exact ns/sa still cannot be ruled out, since a target whose render failed
// could hide a workload matching that exact subject; only the pool's own
// project is checked. A principalSet:// pool/namespace form is checked at
// its own project (and namespace, where present) scope; a cluster-scoped
// principalSet also requires the cluster to match. An unparseable
// pool-shaped member stays conservative (may admit).
func gcpMemberMayAdmitClusterWorkloads(member, project, cluster string) bool {
	switch {
	case strings.HasPrefix(member, "principal://"):
		_, _, poolProject, ok := parseGCPPrincipalSubject(member)
		if !ok {
			return true
		}
		return poolProject == project
	case strings.HasPrefix(member, "serviceAccount:"):
		poolProject, _, _, ok := parseGCPBracketBinding(strings.TrimPrefix(member, "serviceAccount:"))
		if !ok {
			return true
		}
		return poolProject == project
	case strings.HasPrefix(member, "principalSet://"):
		if m := gcpPrincipalSetNamespacePattern.FindStringSubmatch(member); m != nil {
			return m[1] == project
		}
		if m := gcpPrincipalSetPoolPattern.FindStringSubmatch(member); m != nil {
			return m[1] == project
		}
		if m := gcpPrincipalSetClusterPattern.FindStringSubmatch(member); m != nil {
			return m[1] == project && m[2] == cluster
		}
		return true
	default:
		return false
	}
}

// gcpGrantRoleProvenImpersonationCapable reports whether g's bound IAM
// role is POSITIVELY proven capable of impersonation: resolved in
// Evidence.Definitions.Roles and carrying at least one of
// gcpImpersonationPermissions. Unlike gcpGrantIsTrustCapable (used for
// gap-scoping elsewhere in this package, where an unresolved role must
// stay conservatively capable so a hidden gap is never silently
// cleared), a role this package cannot resolve is treated as NOT proven
// here: this gate backs a graph edge asserting confirmed live access,
// which must never be established from an unresolved role (review
// finding #5).
func gcpGrantRoleProvenImpersonationCapable(g Grant, defs Definitions) bool {
	if g.Role == "" {
		return false
	}
	for _, r := range defs.Roles {
		if r.Name != g.Role {
			continue
		}
		for _, p := range r.Permissions {
			if gcpImpersonationPermissions[p] {
				return true
			}
		}
		return false
	}
	return false
}

// gcpGrantBindingIsUnconditional reports whether g carries no binding
// condition, or every one of its CEL Conditions is the literal
// expression "true" -- the only shape GCPWorkloadIdentityUserBindingIsLive
// can prove unconditionally admits the subject without a CEL evaluator.
// A grant whose condition is "false", unresolved, or any other
// expression never counts as confirmed live access here (review
// finding #5): whether some OTHER condition actually admits this subject
// is unknown, and the edge must never guess.
func gcpGrantBindingIsUnconditional(g Grant) bool {
	for _, c := range g.Conditions {
		if c.Expression != "true" {
			return false
		}
	}
	return true
}

// GCPWorkloadIdentityUserBindingIsLive is the single validated gate
// internal/sourceprojection's can_impersonate graph edge uses, so a
// custom role whose name merely contains "workloadIdentityUser" (but
// grants no actual impersonation permission) can never spoof a confirmed
// live binding (review finding #3): role capability is resolved via
// evidence.Definitions.Roles (gcpGrantRoleProvenImpersonationCapable)
// rather than a bare role-name substring match. Unlike the conservative
// gap-scoping gates elsewhere in this package, an UNRESOLVED role here
// never confirms the edge (review finding #5): this function asserts
// proven live access, so only a role Definitions actually resolved with
// an impersonation permission counts, and only when the binding itself
// carries no condition (or every condition is the literal "true") --
// a conditional binding whose CEL expression this package cannot
// evaluate must never be treated as unconditionally live. Only the
// ordinary GKE default-pool member form
// ("serviceAccount:<project>.svc.id.goog[...]" or
// "principal://.../workloadIdentityPools/<project>.svc.id.goog/subject/...")
// is admitted, by EXACT subject match -- never the conservative "unparseable
// member may admit" fallback gcpMemberMayAdmitSubject uses for gap-scoping,
// since that would again let an unrelated/malformed member spoof an edge.
// A custom (non-GKE) Workload Identity Federation pool member (Contract
// A.4) is never admitted here: whether its provider issuer/
// attribute_mapping/attribute_condition actually admits this subject is a
// detection decision VulnView makes from GCPWorkloadIdentityProviders,
// downstream of this native graph projection, including for members
// bound through a custom pool (Contract A.4/A.5).
func GCPWorkloadIdentityUserBindingIsLive(evidence Evidence, project, namespace, serviceAccount string) bool {
	if project == "" || namespace == "" || serviceAccount == "" {
		return false
	}
	for _, g := range evidence.Observed.Trust {
		if g.Effect != "Allow" || !gcpGrantRoleProvenImpersonationCapable(g, evidence.Definitions) || !gcpGrantBindingIsUnconditional(g) {
			continue
		}
		for _, member := range g.Members {
			if gcpMemberExactlyAdmitsGKESubject(member, project, namespace, serviceAccount, evidence.ResolvedIdentifiers) {
				return true
			}
		}
	}
	return false
}

// gcpMemberExactlyAdmitsGKESubject reports whether member is the ordinary
// GKE default-pool form naming EXACTLY project/namespace/serviceAccount.
// Unlike gcpMemberMayAdmitSubject, an unparseable or custom-pool member is
// never admitted (false, not conservative "may admit"): this gate backs a
// graph edge asserting confirmed live access, not a gap-scoping decision
// that must stay conservative about hidden workloads. For the
// "principal://.../projects/<number>/..." form, the member's own embedded
// project NUMBER must also equal the number the live GCP reader resolved
// for project (resolved["gcp_project_number:"+project],
// sources/internal/cloudidentity/gcp_reader.go's
// resolveCallerProjectNumbers): the pool project ID segment alone is not
// a stable identity -- a member naming a DIFFERENT project's numeric
// project under the same pool-project-id text must never admit. An
// unknown expected number never admits either: this gate asserts proven
// access, so an unresolved number is never treated as a match.
func gcpMemberExactlyAdmitsGKESubject(member, project, namespace, serviceAccount string, resolved map[string]string) bool {
	switch {
	case strings.HasPrefix(member, "principal://"):
		ns, sa, poolProject, ok := parseGCPPrincipalSubject(member)
		if !ok || poolProject != project || ns != namespace || sa != serviceAccount {
			return false
		}
		number, numberOK := gcpPrincipalProjectNumber(member)
		expected, expectedOK := resolved["gcp_project_number:"+project]
		return numberOK && expectedOK && expected != "" && number == expected
	case strings.HasPrefix(member, "serviceAccount:"):
		poolProject, ns, sa, ok := parseGCPBracketBinding(strings.TrimPrefix(member, "serviceAccount:"))
		return ok && poolProject == project && ns == namespace && sa == serviceAccount
	default:
		return false
	}
}

// gcpPrincipalProjectNumber extracts the numeric project number from a
// "principal://iam.googleapis.com/projects/<number>/..." member string.
func gcpPrincipalProjectNumber(member string) (string, bool) {
	const marker = "/projects/"
	idx := strings.Index(member, marker)
	if idx < 0 {
		return "", false
	}
	rest := member[idx+len(marker):]
	end := strings.Index(rest, "/")
	if end < 0 {
		return "", false
	}
	number := rest[:end]
	if number == "" {
		return "", false
	}
	for _, c := range number {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return number, true
}
