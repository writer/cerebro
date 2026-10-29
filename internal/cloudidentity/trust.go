package cloudidentity

import (
	"fmt"
	"regexp"
	"strings"
)

// trustKnownSubjects builds the canonical "known consumer subject" -> ALL
// matching source Workloads map used to reconcile declared/observed Trust
// grants against Evidence.Consumers. AWS IRSA subjects use the Kubernetes
// OIDC "system:serviceaccount:<ns>:<sa>" form; GCP Workload Identity
// subjects use "<ns>/<sa>". Every Workload sharing a subject is retained
// (not just the last one seen) because the same namespace/service-account
// subject legitimately recurs across multiple clusters/projects; each one
// must still be independently cross-checked against the cluster/project a
// specific trust grant actually claims to belong to.
func trustKnownSubjects(provider Provider, consumers []Workload) map[string][]Workload {
	known := map[string][]Workload{}
	for _, c := range consumers {
		if c.Namespace == "" || c.ServiceAccount == "" {
			continue
		}
		switch provider {
		case AWS:
			key := "system:serviceaccount:" + c.Namespace + ":" + c.ServiceAccount
			known[key] = append(known[key], c)
		case GCP:
			key := c.Namespace + "/" + c.ServiceAccount
			known[key] = append(known[key], c)
		}
	}
	return known
}

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

// gcpPositiveLinkPermissions lists the GCP permissions that establish a
// positive sharing link (narrower than gcpImpersonationPermissions, the
// conservative possibly-capable gate used by assessTrustCoverage/
// gcpGrantIsTrustCapable): per the binding-semantic contract, only actual
// credential-minting actions count — getOpenIdToken and implicitDelegation
// are excluded here even though they still make a role possibly-capable
// for the stricter excess gate.
var gcpPositiveLinkPermissions = map[string]bool{
	"iam.serviceAccounts.getAccessToken": true,
	"iam.serviceAccounts.signBlob":       true,
	"iam.serviceAccounts.signJwt":        true,
}

// gcpGrantPositiveLinkCapable reports whether a GCP Trust Grant's bound role
// is KNOWN (resolved in Definitions.Roles) and contains one of
// gcpPositiveLinkPermissions. Unlike gcpGrantIsTrustCapable, an unresolved
// role never counts: possibly-capable (conservative, for the excess gate)
// and positively-linked (for sharing counts) are deliberately different
// questions — an unknown role must keep the trust surface incomplete
// rather than silently contributing a confirmed sharing link.
func gcpGrantPositiveLinkCapable(g Grant, defs Definitions) bool {
	if g.Role == "" {
		return false
	}
	for _, r := range defs.Roles {
		if r.Name != g.Role {
			continue
		}
		for _, p := range r.Permissions {
			if gcpPositiveLinkPermissions[p] {
				return true
			}
		}
		return false
	}
	return false
}

// gcpBindingIsUnconditional reports whether a GCP Trust Grant's IAM
// condition (if any) is the positive-link contract's "unconditional"
// binding: no condition at all, or a condition whose CEL Expression is
// exactly the literal "true". Any other CEL expression — including the
// literal "false", which is inert and grants nothing — leaves the
// binding's actual effect on any specific consumer unconfirmed, so it must
// never positively link a consumer.
func gcpBindingIsUnconditional(g Grant) bool {
	for _, c := range g.Conditions {
		if strings.TrimSpace(c.Expression) != "true" {
			return false
		}
	}
	return true
}

// assessTrustCoverage reconciles declared/observed Trust grants (who may
// assume or impersonate this principal) against the known, reviewed
// consumer inventory. ConsumerInventoryComplete only reflects what the
// manifest/IaC scan found in the cluster; it says nothing about whether the
// cloud side's own trust policy actually restricts assumption to those
// consumers. A trust relationship that could admit identities outside the
// reviewed inventory — an unrestricted Federated (OIDC) principal, a
// wildcard/unsupported subject condition, a direct AWS account/user/role or
// non-Pod-Identity service-principal delegation, a GCP member that is not
// an exact Workload Identity binding, or an exact subject match whose OIDC
// provider/project cannot be confirmed to belong to that specific
// consumer's cluster/project — is flagged rather than silently trusted.
// Without the issuer/project cross-check, an exact "sub" match alone could
// be satisfied by a same-named service account living in an entirely
// different cluster.
func assessTrustCoverage(e Evidence) (bool, []Gap) {
	var trust []Grant
	trust = append(trust, e.Declared.Trust...)
	trust = append(trust, e.Observed.Trust...)
	if len(trust) == 0 {
		return true, nil
	}
	known := trustKnownSubjects(e.Principal.Provider, e.Consumers)

	ok := true
	var gaps []Gap
	flag := func(g Grant, member, reason string) {
		ok = false
		gaps = append(gaps, Gap{
			Code:       "cloudidentity.unresolved_trust_consumer",
			Scope:      member,
			Message:    fmt.Sprintf("trust grant %q principal %q %s; additional unseen consumers may be able to assume this principal", g.ID, member, reason),
			References: g.References,
		})
	}

	for _, g := range trust {
		if g.Effect != "Allow" {
			continue
		}
		if e.Principal.Provider == GCP && !gcpGrantIsTrustCapable(g, e.Definitions) {
			// Known role, no impersonation-capable permission: this binding
			// is not a trust relationship at all (e.g. a viewer-only role on
			// the service account), so the trust gate ignores it entirely.
			continue
		}
		for _, member := range g.Members {
			switch e.Principal.Provider {
			case AWS:
				assessAWSTrustMember(g, member, e, known, flag)
			case GCP:
				assessGCPTrustMember(g, member, known, e.ResolvedIdentifiers, flag)
			default:
				flag(g, member, "uses an unrecognized provider and cannot be reconciled against known consumers")
			}
		}
	}
	return ok, gaps
}

// gcpObservedTrustRolesResolved reports whether every Allow GCP
// Observed.Trust grant's bound role is resolved in Definitions.Roles — a
// requirement for Sharing's Clear verdict (AssessSharing) that is
// deliberately independent of, and stricter than, both
// assessTrustCoverage/gcpGrantIsTrustCapable (which conservatively treat an
// unresolved role as possibly-capable so Clear is never reached by
// mistake) and gcpGrantPositiveLinkCapable (which already excludes
// unresolved roles from positive linkage, but a structural member match on
// an unresolved role can still leave assessTrustCoverage's own gate
// satisfied). Without this independent check, a principal whose positive
// linkage comes entirely from AWS or a different grant could still read as
// Clear while a GCP trust grant with an unresolved role sits unexamined.
func gcpObservedTrustRolesResolved(e Evidence) (bool, []Gap) {
	if e.Principal.Provider != GCP {
		return true, nil
	}
	ok := true
	var gaps []Gap
	for _, g := range e.Observed.Trust {
		if g.Effect != "Allow" {
			continue
		}
		resolved := false
		for _, r := range e.Definitions.Roles {
			if r.Name == g.Role {
				resolved = true
				break
			}
		}
		if !resolved {
			ok = false
			gaps = append(gaps, Gap{
				Code:       "cloudidentity.unresolved_trust_role",
				Scope:      g.Role,
				Message:    fmt.Sprintf("trust grant %q binds role %q, which is not resolved in Definitions.Roles; its actual impersonation capability cannot be confirmed", g.ID, g.Role),
				References: g.References,
			})
		}
	}
	return ok, gaps
}

// resolvedIdentifier keys, as documented by the AWS/GCP collection agents.
// GCP project-number keys are scoped per consuming workload's own cloud
// project ("gcp_project_number:<Workload.CloudProject>"), never a single
// global project — a GSA's own project and the GKE workload's project are
// legitimately different in cross-project Workload Identity setups, and the
// GSA's owning project must never be used to validate the caller.
const (
	resolvedAWSOIDCProviderARNPrefix = "aws_eks_oidc_provider_arn:"
	resolvedAWSPodIdentityRolePrefix = "aws_pod_identity_role:"
	resolvedGCPProjectNumberPrefix   = "gcp_project_number:"
	resolvedGCPProjectIDLegacy       = "project_id"
	resolvedGCPProjectNumberLegacy   = "project_number"

	awsPodIdentityServicePrincipal = "Service:pods.eks.amazonaws.com"
)

func assessAWSTrustMember(g Grant, member string, e Evidence, known map[string][]Workload, flag func(Grant, string, string)) {
	switch {
	case member == "*" || strings.HasPrefix(member, "AWS:"):
		flag(g, member, "is a direct account/user/role delegation (or wildcard), not a reviewed Kubernetes consumer")
	case member == awsPodIdentityServicePrincipal:
		assessAWSPodIdentityTrust(g, e, flag)
	case strings.HasPrefix(member, "Service:"):
		flag(g, member, "trusts an AWS service principal outside the reviewed Kubernetes consumer inventory")
	case strings.HasPrefix(member, "Federated:"):
		providerARN := strings.TrimPrefix(member, "Federated:")
		subjects, exact := awsFederatedSubjects(g.Conditions)
		if !exact {
			flag(g, member, "has no exact subject (sub) condition restricting which identities may assume it")
			return
		}
		for _, s := range subjects {
			candidates, found := known[s]
			if !found {
				flag(g, member, fmt.Sprintf("restricts to subject %q, which does not match any known reviewed consumer", s))
				continue
			}
			matched := false
			for _, w := range candidates {
				if expected := e.ResolvedIdentifiers[resolvedAWSOIDCProviderARNPrefix+w.Cluster]; expected != "" && expected == providerARN {
					matched = true
					break
				}
			}
			if !matched {
				flag(g, member, fmt.Sprintf("restricts to subject %q, but no matching consumer's cluster OIDC provider is confirmed as %q", s, providerARN))
			}
		}
	default:
		flag(g, member, "has an unrecognized principal form and cannot be reconciled against known consumers")
	}
}

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

// awsFederatedPositiveLinkSubjects extracts the positive-link subject set
// from a Federated trust grant's Conditions, per the binding-semantic
// contract's stricter requirement than awsFederatedSubjects (used by the
// conservative excess gate): the condition set must consist of exactly a
// StringEquals "...:sub" restriction and, optionally, a StringEquals
// "...:aud" restriction whose only value is "sts.amazonaws.com". Any other
// condition key, a non-StringEquals operator, or an "...:aud" restriction
// that permits anything besides the default STS audience leaves the
// binding's actual scope unconfirmed, so it must never positively link a
// consumer.
func awsFederatedPositiveLinkSubjects(conditions []Condition) ([]string, bool) {
	var subjects []string
	sawSub := false
	for _, c := range conditions {
		key := strings.ToLower(c.Key)
		switch {
		case strings.HasSuffix(key, ":sub"):
			if c.Operator != "StringEquals" {
				return nil, false
			}
			sawSub = true
			subjects = append(subjects, c.Values...)
		case strings.HasSuffix(key, ":aud"):
			if c.Operator != "StringEquals" || len(c.Values) != 1 || c.Values[0] != "sts.amazonaws.com" {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	if !sawSub {
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

// awsPodIdentityPositiveLinkConditionsIncludeConsumer reports whether a Pod
// Identity trust grant's Conditions satisfy the positive-link contract for
// consumer (cluster, namespace, serviceAccount): no conditions at all (the
// grant is unconditional, so association evidence alone decides), or ONLY
// StringEquals session-tag conditions (eks-cluster-name/-arn,
// kubernetes-namespace, kubernetes-service-account) whose values include
// this consumer. Unlike awsPodIdentitySessionTagRestriction (the stricter
// excess/trust gate, which requires ALL three keys present to accept any
// restriction), positive linkage only needs each key that IS present to
// include this consumer; a key the grant never restricts imposes no
// constraint. Any other condition key, or a non-StringEquals operator on
// one of these keys, leaves the grant's actual scope unconfirmed and must
// never positively link a consumer.
func awsPodIdentityPositiveLinkConditionsIncludeConsumer(conditions []Condition, cluster, namespace, serviceAccount string) bool {
	if len(conditions) == 0 {
		return true
	}
	var clusters, namespaces, serviceAccounts []string
	for _, c := range conditions {
		key := strings.ToLower(c.Key)
		switch key {
		case "aws:requesttag/eks-cluster-name", "aws:requesttag/eks-cluster-arn":
			if c.Operator != "StringEquals" {
				return false
			}
			clusters = append(clusters, c.Values...)
		case "aws:requesttag/kubernetes-namespace":
			if c.Operator != "StringEquals" {
				return false
			}
			namespaces = append(namespaces, c.Values...)
		case "aws:requesttag/kubernetes-service-account":
			if c.Operator != "StringEquals" {
				return false
			}
			serviceAccounts = append(serviceAccounts, c.Values...)
		default:
			return false
		}
	}
	if len(clusters) > 0 && !clusterValuesMatch(clusters, cluster) {
		return false
	}
	if len(namespaces) > 0 && !stringValueMatches(namespaces, namespace) {
		return false
	}
	if len(serviceAccounts) > 0 && !stringValueMatches(serviceAccounts, serviceAccount) {
		return false
	}
	return true
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

// assessAWSPodIdentityTrust implements the Pod Identity trust gate:
// "Service:pods.eks.amazonaws.com" trust is accepted only when its
// StringEquals session-tag conditions restrict assumption to a specific
// cluster/namespace/service-account, AND every reviewed consumer matching
// that restriction has EKS Pod Identity association evidence confirming it
// uses this exact role. Associations outside the scan can never be
// excluded, so an unrestricted or unconfirmed grant is always flagged.
func assessAWSPodIdentityTrust(g Grant, e Evidence, flag func(Grant, string, string)) {
	clusters, namespaces, serviceAccounts, ok := awsPodIdentitySessionTagRestriction(g.Conditions)
	if !ok {
		flag(g, awsPodIdentityServicePrincipal, "has no StringEquals session-tag conditions restricting cluster/namespace/service-account; associations outside the scan cannot be excluded")
		return
	}
	matched := false
	for _, c := range e.Consumers {
		if c.Cluster == "" || c.Namespace == "" || c.ServiceAccount == "" {
			continue
		}
		if !clusterValuesMatch(clusters, c.Cluster) || !stringValueMatches(namespaces, c.Namespace) || !stringValueMatches(serviceAccounts, c.ServiceAccount) {
			continue
		}
		matched = true
		subject := "k8s://" + c.Cluster + "/" + c.Namespace + "/sa/" + c.ServiceAccount
		if e.ResolvedIdentifiers[resolvedAWSPodIdentityRolePrefix+subject] != e.Principal.ID {
			flag(g, awsPodIdentityServicePrincipal, fmt.Sprintf("restricts to cluster %q namespace %q service account %q, but no EKS Pod Identity association evidence confirms consumer %q uses this role", c.Cluster, c.Namespace, c.ServiceAccount, c.ID))
		}
	}
	if !matched {
		flag(g, awsPodIdentityServicePrincipal, "restricts assumption to a cluster/namespace/service-account combination that does not match any reviewed consumer")
	}
}

func assessGCPTrustMember(g Grant, member string, known map[string][]Workload, resolved map[string]string, flag func(Grant, string, string)) {
	switch {
	case strings.HasPrefix(member, "principal://"):
		namespace, sa, poolProject, ok := parseGCPPrincipalSubject(member)
		if !ok {
			flag(g, member, "is not a recognized Workload Identity Federation principal and cannot be reconciled against known consumers")
			return
		}
		subject := namespace + "/" + sa
		candidates, found := known[subject]
		if !found {
			flag(g, member, fmt.Sprintf("binds Kubernetes service account %q, which does not match any known reviewed consumer", subject))
			return
		}
		number, numberOK := gcpPrincipalProjectNumber(member)
		matched := false
		for _, w := range candidates {
			if w.CloudProject == "" || poolProject != w.CloudProject {
				continue
			}
			expected, expectedOK := expectedGCPProjectNumber(resolved, w.CloudProject)
			if numberOK && expectedOK && expected == number {
				matched = true
				break
			}
		}
		if !matched {
			flag(g, member, fmt.Sprintf("binds Kubernetes service account %q, but no matching consumer's Workload Identity pool project %q / project number %q is confirmed", subject, poolProject, number))
		}
	case strings.HasPrefix(member, "serviceAccount:"):
		project, namespace, sa, ok := parseGCPBracketBinding(strings.TrimPrefix(member, "serviceAccount:"))
		if !ok {
			flag(g, member, "is not an exact Workload Identity binding ([namespace/ksa]) and cannot be reconciled against known consumers")
			return
		}
		subject := namespace + "/" + sa
		candidates, found := known[subject]
		if !found {
			flag(g, member, fmt.Sprintf("binds Kubernetes service account %q, which does not match any known reviewed consumer", subject))
			return
		}
		// The Workload Identity pool's hosting project must match the
		// consuming workload's own cloud project. A bound GSA living in a
		// different project (legitimate for cross-project GSA usage) is
		// fine; what must match is the *pool*, not the GSA's own project.
		matched := false
		for _, w := range candidates {
			if w.CloudProject != "" && project == w.CloudProject {
				matched = true
				break
			}
		}
		if !matched {
			flag(g, member, fmt.Sprintf("binds Kubernetes service account %q, but the Workload Identity pool project %q is not confirmed as any matching consumer's own cloud project", subject, project))
		}
	default:
		flag(g, member, "is not a Workload Identity service-account binding and cannot be reconciled against known consumers")
	}
}

// expectedGCPProjectNumber resolves the project number expected for a
// consumer's own cloud project. The per-project key is authoritative. The
// legacy unscoped project_number key is only usable once independently
// confirmed — via the equally unscoped resolved project_id — that it
// actually describes this specific consumer's project; the member string's
// own self-reported pool project is never sufficient grounds by itself to
// trust an unscoped number.
func expectedGCPProjectNumber(resolved map[string]string, project string) (string, bool) {
	if v, ok := resolved[resolvedGCPProjectNumberPrefix+project]; ok && v != "" {
		return v, true
	}
	if resolved[resolvedGCPProjectIDLegacy] != project {
		return "", false
	}
	if v, ok := resolved[resolvedGCPProjectNumberLegacy]; ok && v != "" {
		return v, true
	}
	return "", false
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

func gcpPrincipalProjectNumber(member string) (string, bool) {
	const marker = "/projects/"
	idx := strings.Index(member, marker)
	if idx < 0 {
		return "", false
	}
	rest := member[idx+len(marker):]
	end := strings.Index(rest, "/")
	if end <= 0 {
		return "", false
	}
	return rest[:end], true
}

// linkedConsumers returns the subset of Evidence.Consumers IDs that the
// OBSERVED (live) Trust surface positively links to this principal, per the
// consumer-linkage contract: AWS IRSA exact Federated subject + resolved
// provider ARN for that consumer's own cluster; AWS Pod Identity
// association evidence AND a Service:pods.eks.amazonaws.com Allow
// statement whose actions cover sts:AssumeRole and sts:TagSession (session-
// tag association evidence alone cannot mint credentials); GCP
// impersonation-capable (known role) bindings admitting the consumer's
// exact Workload Identity identity; and direct GCP Workload Identity
// Federation principals (this Evidence cohort's own Principal already IS
// the federated KSA identity — no separate GSA trust policy to reconcile)
// are inherently linked. Linkage is positive-only evidence:
// unresolved/ambiguous trust never links a consumer, but also never blocks
// excess — it only blocks sharing's Clear/Supported counts (see
// AssessSharing).
func linkedConsumers(e Evidence) map[string]bool {
	linked := map[string]bool{}
	known := trustKnownSubjects(e.Principal.Provider, e.Consumers)

	if e.Principal.Provider == GCP && e.Principal.Kind == "gcp_workload_identity_principal" {
		if namespace, sa, _, ok := parseGCPPrincipalSubject(e.Principal.ID); ok {
			for _, c := range e.Consumers {
				if c.Namespace == namespace && c.ServiceAccount == sa {
					linked[c.ID] = true
				}
			}
		}
	}

	for _, g := range e.Observed.Trust {
		if g.Effect != "Allow" {
			continue
		}
		if e.Principal.Provider == GCP && (!gcpGrantPositiveLinkCapable(g, e.Definitions) || !gcpBindingIsUnconditional(g)) {
			// Either the bound role is not KNOWN to be credential-minting
			// (an unresolved role never positively links, unlike the
			// conservative excess gate) or the binding is conditional on
			// anything other than a literal CEL "true" — both leave this
			// grant's actual effect on any specific consumer unconfirmed.
			continue
		}
		for _, member := range g.Members {
			switch e.Principal.Provider {
			case AWS:
				for _, id := range awsTrustMemberLinks(g, member, known, e) {
					linked[id] = true
				}
			case GCP:
				for _, id := range gcpTrustMemberLinks(member, known, e.ResolvedIdentifiers) {
					linked[id] = true
				}
			}
		}
	}
	return linked
}

// awsTrustMemberLinks returns the consumer IDs this AWS trust member
// positively links, independent of whether it would also fail the stricter
// unresolved_trust_consumer gate.
func awsTrustMemberLinks(g Grant, member string, known map[string][]Workload, e Evidence) []string {
	switch {
	case member == awsPodIdentityServicePrincipal:
		if matchActionAgainstGrant(AWS, g, "sts:AssumeRole") != matchYes || matchActionAgainstGrant(AWS, g, "sts:TagSession") != matchYes {
			// Positive linkage requires the statement's own Actions to
			// actually cover BOTH sts:AssumeRole and sts:TagSession --
			// Pod Identity mints credentials via AssumeRole and always
			// tags the session.
			return nil
		}
		var ids []string
		for _, c := range e.Consumers {
			if c.Cluster == "" || c.Namespace == "" || c.ServiceAccount == "" {
				continue
			}
			if !awsPodIdentityPositiveLinkConditionsIncludeConsumer(g.Conditions, c.Cluster, c.Namespace, c.ServiceAccount) {
				continue
			}
			subject := "k8s://" + c.Cluster + "/" + c.Namespace + "/sa/" + c.ServiceAccount
			if e.ResolvedIdentifiers[resolvedAWSPodIdentityRolePrefix+subject] == e.Principal.ID {
				ids = append(ids, c.ID)
			}
		}
		return ids
	case strings.HasPrefix(member, "Federated:"):
		if matchActionAgainstGrant(AWS, g, "sts:AssumeRoleWithWebIdentity") != matchYes {
			// Positive linkage requires the statement's own Actions to
			// actually cover AssumeRoleWithWebIdentity (e.g. a statement
			// permitting only sts:TagSession grants no assumption at all).
			return nil
		}
		providerARN := strings.TrimPrefix(member, "Federated:")
		subjects, exact := awsFederatedPositiveLinkSubjects(g.Conditions)
		if !exact {
			return nil
		}
		var ids []string
		for _, s := range subjects {
			for _, w := range known[s] {
				if expected := e.ResolvedIdentifiers[resolvedAWSOIDCProviderARNPrefix+w.Cluster]; expected != "" && expected == providerARN {
					ids = append(ids, w.ID)
				}
			}
		}
		return ids
	default:
		return nil
	}
}

// gcpTrustMemberLinks returns the consumer IDs this GCP trust member
// positively links.
func gcpTrustMemberLinks(member string, known map[string][]Workload, resolved map[string]string) []string {
	switch {
	case strings.HasPrefix(member, "principal://"):
		namespace, sa, poolProject, ok := parseGCPPrincipalSubject(member)
		if !ok {
			return nil
		}
		number, numberOK := gcpPrincipalProjectNumber(member)
		var ids []string
		for _, w := range known[namespace+"/"+sa] {
			if w.CloudProject == "" || poolProject != w.CloudProject {
				continue
			}
			expected, expectedOK := expectedGCPProjectNumber(resolved, w.CloudProject)
			if numberOK && expectedOK && expected == number {
				ids = append(ids, w.ID)
			}
		}
		return ids
	case strings.HasPrefix(member, "serviceAccount:"):
		project, namespace, sa, ok := parseGCPBracketBinding(strings.TrimPrefix(member, "serviceAccount:"))
		if !ok {
			return nil
		}
		var ids []string
		for _, w := range known[namespace+"/"+sa] {
			if w.CloudProject != "" && project == w.CloudProject {
				ids = append(ids, w.ID)
			}
		}
		return ids
	default:
		return nil
	}
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
// be demoted by a gap in a target it has no relationship to.
func cohortMayBeAffectedByTargetGap(cohort Evidence, target ScanTarget) bool {
	for _, consumer := range cohort.Consumers {
		switch target.Provider {
		case AWS:
			if consumer.Cluster == target.Cluster && consumer.CloudAccount == target.Account {
				return true
			}
		case GCP:
			if consumer.CloudProject == target.Project {
				return true
			}
		}
	}
	if isUnresolvedCloudPrincipal(cohort.Principal) {
		// An unrendered/unresolved KSA placeholder for THIS target's
		// cluster is itself a hidden subject the failed render could not
		// identify; a placeholder for any other cluster is untouched.
		return strings.HasPrefix(cohort.Principal.ID, "k8s://"+target.Cluster+"/")
	}
	if cohort.Principal.Provider != target.Provider {
		return false
	}
	if !cohort.Observed.Complete || len(cohort.Observed.Trust) == 0 {
		// Trust itself is unknown/incomplete: stay conservative rather than
		// silently excluding this target's hidden workloads.
		return true
	}
	switch target.Provider {
	case AWS:
		return awsObservedTrustMayAdmitCluster(cohort, target.Cluster)
	case GCP:
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
