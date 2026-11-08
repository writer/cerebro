package cloudidentitysource

import (
	"fmt"
	"strings"
	"time"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// gcpImpersonationPermissions are the GCP IAM permissions that let a
// principal act as (assume/impersonate) a service account. This mirrors the
// core's trust classification boundary (internal/cloudidentity/trust.go):
// iam.serviceAccounts.actAs is deliberately excluded, the same documented
// bounded limitation as AWS iam:PassRole not being treated as trust.
var gcpImpersonationPermissions = []string{
	"iam.serviceAccounts.getAccessToken",
	"iam.serviceAccounts.getOpenIdToken",
	"iam.serviceAccounts.signBlob",
	"iam.serviceAccounts.signJwt",
	"iam.serviceAccounts.implicitDelegation",
}

// gcpSearchQuery builds a conservative Cloud Asset search-query substring
// filter. It only narrows the server-side result set as an optimization;
// gcpMatchingMembers performs the authoritative exact-membership check
// afterwards, so an imprecise (over-broad) query can never cause an
// unauthorized grant to be reported, only extra API work.
func gcpSearchQuery(substring string) string {
	return fmt.Sprintf("policy:%q", substring)
}

// gcpGrantSearchQuery narrows the GSA grant search to bindings that mention
// either the exact service-account member or one of its resource-hierarchy
// principalSet forms (https://docs.cloud.google.com/iam/docs/principal-identifiers),
// OR-combined into a single bounded search instead of one call per
// candidate. Like gcpSearchQuery this is only an optimization: the
// authoritative membership check still happens in gcpMatchingMembers.
func gcpGrantSearchQuery(member string, hierarchyCandidates []gcpApplicablePrincipal) string {
	terms := make([]string, 0, 1+len(hierarchyCandidates))
	terms = append(terms, fmt.Sprintf("policy:%q", member))
	for _, candidate := range hierarchyCandidates {
		terms = append(terms, fmt.Sprintf("policy:%q", candidate.Member))
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return "(" + strings.Join(terms, " OR ") + ")"
}

// gcpAncestorResourceQuery narrows the ancestor inherited-trust search to
// every binding on exactly one ancestor resource, with NO role/permission
// filter term. Cloud Asset's documented contract for a
// policy.role.permissions:<perm> query term is explicit: "if callers don't
// have iam.roles.get access to a role's included permissions, policy
// bindings that specify this role will be dropped from the search results"
// (https://docs.cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllIamPolicies).
// A server-side permission filter would therefore silently omit exactly the
// unreadable-role ancestor bindings this reader must instead surface as a
// Trust gap, so every binding on the ancestor is fetched unfiltered and
// classified locally by effectiveAncestryTrust, resolving each binding's
// role live via IAM roles.get instead of trusting Cloud Asset's own
// permission-aware filtering.
func gcpAncestorResourceQuery(resource string) string {
	return fmt.Sprintf("resource=%s", resource)
}

// gcpAncestorBindingCapable applies the shared possibly-capable trust gate
// (cross-slice semantic: a GCP role that cannot be resolved is treated as
// capable; a role that resolved successfully is capable iff its effective
// permissions contain at least one impersonation permission) to one
// ancestor binding's locally resolved role. A role resolution failure
// (permission denied, lookup error) keeps the binding in Trust
// conservatively; only a role that resolved successfully AND lacks every
// impersonation permission is classified incapable and dropped.
// gcpRoleEffectivePermissions (gcp_definitions.go) already folds a
// resolved-but-deleted-or-disabled role down to zero permissions, so such a
// role correctly classifies as incapable here too, never as "unknown".
func gcpAncestorBindingCapable(resolution gcpRoleResolution) bool {
	if !resolution.Known {
		return true
	}
	for _, permission := range gcpRoleEffectivePermissions(resolution.Role) {
		for _, candidate := range gcpImpersonationPermissions {
			if permission == candidate {
				return true
			}
		}
	}
	return false
}

// gcpGrantFromBinding converts one matched IAM binding into a core Grant,
// scoped to exactly the principal/principalSet members that apply to the
// evaluated identity (never the unrelated co-members of a shared binding).
// The returned error is non-nil only when the binding's content could not
// be digested; the Grant itself is always returned with its real
// permission content (members/role/resource), since a digest failure
// never means the grant evidence is invalid — only that this one
// Reference's content-addressing proof is unavailable, left empty rather
// than fabricated, for the caller to record as an explicit gap.
func gcpGrantFromBinding(result gcpIamPolicySearchResult, bindingIndex int, binding gcpBinding, matchedMembers []string, now time.Time, apiReference string) (ci.Grant, error) {
	digest, digestErr := digestStruct(struct {
		Resource string
		Role     string
		Members  []string
		Cond     *gcpCondition
	}{result.Resource, binding.Role, binding.Members, binding.Condition})
	grant := ci.Grant{
		ID:      fmt.Sprintf("%s#%s#%d", result.Resource, binding.Role, bindingIndex),
		Effect:  "Allow",
		Role:    binding.Role,
		Members: matchedMembers,
		References: []ci.Reference{{
			API:        apiReference,
			Scope:      result.Resource,
			ObservedAt: now,
			Digest:     digest,
		}},
	}
	if result.Resource != "" {
		grant.Resources = []string{result.Resource}
	}
	if binding.Condition != nil && binding.Condition.Expression != "" {
		grant.Conditions = []ci.Condition{{Expression: binding.Condition.Expression}}
	}
	return grant, digestErr
}

// gcpClassifyBindings converts every matched org-wide-search binding into a
// Grant: a binding where the evaluated principal is a member is always
// something that principal is permitted to do (even an impersonation-type
// role like roles/iam.serviceAccountTokenCreator granted on ANOTHER resource
// is an outbound permission this principal holds), so it must never be
// hidden away from Grants. Only a resource's own IAM policy (who may act as
// THAT resource) is Trust; see gcpTrustFromServiceAccountPolicy.
func gcpClassifyBindings(results []gcpIamPolicySearchResult, matcher func(members []string) ([]string, string), now time.Time, apiReference string) ([]ci.Grant, []ci.Gap) {
	var grants []ci.Grant
	var gaps []ci.Gap
	for _, result := range results {
		if result.Policy == nil {
			continue
		}
		for index, binding := range result.Policy.Bindings {
			matched, _ := matcher(binding.Members)
			if len(matched) == 0 {
				continue
			}
			grant, err := gcpGrantFromBinding(result, index, binding, matched, now, apiReference)
			if err != nil {
				gaps = append(gaps, ci.Gap{Code: "gcp_grant_digest_unavailable", Scope: result.Resource + "#" + binding.Role, Message: "grant evidence could not be digested: " + err.Error()})
			}
			grants = append(grants, grant)
		}
	}
	return grants, gaps
}

// gcpTrustFromServiceAccountPolicy converts a GSA resource's own IAM policy
// (who may impersonate/use/administer this identity) entirely into Trust:
// it describes control of the identity, never what the identity itself can
// do to other resources.
func gcpTrustFromServiceAccountPolicy(resource string, policy gcpPolicy, now time.Time) ([]ci.Grant, []ci.Gap) {
	trust := make([]ci.Grant, 0, len(policy.Bindings))
	var gaps []ci.Gap
	for index, binding := range policy.Bindings {
		grant, err := gcpGrantFromBinding(gcpIamPolicySearchResult{Resource: resource}, index, binding, binding.Members, now, gcpGetServiceAccountIAMReference)
		if err != nil {
			gaps = append(gaps, ci.Gap{Code: "gcp_grant_digest_unavailable", Scope: resource + "#" + binding.Role, Message: "trust evidence could not be digested: " + err.Error()})
		}
		trust = append(trust, grant)
	}
	return trust, gaps
}
