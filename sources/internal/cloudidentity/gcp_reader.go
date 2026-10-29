package cloudidentitysource

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	ci "github.com/writer/cerebro/internal/cloudidentity"
)

// GCPOptions configures the GCP cloud-identity reader. The caller supplies an
// already-scoped oauth2.TokenSource (built however the deployment's generic
// GCP auth works, e.g. via NewGCPCredentialSource's AWS->GCP Workload
// Identity Federation exchange, or application default credentials); this
// reader performs no credential resolution, environment reads, or secret
// access of its own, and never logs or returns the bearer token.
type GCPOptions struct {
	// TokenSource is required. It must be scoped to read-only IAM / Cloud
	// Asset / Resource Manager access; this reader issues no write calls.
	TokenSource oauth2.TokenSource
	// HTTPClient is optional. When set, its transport is reused (hardened and
	// wrapped with the token source) instead of building a fresh client.
	HTTPClient *http.Client
	// Organization is the numeric GCP organization id (e.g. "123456789012").
	// It is required: org-wide searchAllIamPolicies is the only way to
	// observe bindings granted outside the principal's own project/folder,
	// and this reader never infers an organization scope on its own.
	Organization string
	// QuotaProject sets X-Goog-User-Project on every request.
	QuotaProject string
	// CloudAssetBaseURL, IAMBaseURL, ResourceManagerBaseURL override the real
	// googleapis.com hosts; intended for fixture-backed tests only.
	CloudAssetBaseURL      string
	IAMBaseURL             string
	ResourceManagerBaseURL string
	RequestTimeout         time.Duration
	PageSize               int
	MaxPages               int
	// Now overrides the observation clock; defaults to time.Now.
	Now func() time.Time
}

type gcpReader struct {
	client *gcpClient
	org    string
	now    func() time.Time

	// ancestryMu/ancestryCache memoize each GSA project's resolved Resource
	// Manager ancestry plus the inherited impersonation Trust collected from
	// it, keyed by project id, for the lifetime of this reader: many GSAs
	// commonly share one project, and both the getAncestry call and the
	// per-ancestor searchAllIamPolicies calls are otherwise redundant work.
	ancestryMu    sync.Mutex
	ancestryCache map[string]gcpAncestryTrust

	// roleMu/roleCache memoize each IAM role's live roles.get resolution,
	// keyed by role resource name, for the lifetime of this reader: the
	// same role (e.g. a broadly granted custom role) is commonly bound on
	// many ancestor resources across many principals, and one roles.get
	// result is authoritative for all of them this run.
	roleMu    sync.Mutex
	roleCache map[string]gcpRoleResolution
}

// NewGCPReader builds a ci.CloudReader backed by live GCP IAM, Cloud Asset,
// and Resource Manager REST APIs. It observes ONLY requested Kubernetes-used
// GSA ("gcp_service_account") or direct KSA ("gcp_kubernetes_service_account")
// principals; any other principal kind produces a scoped gap, never a guess.
func NewGCPReader(options GCPOptions) (ci.CloudReader, error) {
	if options.TokenSource == nil {
		return nil, fmt.Errorf("cloudidentitysource: GCP reader requires a TokenSource")
	}
	org := gcpOrganizationScope(options.Organization)
	if org == "" {
		return nil, fmt.Errorf("cloudidentitysource: GCP reader requires an organization scope")
	}
	client, err := newGCPClient(options)
	if err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &gcpReader{client: client, org: org, now: now, ancestryCache: map[string]gcpAncestryTrust{}, roleCache: map[string]gcpRoleResolution{}}, nil
}

// gcpRoleResolution is one role's locally resolved IAM permissions (or
// resolution failure), cached per role name for the reader's lifetime (one
// run). Known is false when the live roles.get lookup itself failed or was
// denied, never when the role simply has zero effective permissions (a
// resolved-deleted-or-disabled role is Known=true with Role.IncludedPermissions
// still populated; gcpRoleEffectivePermissions folds that down to empty).
type gcpRoleResolution struct {
	Role  gcpRole
	Gaps  []gcpGap
	Known bool
}

// resolveRole resolves one IAM role's permissions live via roles.get,
// memoized per role name for the reader's lifetime. A failed or denied
// lookup is itself memoized (never silently retried into a different
// outcome mid-run) and returned with Known=false so a caller can both
// classify a binding to this role conservatively (unresolvable role =>
// possibly capable) and record the lookup failure as an explicit gap.
func (r *gcpReader) resolveRole(ctx context.Context, name string) gcpRoleResolution {
	r.roleMu.Lock()
	if cached, ok := r.roleCache[name]; ok {
		r.roleMu.Unlock()
		return cached
	}
	r.roleMu.Unlock()

	role, gaps := r.client.getRole(ctx, name)
	resolution := gcpRoleResolution{Role: role, Gaps: gaps, Known: len(gaps) == 0}

	r.roleMu.Lock()
	r.roleCache[name] = resolution
	r.roleMu.Unlock()
	return resolution
}

// gcpOrganizationIDPattern restricts the organization option to digits only,
// so it can never inject an unexpected path or query segment into a
// searchAllIamPolicies scope URL.
var gcpOrganizationIDPattern = regexp.MustCompile(`^[0-9]+$`)

func gcpOrganizationScope(raw string) string {
	trimmed := strings.TrimPrefix(strings.TrimSpace(raw), "organizations/")
	if !gcpOrganizationIDPattern.MatchString(trimmed) {
		return ""
	}
	return "organizations/" + trimmed
}

// Observe implements ci.CloudReader.
func (r *gcpReader) Observe(ctx context.Context, req ci.CloudRequest) (ci.Observation, error) {
	now := r.now().UTC()
	switch req.Principal.Kind {
	case gcpKindServiceAccount:
		return r.observeServiceAccount(ctx, req.Principal, req.Consumers, now), nil
	case gcpKindKubernetesServiceAccount:
		return r.observeKubernetesServiceAccount(ctx, req.Principal, req.Consumers, now), nil
	default:
		return ci.Observation{
			Definitions: ci.Definitions{Complete: true},
			Gaps: []ci.Gap{{
				Code:    "gcp_principal_kind_unsupported",
				Scope:   req.Principal.ID,
				Message: fmt.Sprintf("GCP reader only observes %q and %q principals, got %q", gcpKindServiceAccount, gcpKindKubernetesServiceAccount, req.Principal.Kind),
			}},
		}, nil
	}
}

func (r *gcpReader) observeServiceAccount(ctx context.Context, principal ci.Principal, consumers []ci.Workload, now time.Time) ci.Observation {
	email := strings.TrimSpace(principal.ID)
	emailProject, ok := gcpProjectFromServiceAccountEmail(email)
	if !ok {
		return ci.Observation{
			Definitions: ci.Definitions{Complete: true},
			Gaps: []ci.Gap{{
				Code:    "gcp_service_account_email_invalid",
				Scope:   principal.ID,
				Message: "principal id is not a *.iam.gserviceaccount.com service account email",
			}},
		}
	}
	var gaps []ci.Gap
	if declared := strings.TrimSpace(principal.Project); declared != "" && declared != emailProject {
		gaps = append(gaps, ci.Gap{Code: "gcp_project_mismatch", Scope: email, Message: fmt.Sprintf("principal project %q does not match the service account email's project %q; using the email's project", declared, emailProject)})
	}
	resolved := map[string]string{"project_id": emailProject, "service_account_email": email}
	complete := true
	var ownNumber string

	project, projectGaps := r.client.getProject(ctx, emailProject)
	if len(projectGaps) > 0 {
		gaps = append(gaps, gcpGapsToCore(emailProject, projectGaps)...)
		complete = false
	} else if number := gcpProjectNumber(project.Name); number != "" {
		ownNumber = number
		resolved["project_number"] = number
	}

	account, accountGaps := r.client.getServiceAccount(ctx, emailProject, email)
	if len(accountGaps) > 0 {
		gaps = append(gaps, gcpGapsToCore(email, accountGaps)...)
		complete = false
	} else if account.Disabled {
		gaps = append(gaps, ci.Gap{Code: "gcp_service_account_disabled", Scope: email, Message: "service account is disabled"})
	}

	policy, policyGaps := r.client.getServiceAccountIAMPolicy(ctx, emailProject, email)
	var trust []ci.Grant
	if len(policyGaps) > 0 {
		gaps = append(gaps, gcpGapsToCore(email, policyGaps)...)
		complete = false
	} else {
		trust = gcpTrustFromServiceAccountPolicy(fmt.Sprintf("//iam.googleapis.com/projects/%s/serviceAccounts/%s", emailProject, email), policy, now)
	}

	// A service account's direct resource policy is not its complete trust
	// surface: Google IAM also honors impersonation-capable roles (Token
	// Creator, Workload Identity User, custom roles with the same
	// permissions) granted on its project, enclosing folders, or
	// organization. Resolve that ancestry and fold in every inherited
	// impersonation-capable binding found on it; any failure anywhere in
	// this resolution marks the whole policy incomplete rather than
	// silently treating an uninherited-looking trust surface as final.
	ancestry := r.effectiveAncestryTrust(ctx, emailProject, now)
	trust = append(trust, ancestry.Trust...)
	gaps = append(gaps, ancestry.Gaps...)
	complete = complete && ancestry.Complete

	// A GSA commonly lives in one project (e.g. a shared IAM project) while
	// the GKE cluster that impersonates it via Workload Identity Federation
	// lives in another; the trust binding's principal pool belongs to the
	// CALLER's project, never the GSA's own project. Resolve every unique
	// consumer-reported caller project number as separate, explicitly-keyed
	// trust evidence so a validator can match pools without guessing from
	// the SA email. A resolution failure is scoped to that caller project
	// and marks the whole cohort incomplete rather than silently omitted.
	callerGaps := r.resolveCallerProjectNumbers(ctx, consumers, emailProject, ownNumber, resolved)
	if len(callerGaps) > 0 {
		gaps = append(gaps, callerGaps...)
		complete = false
	}

	// GCP IAM also grants to every service account under a project/folder/
	// organization via principalSet://cloudresourcemanager.googleapis.com/
	// <ancestor>/type/ServiceAccount, which never carries this GSA's email
	// and so is invisible to a search scoped only to the exact member
	// string. OR the hierarchy candidates into the same bounded search.
	member := gcpServiceAccountMember(email)
	hierarchyCandidates := gcpHierarchyServiceAccountPrincipalSets(ancestry.Ancestors)
	results, searchGaps, searchComplete := r.client.searchAllIamPolicies(ctx, r.org, gcpGrantSearchQuery(member, hierarchyCandidates))
	gaps = append(gaps, gcpGapsToCore(r.org, searchGaps)...)
	complete = complete && searchComplete
	candidates := append([]gcpApplicablePrincipal{{Member: member, Specificity: "exact"}}, hierarchyCandidates...)
	matcher := func(members []string) ([]string, string) {
		return gcpMatchingMembers(members, candidates)
	}
	grants := gcpClassifyBindings(results, matcher, now, gcpSearchAllIAMPoliciesReference)

	return ci.Observation{
		Policy: ci.PolicyState{
			Grants:     grants,
			Trust:      trust,
			Complete:   complete,
			ObservedAt: now,
			References: []ci.Reference{{API: gcpSearchAllIAMPoliciesReference, Scope: r.org, ObservedAt: now, Digest: ci.Digest(results)}},
			Gaps:       gaps,
		},
		Definitions:         ci.Definitions{Complete: true},
		ResolvedIdentifiers: resolved,
		Gaps:                gaps,
	}
}

// resolveCallerProjectNumbers resolves the project number for every unique,
// syntactically concrete Workload.CloudProject among consumers, keyed as
// "gcp_project_number:<project>" so a validator can look one up by the exact
// caller project it already knows, independent of the GSA's own project.
// It never infers a caller project from the SA email or guesses an unknown
// one; an unresolvable project is only a scoped gap.
func (r *gcpReader) resolveCallerProjectNumbers(ctx context.Context, consumers []ci.Workload, ownProject string, ownNumber string, resolved map[string]string) []ci.Gap {
	var gaps []ci.Gap
	seen := map[string]bool{}
	for _, consumer := range consumers {
		project := strings.TrimSpace(consumer.CloudProject)
		if project == "" || seen[project] {
			continue
		}
		seen[project] = true
		if project == ownProject {
			if ownNumber != "" {
				resolved["gcp_project_number:"+project] = ownNumber
			}
			continue
		}
		if !gcpResolvableProjectID(project) {
			gaps = append(gaps, ci.Gap{Code: "gcp_caller_project_unresolved", Scope: project, Message: "consumer workload reported an unresolvable GCP project; refusing to infer it"})
			continue
		}
		callerProject, callerGaps := r.client.getProject(ctx, project)
		if len(callerGaps) > 0 {
			gaps = append(gaps, gcpGapsToCore(project, callerGaps)...)
			continue
		}
		if number := gcpProjectNumber(callerProject.Name); number != "" {
			resolved["gcp_project_number:"+project] = number
		}
	}
	return gaps
}

// gcpAncestryTrust is one GSA project's resolved Resource Manager ancestry
// plus the inherited impersonation Trust collected from it, cached per
// project for the reader's lifetime.
type gcpAncestryTrust struct {
	Ancestors []gcpAncestor
	Trust     []ci.Grant
	Complete  bool
	Gaps      []ci.Gap
}

// effectiveAncestryTrust resolves a GSA project's ancestry (the project
// itself, its enclosing folders, and its organization) and, for each
// ancestor, discovers every IAM binding set on that exact ancestor
// resource (gcpAncestorResourceQuery, with NO role/permission search
// filter: see its doc comment for why a permission-filtered query would
// silently omit bindings whose role the caller cannot read), then resolves
// each binding's role locally via resolveRole to decide whether Google IAM
// would honor it as inherited impersonation trust over every service
// account beneath that ancestor, not just bindings on the service account
// resource itself. A binding whose role resolves successfully AND lacks
// every impersonation permission is dropped; a binding whose role is
// impersonation-capable, OR whose role could not be resolved (permission
// denied, lookup failure), stays in Trust conservatively, with an explicit
// gap recorded for every unresolved role so the caller can see exactly
// what evidence is missing (gcpAncestorBindingCapable). Ancestor
// resolution or search failure marks the whole result incomplete with a
// scoped gap, never a silently-omitted inherited trust path; an individual
// unresolved role lookup does not, since the binding is conservatively
// retained rather than lost. Results are cached per project.
func (r *gcpReader) effectiveAncestryTrust(ctx context.Context, projectID string, now time.Time) gcpAncestryTrust {
	r.ancestryMu.Lock()
	if cached, ok := r.ancestryCache[projectID]; ok {
		r.ancestryMu.Unlock()
		return cached
	}
	r.ancestryMu.Unlock()

	complete := true
	var gaps []ci.Gap
	var trust []ci.Grant

	ancestors, ancestryGaps := r.client.getProjectAncestry(ctx, projectID)
	if len(ancestryGaps) > 0 {
		gaps = append(gaps, gcpGapsToCore(projectID, ancestryGaps)...)
		complete = false
	} else {
		for _, ancestor := range ancestors {
			resourceName := gcpAncestorResourceName(ancestor)
			if resourceName == "" {
				gaps = append(gaps, ci.Gap{Code: "gcp_ancestor_type_unrecognized", Scope: projectID, Message: fmt.Sprintf("resource manager returned an unrecognized ancestor type %q", ancestor.ResourceID.Type)})
				complete = false
				continue
			}
			resource := "//cloudresourcemanager.googleapis.com/" + resourceName
			results, searchGaps, searchComplete := r.client.searchAllIamPolicies(ctx, r.org, gcpAncestorResourceQuery(resource))
			gaps = append(gaps, gcpGapsToCore(resource, searchGaps)...)
			if !searchComplete {
				complete = false
			}
			for _, result := range results {
				if result.Policy == nil || result.Resource != resource {
					continue
				}
				for index, binding := range result.Policy.Bindings {
					resolution := r.resolveRole(ctx, binding.Role)
					if !resolution.Known {
						gaps = append(gaps, gcpGapsToCore(resource+"#"+binding.Role, resolution.Gaps)...)
					}
					if !gcpAncestorBindingCapable(resolution) {
						continue
					}
					trust = append(trust, gcpGrantFromBinding(result, index, binding, binding.Members, now, gcpSearchAllIAMPoliciesReference))
				}
			}
		}
	}

	cached := gcpAncestryTrust{Ancestors: ancestors, Trust: trust, Complete: complete, Gaps: gaps}
	r.ancestryMu.Lock()
	r.ancestryCache[projectID] = cached
	r.ancestryMu.Unlock()
	return cached
}

// observeKubernetesServiceAccount accepts either the canonical
// "principal://iam.googleapis.com/projects/NUMBER/locations/global/
// workloadIdentityPools/PROJECT.svc.id.goog/subject/ns/NS/sa/SA" cloud
// identity directly (no extra Resource Manager call needed: the project
// number/id are embedded in the URI, avoiding redundant resolution when a
// cohort was already regrouped onto its canonical identifier upstream), or
// the cluster-local "k8s://<cluster>/<namespace>/sa/<name>" shape, which
// this reader resolves into that same canonical URI live and reports back
// via ResolvedIdentifiers so the caller can union same-pool, same-ns/sa
// identities across clusters ("identity sameness") into one cloud principal
// before assessment, the same way it would be done for any other alias.
func (r *gcpReader) observeKubernetesServiceAccount(ctx context.Context, principal ci.Principal, consumers []ci.Workload, now time.Time) ci.Observation {
	if projectNumber, projectID, namespace, serviceAccount, ok := gcpParseCanonicalKSAPrincipal(principal.ID); ok {
		resolved := map[string]string{
			"project_id":                 projectID,
			"project_number":             projectNumber,
			"workload_identity_pool":     gcpWorkloadIdentityPool(projectID),
			"kubernetes_namespace":       namespace,
			"kubernetes_service_account": serviceAccount,
		}
		// The canonical principal:// id deliberately drops which cluster(s)
		// alias to it (see observeKSAMembers' project-number key comment
		// above), so no cluster-scoped candidate can ever be built or
		// verified here; a cluster-scoped binding found in this pool is
		// always treated as an unresolved, possibly-applicable surface.
		return r.observeKSAMembers(ctx, now, projectNumber, projectID, namespace, serviceAccount, "", "", resolved)
	}

	identity, ok := gcpParseKSAIdentity(principal.ID)
	if !ok {
		return ci.Observation{
			Definitions: ci.Definitions{Complete: true},
			Gaps: []ci.Gap{{
				Code:    "gcp_kubernetes_service_account_id_invalid",
				Scope:   principal.ID,
				Message: `principal id must be "k8s://<cluster>/<namespace>/sa/<name>" or the canonical "principal://iam.googleapis.com/..." form`,
			}},
		}
	}
	projectID := strings.TrimSpace(principal.Project)
	if !gcpResolvableProjectID(projectID) {
		return ci.Observation{
			Definitions: ci.Definitions{Complete: true},
			Gaps: []ci.Gap{{
				Code:    "gcp_project_unresolved",
				Scope:   principal.ID,
				Message: "no concrete GCP project is known for this Kubernetes service account; refusing to infer an organization-wide scope",
			}},
		}
	}

	// kubernetes_cluster is deliberately omitted here: it differs per
	// original cluster-local id while project/pool/namespace/sa are shared
	// once multiple clusters alias to the same canonical principal, and the
	// Workload already records cluster independently.
	resolved := map[string]string{
		"project_id":                 projectID,
		"workload_identity_pool":     gcpWorkloadIdentityPool(projectID),
		"kubernetes_namespace":       identity.Namespace,
		"kubernetes_service_account": identity.ServiceAccount,
	}

	project, projectGaps := r.client.getProject(ctx, projectID)
	if len(projectGaps) > 0 {
		return ci.Observation{
			Definitions:         ci.Definitions{Complete: true},
			ResolvedIdentifiers: resolved,
			Gaps:                gcpGapsToCore(projectID, projectGaps),
		}
	}
	projectNumber := gcpProjectNumber(project.Name)
	if projectNumber == "" {
		return ci.Observation{
			Definitions:         ci.Definitions{Complete: true},
			ResolvedIdentifiers: resolved,
			Gaps:                []ci.Gap{{Code: "gcp_project_number_unresolved", Scope: projectID, Message: "resource manager did not return a numeric project name"}},
		}
	}
	resolved["project_number"] = projectNumber
	resolved["gcp_ksa_principal:"+principal.ID] = gcpCanonicalKSAURI(projectNumber, projectID, identity.Namespace, identity.ServiceAccount)

	region := gcpConsumerRegionForCluster(consumers, identity.Cluster)
	return r.observeKSAMembers(ctx, now, projectNumber, projectID, identity.Namespace, identity.ServiceAccount, identity.Cluster, region, resolved)
}

// gcpConsumerRegionForCluster returns the cluster location reported by the
// consumer Workload whose Cluster matches cluster, the location a GKE
// cluster-scoped principalSet candidate must be built against. It never
// falls back to an unrelated consumer's region.
func gcpConsumerRegionForCluster(consumers []ci.Workload, cluster string) string {
	for _, workload := range consumers {
		if workload.Cluster == cluster {
			if region := strings.TrimSpace(workload.Region); region != "" {
				return region
			}
		}
	}
	return ""
}

// observeKSAMembers runs the org-wide search and exact/principalSet
// applicability matching shared by both canonical-URI and cluster-local KSA
// entry points; it never calls Resource Manager, since both callers already
// resolved projectNumber before reaching here. cluster/region build the
// cluster-scoped candidate when both are known (cluster-local entry only,
// with a resolved consumer region); when either is empty no cluster-scoped
// candidate can be verified, and any cluster-scoped binding found in this
// pool is treated as an unresolved, possibly-applicable surface instead of
// being silently ignored.
func (r *gcpReader) observeKSAMembers(ctx context.Context, now time.Time, projectNumber string, projectID string, namespace string, serviceAccount string, cluster string, region string, resolved map[string]string) ci.Observation {
	// Keyed identically to the GSA cross-project case so a validator can
	// look up "gcp_project_number:<project>" the same way regardless of
	// principal kind, even though for a direct KSA the caller project IS
	// the principal's own project (no separate owning-SA project exists).
	resolved["gcp_project_number:"+projectID] = projectNumber
	candidates := gcpKSAApplicableMembers(projectNumber, projectID, namespace, serviceAccount)
	clusterKnown := cluster != "" && region != ""
	if clusterKnown {
		candidates = append(candidates, gcpApplicablePrincipal{Member: gcpKSAClusterScopedMember(projectNumber, projectID, region, cluster), Specificity: "cluster"})
	}
	pool := gcpWorkloadIdentityPool(projectID)
	results, searchGaps, searchComplete := r.client.searchAllIamPolicies(ctx, r.org, gcpSearchQuery(pool))
	gaps := gcpGapsToCore(r.org, searchGaps)
	matcher := func(members []string) ([]string, string) {
		return gcpMatchingMembers(members, candidates)
	}
	grants := gcpClassifyBindings(results, matcher, now, gcpSearchAllIAMPoliciesReference)

	// A binding member that references this pool but matched none of the
	// built candidates could still be a documented form this reader simply
	// could not resolve/verify (an unavailable cluster-scoped set, or an
	// unrecognized shape); reporting the policy complete would silently
	// drop a grant that may apply. Members unambiguously addressing a
	// DIFFERENT namespace/service-account/cluster are not flagged.
	known := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		known[candidate.Member] = true
	}
	seenUnresolved := map[string]bool{}
	complete := searchComplete
	for _, result := range results {
		if result.Policy == nil {
			continue
		}
		for _, binding := range result.Policy.Bindings {
			for _, member := range binding.Members {
				if known[member] || seenUnresolved[member] || !strings.Contains(member, pool) {
					continue
				}
				if !gcpKSAMemberCouldApply(member, namespace, serviceAccount, clusterKnown, cluster) {
					continue
				}
				seenUnresolved[member] = true
				gaps = append(gaps, ci.Gap{Code: "gcp_ksa_principal_form_unresolved", Scope: member, Message: "binding member references this workload identity pool in a form this reader could not verify applicability for; treating as incomplete rather than silently dropping it"})
				complete = false
			}
		}
	}

	return ci.Observation{
		Policy: ci.PolicyState{
			Grants:     grants,
			Complete:   complete,
			ObservedAt: now,
			References: []ci.Reference{{API: gcpSearchAllIAMPoliciesReference, Scope: r.org, ObservedAt: now, Digest: ci.Digest(results)}},
			Gaps:       gaps,
		},
		Definitions:         ci.Definitions{Complete: true},
		ResolvedIdentifiers: resolved,
		Gaps:                gaps,
	}
}

// gcpProjectNumber extracts the numeric suffix from a Resource Manager v3
// project resource name, e.g. "projects/123456789012" -> "123456789012".
func gcpProjectNumber(resourceName string) string {
	const prefix = "projects/"
	if !strings.HasPrefix(resourceName, prefix) {
		return ""
	}
	return strings.TrimPrefix(resourceName, prefix)
}
