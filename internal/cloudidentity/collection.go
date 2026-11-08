package cloudidentity

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"
)

type collectionRun struct {
	ports         CollectionPorts
	now           time.Time
	repositories  map[string]repositoryResult
	images        map[string]imageResult
	podIdentities []PodIdentityDeclaration
}

type repositoryResult struct {
	repository Repository
	err        error
}

type imageResult struct {
	image ImageProvenance
	err   error
}

type targetCollection struct {
	target          ScanTarget
	workloads       []Workload
	declarations    []Declaration
	podIdentities   []PodIdentityDeclaration
	inventoryGaps   []Gap
	declarationGaps []Gap
}

// Collect gathers one bounded evidence cohort. Provider failures become explicit
// coverage gaps; cancellation aborts rather than publishing a misleading cohort.
func Collect(ctx context.Context, plan ScanPlan, ports CollectionPorts, now time.Time) (Collection, error) {
	if ports.Repositories == nil || ports.Registry == nil || ports.Manifests == nil || ports.Declarations == nil || ports.Investigator == nil {
		return Collection{}, fmt.Errorf("cloud identity collection ports are required")
	}
	run := collectionRun{ports: ports, now: now.UTC(), repositories: make(map[string]repositoryResult), images: make(map[string]imageResult)}
	result := Collection{Scope: plan.Scope, CollectedAt: run.now, InventoryComplete: true, Evidence: []Evidence{}}
	var workloads []Workload
	var declarations []Declaration
	targets := make([]targetCollection, 0, len(plan.Targets))
	for _, target := range plan.Targets {
		if err := ctx.Err(); err != nil {
			return Collection{}, err
		}
		collected := run.collectTarget(ctx, target, plan.Services)
		workloads = append(workloads, collected.workloads...)
		declarations = append(declarations, collected.declarations...)
		run.podIdentities = append(run.podIdentities, collected.podIdentities...)
		targets = append(targets, collected)
		result.Gaps = append(result.Gaps, collected.inventoryGaps...)
		result.Gaps = append(result.Gaps, collected.declarationGaps...)
		if collectionHasNonWorkloadScopedGap(collected.inventoryGaps) {
			result.InventoryComplete = false
		}
	}
	cohorts := collectionCohorts(workloads)
	keys := make([]string, 0, len(cohorts))
	for key := range cohorts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	observed := make([]Evidence, 0, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return Collection{}, err
		}
		cohort := cohorts[key]
		cohort.Schema, cohort.Scope, cohort.CollectedAt = SchemaVersion, plan.Scope, run.now
		cohort.Declared = collectionDeclaration(cohort.Principal, declarations, nil)
		observed = append(observed, run.collectObservation(ctx, cohort))
	}
	// Live reads resolve computed IaC identifiers, but never supply desired
	// policy. Evaluate the pinned HCL only after those identifiers are known.
	for index, target := range plan.Targets {
		terraform := run.collectTerraform(ctx, target, collectionTargetIdentifiers(observed, target))
		targets[index].declarationGaps = append(targets[index].declarationGaps, terraform.declarationGaps...)
		declarations = append(declarations, terraform.declarations...)
		result.Gaps = append(result.Gaps, terraform.declarationGaps...)
	}
	subjectGaps := collectionSubjectGapsFromTargets(targets)
	// collectFederatedGCPCohorts resolves a federated GCP target's own
	// custom-pool identity BEFORE the generic alias resolution it performs
	// internally for every other cohort, so an EKS-hosted KSA is never
	// silently rewritten onto the project's GKE default-pool alias first
	// (review finding #2a).
	resolved, err := run.collectFederatedGCPCohorts(ctx, plan, observed, declarations)
	if err != nil {
		return Collection{}, err
	}
	for _, cohort := range resolved {
		cohort.Declared = collectionDeclaration(cohort.Principal, declarations, collectionConsumerDeclarationGaps(cohort.Consumers, targets))
		cohort = collectionApplySubjectScopedGaps(cohort, subjectGaps)
		// Target-scoped inventory gaps are scoped AFTER observation, using
		// this cohort's own known consumers and observed trust -- never
		// bare account/project equality (see cohortMayBeAffectedByTargetGap
		// in trust.go).
		if scoped := collectionCohortTargetScopedGaps(cohort, targets); len(scoped) > 0 {
			cohort.ConsumerInventoryComplete = false
			cohort.Gaps = append(cohort.Gaps, scoped...)
		}
		result.Evidence = append(result.Evidence, run.collectPrincipal(ctx, cohort))
	}
	if err := ctx.Err(); err != nil {
		return Collection{}, err
	}
	return result, nil
}

func (run *collectionRun) repository(ctx context.Context, pin SourcePin) (Repository, error) {
	key, err := digestJSON(pin)
	if err != nil {
		return Repository{}, fmt.Errorf("cloudidentity: digest source pin: %w", err)
	}
	if cached, ok := run.repositories[key]; ok {
		return cached.repository, cached.err
	}
	repository, err := run.ports.Repositories.ReadRepository(ctx, pin)
	run.repositories[key] = repositoryResult{repository, err}
	return repository, err
}

// verifyInputAssertions reads each assertion's own pinned repository
// through the run's shared cache and checks it with VerifyInputAssertion,
// returning one InputAssertionFailedGapCode gap scoped to scope per
// failure -- an unreadable repository is itself a failure. Shared by
// collectTarget (target-level assertions, appended to inventory gaps) and
// collectTerraform (per-root assertions, appended to declaration gaps):
// both report the same code, the same message shape, and the same scope
// (the owning target's own Name).
func (run *collectionRun) verifyInputAssertions(ctx context.Context, assertions []InputAssertion, scope string) []Gap {
	var gaps []Gap
	for _, assertion := range assertions {
		repository, err := run.repository(ctx, assertion.Source)
		if err != nil {
			gaps = append(gaps, Gap{Code: InputAssertionFailedGapCode, Scope: scope, Message: fmt.Sprintf("%s assertion on %s@%s:%s failed: pinned repository could not be read: %s", assertion.Kind, assertion.Source.Repository, assertion.Source.Revision, assertion.Path, err)})
			continue
		}
		ref, err := VerifyInputAssertion(repository, assertion)
		if err != nil {
			gaps = append(gaps, Gap{Code: InputAssertionFailedGapCode, Scope: scope, Message: fmt.Sprintf("%s assertion on %s@%s:%s failed: %s", assertion.Kind, ref.Repository, ref.Revision, assertion.Path, err), References: []Reference{ref}})
		}
	}
	return gaps
}

func (run *collectionRun) collectTarget(ctx context.Context, target ScanTarget, services []ServiceMapping) targetCollection {
	result := targetCollection{target: target}
	var manifests []Manifest
	for _, input := range target.Manifests {
		repository, err := run.repository(ctx, input.Source)
		if err != nil {
			result.inventoryGaps = append(result.inventoryGaps, collectionGap("manifest_repository_unavailable", target.Name, "Pinned manifest repository could not be read"))
			continue
		}
		result.inventoryGaps = append(result.inventoryGaps, repository.Gaps...)
		rendered, gaps, err := run.ports.Manifests.Render(ctx, ManifestRequest{Repository: repository, Paths: input.Paths, Chart: input.Chart, ValuesFiles: input.ValuesFiles, Values: input.Values, Release: input.Release, Namespace: input.Namespace, Environment: target.Environment, Cluster: target.Cluster, Applications: input.Applications, IgnoreMissingValueFiles: input.IgnoreMissingValueFiles, UnresolvedValues: input.UnresolvedValues})
		result.inventoryGaps = append(result.inventoryGaps, gaps...)
		if err != nil {
			result.inventoryGaps = append(result.inventoryGaps, collectionGap("manifest_render_failed", target.Name, "Manifest rendering did not complete"))
		}
		manifests = append(manifests, rendered...)
		// Terraform-contract value keys this scan could not bind are never
		// gapped blanket-wide here: the renderer's own object-scoped
		// cloud_identity.manifest.unresolved_value_in_object gap (appended
		// above via `gaps`) already names every rendered object the marker
		// actually reached, and only an identity-bearing one of those
		// demotes completeness (collectionGapIsIdentityBearingObject) --
		// vpcId/hostedZoneId/karpenter.* markers confined to non-identity
		// objects must never make an unrelated target's run look incomplete
		// (review finding #4).
	}
	// Claims and the Compositions/EnvironmentConfigs that expand them are
	// usually deployed by different charts, so composition runs per target.
	composed, composeGaps, err := run.ports.Manifests.Compose(ctx, ComposeRequest{Manifests: manifests, Environment: target.Environment, Cluster: target.Cluster})
	result.inventoryGaps = append(result.inventoryGaps, composeGaps...)
	if err != nil {
		result.inventoryGaps = append(result.inventoryGaps, collectionGap("manifest_composition_failed", target.Name, "Crossplane composition expansion did not complete"))
	}
	manifests = append(manifests, composed...)
	// Target-scoped services are appended AFTER the plan's own services, on
	// a fresh slice: they apply only to this target's own inventory
	// passes, and the plan's own slice must never be mutated by any
	// target's append.
	targetServices := append(append([]ServiceMapping{}, services...), target.Services...)
	workloads, gaps := Inventory(InventoryRequest{Manifests: manifests, Environment: target.Environment, Cluster: target.Cluster, Region: target.Region, Provider: target.Provider, Project: target.Project, Account: target.Account, Services: targetServices})
	result.inventoryGaps = append(result.inventoryGaps, gaps...)
	if target.Provider == AWS && target.Project != "" {
		// An AWS target with a paired GCP project: its own cluster also
		// carries a federated GCP identity domain (custom Workload Identity
		// Federation pool subjects declared by its own paired GCP identity
		// Terraform root). Inventory the SAME rendered manifests again as
		// GCP, producing a bare-KSA placeholder cohort per workload --
		// collectFederatedGCPCohorts later resolves it onto the Google
		// service account this target's own declarations show trusting
		// that exact subject, never inferring access here. Workload IDs
		// are qualified by provider and by the target's own
		// account/project/region: the same container's AWS-domain Workload
		// shares cluster/namespace/kind/name/container, and two targets may
		// reuse one cluster name under different domains. The placeholder
		// cohort itself is project-qualified by collectionPrincipalKey, so
		// its principal ID stays the parseable
		// k8s://<cluster>/<namespace>/sa/<name> form.
		// dedupeGaps collapses the generic render/pod-shape gaps the two
		// passes produce identically, keeping only genuinely new
		// GCP-principal-specific gaps.
		gcpWorkloads, gcpGaps := Inventory(InventoryRequest{Manifests: manifests, Environment: target.Environment, Cluster: target.Cluster, Region: target.Region, Provider: GCP, Project: target.Project, Account: target.Account, Services: targetServices})
		domain := target.Account + "/" + target.Project + "/" + target.Region
		for i := range gcpWorkloads {
			gcpWorkloads[i].ID += ":gcp:" + domain
		}
		workloads = append(workloads, gcpWorkloads...)
		result.inventoryGaps = dedupeGaps(append(result.inventoryGaps, gcpGaps...))
	}
	result.workloads = workloads
	crossplane, declarationGaps := DeclarationsFromManifests(manifests, target.Account, target.Project)
	result.declarations = append(result.declarations, crossplane...)
	result.declarationGaps = append(result.declarationGaps, declarationGaps...)
	ackRoles, ackPodIdentities, ackGaps := DeclarationsFromACK(manifests, target.Cluster, target.Account)
	result.declarations = append(result.declarations, ackRoles...)
	result.podIdentities = ackPodIdentities
	result.declarationGaps = append(result.declarationGaps, ackGaps...)
	result.inventoryGaps = append(result.inventoryGaps, run.verifyInputAssertions(ctx, target.InputAssertions, target.Name)...)
	for _, known := range target.KnownGaps {
		result.inventoryGaps = append(result.inventoryGaps, collectionGap("cloud_identity.plan_known_gap", target.Name, known.Code+": "+known.Message))
	}
	return result
}

func (run *collectionRun) collectTerraform(ctx context.Context, target ScanTarget, identifiers map[string]string) targetCollection {
	var result targetCollection
	for _, root := range target.Terraform {
		repository, err := run.repository(ctx, root.Source)
		if err != nil {
			result.declarationGaps = append(result.declarationGaps, collectionGap("terraform_repository_unavailable", target.Name, "Pinned Terraform repository could not be read"))
			continue
		}
		result.declarationGaps = append(result.declarationGaps, repository.Gaps...)
		result.declarationGaps = append(result.declarationGaps, run.verifyInputAssertions(ctx, root.InputAssertions, target.Name)...)
		declarations, gaps, err := run.ports.Declarations.ReadDeclarations(ctx, TerraformInput{Repository: repository, Root: root.Root, Variables: root.Variables, Account: target.Account, Project: target.Project, Region: root.Region, ResolvedIdentifiers: identifiers, VarFiles: root.VarFiles, MetadataBindings: root.MetadataBindings})
		result.declarations = append(result.declarations, declarations...)
		result.declarationGaps = append(result.declarationGaps, gaps...)
		if err != nil {
			result.declarationGaps = append(result.declarationGaps, collectionGap("terraform_evaluation_failed", target.Name, "Terraform declaration evaluation did not complete"))
		}
	}
	return result
}

func collectionGap(code, scope, message string) Gap {
	return Gap{Code: code, Scope: scope, Message: message}
}

// federatedGCPCustomPoolSubjectPattern matches a custom (non-GKE) Workload
// Identity Federation pool subject member form
// "principal://iam.googleapis.com/<pool resource name>/subject/
// system:serviceaccount:<namespace>:<name>", duplicated as a literal from
// internal/cloudidentity/iac/gcp.go's gcpCustomPoolPrincipalPattern: this
// package cannot import iac (iac imports this package). Capture groups:
// (1) project number, (2) pool id, (3) namespace, (4) service account --
// pool identity is never reduced to a bare namespace/serviceAccount match
// (review finding #2c): two federated GCP targets sharing a
// namespace/serviceAccount name must never cross-match through an
// unrelated pool.
var federatedGCPCustomPoolSubjectPattern = regexp.MustCompile(`^principal://iam\.googleapis\.com/projects/([0-9]+)/locations/global/workloadIdentityPools/([a-zA-Z0-9-]+)/subject/system:serviceaccount:([^:]+):([^:]+)$`)

// federatedGCPServiceAccountKind mirrors the Principal.Kind the live GCP
// reader (sources/internal/cloudidentity/gcp_principal.go's
// gcpKindServiceAccount) requires to observe a Google service account;
// duplicated as a literal since that package depends on this one, not the
// reverse. The Terraform declaration reader (iac/gcp.go's
// gcpServiceAccountIdentity) registers a declared service account's own
// Kind as the unrelated literal "service_account", so it is normalized
// here before the principal is handed to the live reader.
const federatedGCPServiceAccountKind = "gcp_service_account"

// federatedGCPDirectPrincipalKind is Contract A.5's Kind for a Workload
// Identity Federation member granted a role directly (project/org/folder-
// or resource-level IAM), never through impersonating a Google service
// account.
const federatedGCPDirectPrincipalKind = "gcp_workload_identity_principal"

// federatedGCPDeclaredCustomPools collects the (project number, pool id)
// pairs of every custom Workload Identity Federation pool-provider fact
// declared for project (iac/run.go attaches the whole discovered provider
// set to every GCP principal one Terraform evaluation declares, so
// filtering declarations by Principal.Project==project already scopes to
// that project's own paired GCP identity Terraform root), so
// federatedGCPCustomPoolServiceAccounts/federatedGCPCustomPoolDirectPrincipals
// never match a custom-pool subject against a pool declared for a
// DIFFERENT federated GCP target/project (review finding #2c).
func federatedGCPDeclaredCustomPools(declarations []Declaration, project string) map[[2]string]bool {
	pools := make(map[[2]string]bool)
	for _, declaration := range declarations {
		if declaration.Principal.Provider != GCP || declaration.Principal.Project != project {
			continue
		}
		for _, provider := range declaration.GCPWorkloadIdentityProviders {
			if provider.ProjectNumber == "" || provider.PoolID == "" {
				continue
			}
			pools[[2]string{provider.ProjectNumber, provider.PoolID}] = true
		}
	}
	return pools
}

// federatedGCPCustomPoolGSAMatch pairs a declared trusted Google service
// account with the exact declared trust member (subject) that must still
// be confirmed live for it (federatedGCPCustomPoolBindingIsLive, finding
// #2d).
type federatedGCPCustomPoolGSAMatch struct {
	Principal Principal
	Subject   string
}

// federatedGCPCustomPoolServiceAccounts finds EVERY Google service account
// this scan's own paired GCP identity Terraform root declares as trusting
// the exact Kubernetes namespace/serviceAccount subject through a custom
// Workload Identity Federation pool actually declared for project --
// never only the first (review finding #3): a workload's rendered
// ServiceAccount can be declared to impersonate more than one GSA through
// the identical custom-pool subject, and every one of them must be
// re-observed, not silently dropped after the first match. Each
// Declaration contributes at most one match (its own Principal, deduped
// by principal key), walked in declaration order, so the result is
// deterministic. It is declaration-only: it never establishes access by
// itself, only identifies WHICH principals collectFederatedGCPCohorts
// should hand to the existing live GCP reader, plus each one's exact
// declared trust member (subject) that must still be confirmed live
// (finding #2d).
func federatedGCPCustomPoolServiceAccounts(declarations []Declaration, project, namespace, serviceAccount string) []federatedGCPCustomPoolGSAMatch {
	declaredPools := federatedGCPDeclaredCustomPools(declarations, project)
	var matches []federatedGCPCustomPoolGSAMatch
	seen := map[string]bool{}
	for _, declaration := range declarations {
		p := declaration.Principal
		if p.Provider != GCP || p.Project != project || p.ID == "" {
			continue
		}
		found := false
		for _, grant := range declaration.Policy.Trust {
			if found {
				break
			}
			for _, member := range grant.Members {
				match := federatedGCPCustomPoolSubjectPattern.FindStringSubmatch(member)
				if match == nil || match[3] != namespace || match[4] != serviceAccount {
					continue
				}
				if !declaredPools[[2]string{match[1], match[2]}] {
					continue
				}
				resolved := p
				resolved.Kind = federatedGCPServiceAccountKind
				if key := collectionPrincipalKey(resolved); !seen[key] {
					seen[key] = true
					matches = append(matches, federatedGCPCustomPoolGSAMatch{Principal: resolved, Subject: member})
				}
				found = true
				break
			}
		}
	}
	return matches
}

// federatedGCPCustomPoolDirectPrincipals finds EVERY Declaration whose own
// Principal IS exactly a custom-pool Workload Identity Federation subject
// (project/org/folder- or resource-level IAM granting the member
// directly, never impersonating a Google service account -- iac/gcp.go's
// gcpResourceIAM/gcpResourceLevelIAM), for the exact Kubernetes
// namespace/serviceAccount subject, through a pool actually declared for
// project (review finding #2b; Contract A.5/A.6) -- never only the first
// (review finding #3): a workload simultaneously holding a direct-
// principal grant and one or more GSA impersonation grants on the SAME
// subject must have all of them emitted. Deduped by principal key.
func federatedGCPCustomPoolDirectPrincipals(declarations []Declaration, project, namespace, serviceAccount string) []Principal {
	declaredPools := federatedGCPDeclaredCustomPools(declarations, project)
	var principals []Principal
	seen := map[string]bool{}
	for _, declaration := range declarations {
		p := declaration.Principal
		if p.Provider != GCP || p.Project != project {
			continue
		}
		match := federatedGCPCustomPoolSubjectPattern.FindStringSubmatch(p.ID)
		if match == nil || match[3] != namespace || match[4] != serviceAccount {
			continue
		}
		if !declaredPools[[2]string{match[1], match[2]}] {
			continue
		}
		direct := Principal{ID: p.ID, Provider: GCP, Kind: federatedGCPDirectPrincipalKind, Project: project}
		if key := collectionPrincipalKey(direct); !seen[key] {
			seen[key] = true
			principals = append(principals, direct)
		}
	}
	return principals
}

// federatedGCPCustomPoolBindingIsLive reports whether reobserved's OWN
// live re-observed Trust holds a POSITIVELY proven impersonation-capable
// (gcpGrantRoleProvenImpersonationCapable, trust.go) Allow grant whose
// Members exactly lists subject -- the custom-pool Workload Identity
// Federation member this target's own paired GCP identity Terraform root
// declares trusting this exact Kubernetes subject. Re-observation proves
// the Google service account's own live identity exists and is readable,
// but never that THIS specific binding is still live: a service account
// whose live policy no longer lists the exact declared member (removed,
// renamed, role narrowed to non-impersonation) must never silently keep
// the target's declared trust as if it were still granted (review finding
// #2d). The conservative "unresolved role = capable" default
// (gcpGrantIsTrustCapable) used elsewhere in this package for gap-scoping
// is deliberately NOT used here: this gate backs an alias asserting
// confirmed live access, so an unresolved role must never establish it;
// callers must resolve reobserved.Definitions via the cloud-reader Define
// port before calling this.
func federatedGCPCustomPoolBindingIsLive(reobserved Evidence, subject string) bool {
	if !reobserved.Observed.Complete {
		return false
	}
	for _, g := range reobserved.Observed.Trust {
		if g.Effect != "Allow" || !gcpGrantRoleProvenImpersonationCapable(g, reobserved.Definitions) {
			continue
		}
		if stringValueMatches(g.Members, subject) {
			return true
		}
	}
	return false
}

// federatedGCPConsumerClusterIssuer finds the EKS OIDC issuer the AWS
// reader already resolved (aws_eks_oidc_issuer:<cluster>,
// sources/internal/cloudidentity/aws_observe.go's resolveWorkloadLinkage,
// the same key collectionTargetIdentifiers already reuses for HCL) for
// consumer's own cluster, reusing it ONLY when some Evidence among
// cohorts actually observed a consumer on consumer's own exact
// Cluster/CloudAccount/Region (Contract C4): the AWS reader itself
// refuses to resolve an issuer for a cluster name shared ambiguously
// across accounts/regions, so a value must never be borrowed from a
// different federated GCP target's same-named cluster. Conflicting
// values across matching Evidence are left unresolved rather than
// guessed.
func federatedGCPConsumerClusterIssuer(cohorts []Evidence, consumer Workload) (string, bool) {
	if consumer.Cluster == "" {
		return "", false
	}
	key := "aws_eks_oidc_issuer:" + consumer.Cluster
	issuer, found, conflict := "", false, false
	for _, cohort := range cohorts {
		value, ok := cohort.ResolvedIdentifiers[key]
		if !ok || value == "" {
			continue
		}
		belongs := false
		for _, c := range cohort.Consumers {
			if c.Cluster == consumer.Cluster && c.CloudAccount == consumer.CloudAccount && c.Region == consumer.Region {
				belongs = true
				break
			}
		}
		if !belongs {
			continue
		}
		if found && issuer != value {
			conflict = true
			continue
		}
		issuer, found = value, true
	}
	if conflict {
		return "", false
	}
	return issuer, found
}

// federatedGCPCustomPoolIssuerGapCode scopes a re-observed custom-pool GCP
// cohort (GSA or direct principal) that is about to be emitted but for
// which no AWS-resolved EKS OIDC issuer could be found for its
// consumer's own cluster (Contract C4): the value is never fabricated or
// borrowed from another cluster.
const federatedGCPCustomPoolIssuerGapCode = "cloud_identity.gcp.custom_pool_issuer_unresolved"

// federatedGCPClusterDomain is the (Cluster, CloudAccount, Region) a
// consumer workload's own aws_eks_oidc_issuer:<cluster> value is scoped
// to (federatedGCPConsumerClusterIssuer, Contract C4) -- CloudProject is
// deliberately excluded, since the issuer key itself carries only the
// cluster name.
type federatedGCPClusterDomain struct {
	Cluster      string
	CloudAccount string
	Region       string
}

// federatedGCPAttachClusterIssuer carries the AWS reader's own
// live-resolved EKS OIDC issuer for EVERY distinct (Cluster, CloudAccount,
// Region) among consumers (federatedGCPConsumerClusterIssuer, Contract
// C4) onto evidence.ResolvedIdentifiers under the exact
// aws_eks_oidc_issuer:<cluster> key the GCP custom-pool detector
// normalizes and compares against a provider's own issuerUri -- without
// it a custom-pool GSA/direct-principal cohort carries only the GCP
// reader's own project_number and the detector can never confirm the
// provider actually belongs to this cluster. consumers is every federated
// GCP consumer of the principal's final merged evidence, never its
// consumers unfiltered: an unrelated consumer's cluster must never
// contribute an issuer. It runs once per principal, after
// collectObservation (which fully replaces ResolvedIdentifiers with the
// GCP reader's own observation) and after every cohort and subject
// partition resolving onto that principal is merged: the merge keeps the
// last of two disagreeing identifiers, so an issuer attached before it
// could replace one this check leaves unset. Because the
// aws_eks_oidc_issuer key carries only the cluster name, two distinct
// consumer domains sharing a cluster name but resolving different issuers
// can never both be represented under it: rather than silently keep
// whichever ran last, that key is left unset and a scoped gap is attached
// instead, the same as when no issuer is available at all.
func federatedGCPAttachClusterIssuer(evidence Evidence, cohorts []Evidence, consumers []Workload) Evidence {
	resolved := make(map[string]string, len(evidence.ResolvedIdentifiers)+len(consumers))
	for k, v := range evidence.ResolvedIdentifiers {
		resolved[k] = v
	}
	seen := map[federatedGCPClusterDomain]bool{}
	conflicted := map[string]bool{}
	for _, consumer := range consumers {
		domain := federatedGCPClusterDomain{Cluster: consumer.Cluster, CloudAccount: consumer.CloudAccount, Region: consumer.Region}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		key := "aws_eks_oidc_issuer:" + consumer.Cluster
		issuer, ok := federatedGCPConsumerClusterIssuer(cohorts, consumer)
		if !ok {
			evidence.Gaps = append(evidence.Gaps, collectionGap(federatedGCPCustomPoolIssuerGapCode, evidence.Principal.ID, "no AWS-resolved EKS OIDC issuer is available for cluster "+consumer.Cluster+"; this custom-pool binding's provider issuer cannot be cross-checked"))
			continue
		}
		if conflicted[key] {
			continue
		}
		if existing, already := resolved[key]; already && existing != issuer {
			conflicted[key] = true
			delete(resolved, key)
			evidence.Gaps = append(evidence.Gaps, collectionGap(federatedGCPCustomPoolIssuerGapCode, evidence.Principal.ID, "cluster "+consumer.Cluster+" resolves to conflicting AWS EKS OIDC issuers across this principal's own consumer domains; this custom-pool binding's provider issuer cannot be cross-checked"))
			continue
		}
		resolved[key] = issuer
	}
	evidence.ResolvedIdentifiers = resolved
	return evidence
}

// federatedGCPTargetDomain is the exact AWS target domain
// (Cluster/CloudAccount/Region/CloudProject) collectTarget's extra
// GCP-provider Inventory pass stamps onto every re-inventoried workload
// for an AWS target with a paired GCP project (inventory.go). A workload
// belongs to this federation iff its own domain equals one of these
// exactly -- never a Principal.Project match (review finding #6): a
// federated GCP target's own custom-pool GSA can be declared/owned in a
// different (identity) GCP project than its own paired project, and the
// live GCP reader already resolves such cross-project GSAs by the custom
// pool's own project number, not by the GSA's project.
type federatedGCPTargetDomain struct {
	Cluster      string
	CloudAccount string
	Region       string
	CloudProject string
}

// federatedGCPTargetDomains builds, once, the set of every AWS target
// with a paired GCP project's own domain (Provider AWS, Project != "")
// this plan declares.
func federatedGCPTargetDomains(plan ScanPlan) map[federatedGCPTargetDomain]bool {
	domains := map[federatedGCPTargetDomain]bool{}
	for _, target := range plan.Targets {
		if target.Provider == AWS && target.Project != "" {
			domains[federatedGCPTargetDomain{Cluster: target.Cluster, CloudAccount: target.Account, Region: target.Region, CloudProject: target.Project}] = true
		}
	}
	return domains
}

// federatedGCPCohortConsumers returns cohort's own Consumers that are
// federated GCP consumers (their exact domain matches some AWS target
// with a paired GCP project in domains), in cohort.Consumers' own order:
// only these ever drive federated GCP custom-pool expansion or issuer
// attachment (review finding #6) -- a legacy GKE/GCP consumer sharing
// this same Google service account must never leak federated-GCP
// behavior onto it, nor the reverse.
func federatedGCPCohortConsumers(cohort Evidence, domains map[federatedGCPTargetDomain]bool) []Workload {
	var consumers []Workload
	for _, consumer := range cohort.Consumers {
		d := federatedGCPTargetDomain{Cluster: consumer.Cluster, CloudAccount: consumer.CloudAccount, Region: consumer.Region, CloudProject: consumer.CloudProject}
		if domains[d] {
			consumers = append(consumers, consumer)
		}
	}
	return consumers
}

// federatedGCPSubject is the exact Kubernetes custom-pool trust subject
// (CloudProject/Namespace/ServiceAccount)
// federatedGCPCustomPoolServiceAccounts/federatedGCPCustomPoolDirectPrincipals
// key their declared-trust lookup by. CloudProject is the CONSUMING
// workload's own paired GCP project, never the resolved GSA's own
// Principal.Project (review finding #4): federated GCP custom-pool
// expansion must always use the consumer's own project, the one whose
// Terraform root actually declares the custom pool -- a GSA shared by
// consumers in two different federated GCP projects must expand each one
// against its OWN project's declarations, never the other's.
type federatedGCPSubject struct {
	CloudProject   string
	Namespace      string
	ServiceAccount string
}

// federatedGCPPartitionConsumersBySubject groups consumers by their exact
// custom-pool trust subject, in first-seen order (deterministic): multiple
// consumers can share one resolved GSA (an already-annotated cohort
// groups every workload using that one Google service account) while
// declaring DIFFERENT custom-pool trust subjects -- each subject's own
// expansion must only ever see that subject's own consumers (review
// finding #4), never another subject's.
func federatedGCPPartitionConsumersBySubject(consumers []Workload) ([]federatedGCPSubject, map[federatedGCPSubject][]Workload) {
	var order []federatedGCPSubject
	bySubject := make(map[federatedGCPSubject][]Workload, len(consumers))
	for _, consumer := range consumers {
		subject := federatedGCPSubject{CloudProject: consumer.CloudProject, Namespace: consumer.Namespace, ServiceAccount: consumer.ServiceAccount}
		if _, ok := bySubject[subject]; !ok {
			order = append(order, subject)
		}
		bySubject[subject] = append(bySubject[subject], consumer)
	}
	return order, bySubject
}

// collectFederatedGCPCohorts resolves every federated GCP
// bare-Kubernetes-service-account placeholder cohort (collectTarget's
// extra GCP-provider Inventory pass for an AWS target with a paired GCP
// project) BEFORE any generic alias resolution (collectionResolvedCohorts)
// runs for it, so an EKS-hosted KSA is never silently rewritten onto the
// project's GKE default-pool alias first (review finding #2a; cohorts
// must be the raw, pre-alias-resolution observed list). A GCP cohort is a
// FEDERATED cohort iff at least one of its own Consumers is itself a
// federated GCP consumer -- its exact domain
// (Cluster/CloudAccount/Region/CloudProject) equals some AWS target with
// a paired GCP project in this plan (federatedGCPTargetDomains) -- never
// by matching the cohort's own Principal.Project (review finding #6): a
// federated GCP target's own custom-pool GSA can be owned in a different
// (identity) GCP project than its own paired project, and the live GCP
// reader already resolves such cross-project GSAs by the custom pool's
// own project number. Every other cohort passes through the ordinary
// generic alias resolution untouched.
//
// Within a federated cohort, only its own federated GCP consumers ever
// drive expansion or issuer attachment; they are partitioned by their
// exact custom-pool trust subject (CloudProject/Namespace/ServiceAccount,
// federatedGCPPartitionConsumersBySubject) in deterministic order, because
// one resolved GSA can be shared by consumers declaring entirely
// different subjects (different federated GCP projects and/or different
// Kubernetes service accounts) and each subject's own expansion must only
// ever see that subject's own consumers (review finding #4) -- never only
// the cohort's first consumer, and never another subject's consumers. Per
// subject, the cohort resolves onto EVERY matching Google service account
// that subject's own CloudProject's paired GCP identity Terraform root
// declares as trusting that exact Kubernetes subject through a declared
// custom Workload Identity Federation pool (each re-read live, and kept
// only when that exact binding is still live --
// federatedGCPCustomPoolBindingIsLive, finding #2d), plus every directly
// granted custom-pool principal (finding #2b) -- never only the first
// match of either kind (review finding #3): a workload can be declared to
// impersonate more than one GSA, or hold a direct-principal grant
// alongside one or more GSA grants, on the identical subject. Access is
// still only ever proven by each principal's own re-observed live
// binding, never inferred from the declaration alone. The unresolved
// placeholder cohort itself (always exactly one subject) is kept
// alongside any live-confirmed/direct cohorts whenever at least one
// declared GSA binding failed live confirmation (so that gap stays
// visible), or emitted alone when nothing resolved at all. An
// already-configured (annotated) GSA is additionally still emitted with
// ALL of its own consumers. Every emitted GSA/direct cohort carries the
// AWS-resolved EKS OIDC issuer for EVERY distinct cluster domain among its
// federated GCP consumers (federatedGCPAttachClusterIssuer, Contract C4),
// attached once after all of its cohorts and subject partitions are
// merged. Legacy GCP/GKE cohorts (not part of this federation) pass
// through the ordinary generic alias resolution untouched.
func (run *collectionRun) collectFederatedGCPCohorts(ctx context.Context, plan ScanPlan, cohorts []Evidence, declarations []Declaration) ([]Evidence, error) {
	domains := federatedGCPTargetDomains(plan)
	if len(domains) == 0 {
		return collectionResolvedCohorts(cohorts), nil
	}
	reader := run.ports.Clouds[GCP]
	type federatedGCPPendingCohort struct {
		evidence  Evidence
		consumers []Workload
	}
	var federatedCohorts []federatedGCPPendingCohort
	var otherCohorts []Evidence
	for _, cohort := range cohorts {
		if cohort.Principal.Provider == GCP {
			if consumers := federatedGCPCohortConsumers(cohort, domains); len(consumers) > 0 {
				federatedCohorts = append(federatedCohorts, federatedGCPPendingCohort{evidence: cohort, consumers: consumers})
				continue
			}
		}
		otherCohorts = append(otherCohorts, cohort)
	}
	byKey := make(map[string]Evidence, len(cohorts))
	var order []string
	merge := func(key string, cohort Evidence) {
		if existing, ok := byKey[key]; ok {
			byKey[key] = collectionMergeCohort(existing, cohort)
			return
		}
		byKey[key] = cohort
		order = append(order, key)
	}
	// carriesIssuers marks the federated GCP principals that carry their
	// federated GCP consumers' cluster issuers, attached once the result
	// is assembled.
	carriesIssuers := map[string]bool{}
	mergeFederated := func(key string, cohort Evidence) {
		merge(key, cohort)
		carriesIssuers[key] = true
	}
	for _, pending := range federatedCohorts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cohort := pending.evidence
		unresolved := isUnresolvedCloudPrincipal(cohort.Principal)
		if !unresolved {
			// An already-configured GSA (e.g. an iam.gke.io/gcp-service-
			// account annotation) is emitted with all of its consumers, and
			// each of its subjects may also be declared to trust additional
			// GSAs/direct principals the annotation never names.
			mergeFederated(collectionPrincipalKey(cohort.Principal), cohort)
		}
		subjects, bySubject := federatedGCPPartitionConsumersBySubject(pending.consumers)
		keepPlaceholder, anyMatch := false, false
		for _, subject := range subjects {
			subjectConsumers := bySubject[subject]
			gsas := federatedGCPCustomPoolServiceAccounts(declarations, subject.CloudProject, subject.Namespace, subject.ServiceAccount)
			directs := federatedGCPCustomPoolDirectPrincipals(declarations, subject.CloudProject, subject.Namespace, subject.ServiceAccount)
			if len(gsas) > 0 || len(directs) > 0 {
				anyMatch = true
			}
			for _, match := range gsas {
				reobserved := run.collectObservation(ctx, Evidence{Schema: SchemaVersion, Principal: match.Principal, Scope: plan.Scope, CollectedAt: run.now, ConsumerInventoryComplete: cohort.ConsumerInventoryComplete, Consumers: subjectConsumers, Gaps: cohort.Gaps})
				// collectObservation never resolves role Definitions (Define
				// otherwise runs only on the final cohorts, in collectPrincipal);
				// the alias gate requires a proven role, so resolve it first.
				if reader != nil {
					if definitions, err := reader.Define(ctx, collectionDefinitionRequest(reobserved.Declared, reobserved.Observed)); err == nil {
						reobserved.Definitions = MergeDefinitions(reobserved.Definitions, definitions)
					}
				}
				if !federatedGCPCustomPoolBindingIsLive(reobserved, match.Subject) {
					if unresolved {
						keepPlaceholder = true
						cohort.Gaps = append(cohort.Gaps, collectionGap("cloud_identity.gcp.custom_pool_binding_not_live", cohort.Principal.ID, "this target's declared custom-pool trust binding to "+match.Principal.ID+" is not confirmed by that service account's own live IAM policy"))
					}
					continue
				}
				mergeFederated(collectionPrincipalKey(match.Principal), reobserved)
			}
			for _, direct := range directs {
				reobserved := run.collectObservation(ctx, Evidence{Schema: SchemaVersion, Principal: direct, Scope: plan.Scope, CollectedAt: run.now, ConsumerInventoryComplete: cohort.ConsumerInventoryComplete, Consumers: subjectConsumers, Gaps: cohort.Gaps})
				mergeFederated(collectionPrincipalKey(direct), reobserved)
			}
		}
		if unresolved && (keepPlaceholder || !anyMatch) {
			merge(collectionPrincipalKey(cohort.Principal), cohort)
		}
	}
	for _, cohort := range collectionResolvedCohorts(otherCohorts) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		merge(collectionPrincipalKey(cohort.Principal), cohort)
	}
	result := make([]Evidence, 0, len(order))
	for _, key := range order {
		evidence := byKey[key]
		if carriesIssuers[key] {
			evidence = federatedGCPAttachClusterIssuer(evidence, cohorts, federatedGCPCohortConsumers(evidence, domains))
		}
		result = append(result, evidence)
	}
	sort.Slice(result, func(i, j int) bool {
		return collectionPrincipalKey(result[i].Principal) < collectionPrincipalKey(result[j].Principal)
	})
	return result, nil
}
