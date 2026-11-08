package cloudidentity

import (
	"context"
	"maps"
	"slices"
	"strings"
)

func (run *collectionRun) collectObservation(ctx context.Context, evidence Evidence) Evidence {
	reader := run.ports.Clouds[evidence.Principal.Provider]
	if reader == nil {
		evidence.Gaps = append(evidence.Gaps, collectionGap("cloud_reader_unavailable", evidence.Principal.ID, "No read-only cloud adapter is configured for this principal"))
		return evidence
	}
	observation, err := reader.Observe(ctx, CloudRequest{Principal: evidence.Principal, Consumers: evidence.Consumers, Declared: evidence.Declared})
	evidence.Observed = observation.Policy
	evidence.ResolvedIdentifiers = observation.ResolvedIdentifiers
	evidence.GCPWorkloadIdentityProviders = observation.GCPWorkloadIdentityProviders
	evidence.Gaps = append(evidence.Gaps, observation.Gaps...)
	if err != nil {
		evidence.Observed.Complete = false
		evidence.Observed.Gaps = append(evidence.Observed.Gaps, collectionGap("cloud_observation_failed", evidence.Principal.ID, "Live IAM observation did not complete"))
	}
	evidence.Definitions = observation.Definitions
	evidence.Gaps = append(evidence.Gaps, run.undeclaredLivePodIdentityGaps(evidence)...)
	evidence = run.joinDeclaredPodIdentityAssociation(evidence)
	return evidence
}

// identityBindingKindACKPodIdentityAssociation is the exact
// Workload.Configuration["identity_binding_kind"] value the cloud-identity
// graph projector (internal/sourceprojection/cloud_identity.go's
// cloudIdentityAssociationBasis) recognizes as the declared-only ACK
// PodIdentityAssociation mechanism, so it emits associated_with with
// basis="ack_pod_identity_association", verified=false for this consumer
// instead of falling back to the generic irsa_annotation label.
const identityBindingKindACKPodIdentityAssociation = "ack_pod_identity_association"

// joinDeclaredPodIdentityAssociation promotes a bare-Kubernetes-service-
// account AWS cohort onto its declared ACK PodIdentityAssociation role
// (DeclarationsFromACK, collected into run.podIdentities) when no live EKS
// Pod Identity association already confirmed one for the same cluster/
// namespace/service account -- collectObservation runs first, so
// evidence.ResolvedIdentifiers already reflects any live confirmation, and
// a subject the live reader already resolved is left for
// collectionResolvedCohorts to promote from ResolvedIdentifiers exactly as
// before. Without this, a cohort whose identity is declared only in the
// rendered chart (or whose live read is unavailable) keeps the unresolved
// "k8s://..." principal ID: cloudIdentityCanonicalPrincipalURN mints no
// principal entity for that prefix, so the declared role relationship
// disappears from the graph entirely instead of becoming an unverified
// associated_with edge.
//
// This never writes ResolvedIdentifiers and never changes which key a live
// EKS Pod Identity association is checked under
// (ackLivePodIdentityResolvedPrefix), so
// cloudIdentityHasLiveAWSPodIdentityAssociation -- the projector's
// can_assume gate -- stays false for every consumer this function touches:
// a declaration alone never becomes live-confirmed access here.
func (run *collectionRun) joinDeclaredPodIdentityAssociation(evidence Evidence) Evidence {
	if evidence.Principal.Provider != AWS || !strings.HasPrefix(evidence.Principal.ID, "k8s://") {
		return evidence
	}
	var roleARN string
	var declRefs []Reference
	matched := make(map[string]bool, len(evidence.Consumers))
	for _, c := range evidence.Consumers {
		if c.Cluster == "" || c.Namespace == "" || c.ServiceAccount == "" {
			continue
		}
		subject := "k8s://" + c.Cluster + "/" + c.Namespace + "/sa/" + c.ServiceAccount
		if evidence.ResolvedIdentifiers[ackLivePodIdentityResolvedPrefix+subject] != "" {
			continue
		}
		for _, pid := range run.podIdentities {
			if pid.Cluster == c.Cluster && pid.Namespace == c.Namespace && pid.ServiceAccount == c.ServiceAccount {
				roleARN, declRefs = pid.RoleARN, pid.References
				matched[c.ID] = true
				break
			}
		}
	}
	if roleARN == "" {
		return evidence
	}
	oldKey := collectionPrincipalKey(evidence.Principal)
	evidence.Principal.ID, evidence.Principal.Kind = roleARN, manifestInventoryKindAWSRole
	evidence.Consumers = slices.Clone(evidence.Consumers)
	for i := range evidence.Consumers {
		if !matched[evidence.Consumers[i].ID] {
			continue
		}
		configuration := maps.Clone(evidence.Consumers[i].Configuration)
		if configuration == nil {
			configuration = map[string]string{}
		}
		configuration["identity_binding_kind"] = identityBindingKindACKPodIdentityAssociation
		evidence.Consumers[i].Configuration = configuration
		evidence.Consumers[i].References = append(slices.Clone(evidence.Consumers[i].References), declRefs...)
		principals := slices.Clone(evidence.Consumers[i].Principals)
		for p, principal := range principals {
			if collectionPrincipalKey(principal) == oldKey {
				principals[p] = evidence.Principal
			}
		}
		evidence.Consumers[i].Principals = principals
	}
	return evidence
}

// ackLivePodIdentityResolvedPrefix mirrors the ResolvedIdentifiers key
// format a live AWS Pod Identity reader populates for a confirmed EKS Pod
// Identity association (sources/internal/cloudidentity/aws_observe.go):
// "aws_pod_identity_role:k8s://<cluster>/<namespace>/sa/<name>" -> the
// bound role's ARN. It is duplicated here as a literal, not imported from
// trust.go, because that file holds decision-only (Assess-exclusive)
// helpers being migrated to VulnView; this collection-time comparison
// must not depend on code scheduled for removal.
const ackLivePodIdentityResolvedPrefix = "aws_pod_identity_role:"

// undeclaredLivePodIdentityGaps reports, for every live EKS Pod Identity
// association this principal's live reader confirmed for one of its
// reviewed consumers, whether a matching ACK PodIdentityAssociation
// (DeclarationsFromACK) was collected from manifests for the same cluster/
// namespace/service account/role. An association an operator created
// without an in-repo PodIdentityAssociation is live-only linkage
// evidence -- recorded as a gap for downstream (VulnView) review, never
// treated here as drift or excess, which are posture decisions this
// package no longer makes.
//
// This runs inside collectObservation, BEFORE collectionResolvedCohorts
// aliases a bare-Kubernetes-service-account cohort onto its live-resolved
// role: evidence.Principal.ID is still the KSA subject at this point, not
// the role ARN, so the comparison uses the resolved ARN value itself
// (ResolvedIdentifiers[...]) rather than evidence.Principal.ID.
func (run *collectionRun) undeclaredLivePodIdentityGaps(evidence Evidence) []Gap {
	if evidence.Principal.Provider != AWS {
		return nil
	}
	var gaps []Gap
	for _, c := range evidence.Consumers {
		if c.Cluster == "" || c.Namespace == "" || c.ServiceAccount == "" {
			continue
		}
		subject := "k8s://" + c.Cluster + "/" + c.Namespace + "/sa/" + c.ServiceAccount
		roleARN := evidence.ResolvedIdentifiers[ackLivePodIdentityResolvedPrefix+subject]
		if roleARN == "" {
			continue
		}
		declared := false
		for _, pid := range run.podIdentities {
			if pid.Cluster == c.Cluster && pid.Namespace == c.Namespace && pid.ServiceAccount == c.ServiceAccount && pid.RoleARN == roleARN {
				declared = true
				break
			}
		}
		if !declared {
			gaps = append(gaps, Gap{Code: "cloud_identity.ack_declaration.live_only_pod_identity_association", Scope: subject, Message: "a live EKS Pod Identity association binds role " + roleARN + " to " + subject + ", but no ACK PodIdentityAssociation declares it; an operator may have created the association directly"})
		}
	}
	return gaps
}

func (run *collectionRun) collectPrincipal(ctx context.Context, evidence Evidence) Evidence {
	reader := run.ports.Clouds[evidence.Principal.Provider]
	if reader == nil {
		return evidence
	}
	definitions, err := reader.Define(ctx, collectionDefinitionRequest(evidence.Declared, evidence.Observed))
	if err != nil {
		definitions.Complete = false
		definitions.Gaps = append(definitions.Gaps, collectionGap("permission_definitions_unavailable", evidence.Principal.ID, "Current permission definitions could not be completely retrieved"))
	}
	evidence.Definitions = MergeDefinitions(evidence.Definitions, definitions)
	for index := range evidence.Consumers {
		if ctx.Err() != nil {
			break
		}
		workload, investigation, gaps := run.collectInvestigation(ctx, evidence.Consumers[index], evidence.Definitions)
		evidence.Consumers[index] = workload
		evidence.Investigations = append(evidence.Investigations, investigation)
		evidence.Gaps = append(evidence.Gaps, gaps...)
	}
	return evidence
}

func (run *collectionRun) image(ctx context.Context, image string) (ImageProvenance, error) {
	if cached, ok := run.images[image]; ok {
		return cached.image, cached.err
	}
	provenance, err := run.ports.Registry.ReadImage(ctx, image)
	run.images[image] = imageResult{provenance, err}
	return provenance, err
}

func (run *collectionRun) collectInvestigation(ctx context.Context, workload Workload, definitions Definitions) (Workload, Investigation, []Gap) {
	investigation := Investigation{ConsumerID: workload.ID, Source: workload.Source}
	image, err := run.image(ctx, workload.Image)
	if err != nil {
		gap := collectionGap("image_provenance_unavailable", workload.ID, "Image source provenance could not be retrieved")
		investigation.Validation.Gaps = []Gap{gap}
		return workload, investigation, []Gap{gap}
	}
	gaps := slices.Clone(image.Gaps)
	if workload.Source.Repository != "" && workload.Source.Repository != image.Source.Repository {
		gap := collectionGap("image_source_mapping_conflict", workload.ID, "Image source provenance disagrees with the configured application repository")
		investigation.Validation.Gaps = []Gap{gap}
		return workload, investigation, append(gaps, gap)
	}
	pin := image.Source
	if workload.Source.Root != "" {
		pin.Root = workload.Source.Root
	}
	pin.Exact = pin.Exact && image.DeploymentPinned
	if !pin.Exact {
		gaps = append(gaps, collectionGap("image_source_not_exact", workload.ID, "A mutable tag or incomplete image provenance does not establish the deployed application revision"))
	}
	if pin.Repository == "" || pin.Revision == "" {
		gap := collectionGap("application_revision_unresolved", workload.ID, "No immutable application revision was established from the image")
		investigation.Validation.Gaps = []Gap{gap}
		return workload, investigation, append(gaps, gap)
	}
	repository, err := run.repository(ctx, pin)
	if err != nil {
		gap := collectionGap("application_repository_unavailable", workload.ID, "Pinned application source could not be read")
		investigation.Validation.Gaps = []Gap{gap}
		return workload, investigation, append(gaps, gap)
	}
	gaps = append(gaps, repository.Gaps...)
	workload.Source = repository.Pin
	workload.Source.Exact = pin.Exact && repository.Pin.Exact
	workload.ImageDigest = image.Digest
	workload.References = append(slices.Clone(workload.References), image.References...)
	investigation, err = run.ports.Investigator.Investigate(ctx, InvestigationRequest{Workload: workload, Repository: repository, Definitions: definitions})
	if err != nil {
		gap := collectionGap("requirement_investigation_failed", workload.ID, "Source requirement investigation did not complete")
		investigation = Investigation{ConsumerID: workload.ID, Source: workload.Source, Validation: Validation{Gaps: []Gap{gap}}}
		gaps = append(gaps, gap)
	}
	return workload, investigation, gaps
}
