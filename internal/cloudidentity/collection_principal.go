package cloudidentity

import (
	"context"
	"slices"
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
	evidence.Gaps = append(evidence.Gaps, observation.Gaps...)
	if err != nil {
		evidence.Observed.Complete = false
		evidence.Observed.Gaps = append(evidence.Observed.Gaps, collectionGap("cloud_observation_failed", evidence.Principal.ID, "Live IAM observation did not complete"))
	}
	evidence.Definitions = observation.Definitions
	return evidence
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
