package cloudidentity

import (
	"context"
	"fmt"
	"sort"
	"time"
)

type collectionRun struct {
	ports        CollectionPorts
	now          time.Time
	repositories map[string]repositoryResult
	images       map[string]imageResult
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
	for _, cohort := range collectionResolvedCohorts(observed) {
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
		rendered, gaps, err := run.ports.Manifests.Render(ctx, ManifestRequest{Repository: repository, Paths: input.Paths, Chart: input.Chart, ValuesFiles: input.ValuesFiles, Values: input.Values, Release: input.Release, Namespace: input.Namespace, Environment: target.Environment, Cluster: target.Cluster, Applications: input.Applications})
		result.inventoryGaps = append(result.inventoryGaps, gaps...)
		if err != nil {
			result.inventoryGaps = append(result.inventoryGaps, collectionGap("manifest_render_failed", target.Name, "Manifest rendering did not complete"))
		}
		manifests = append(manifests, rendered...)
	}
	// Claims and the Compositions/EnvironmentConfigs that expand them are
	// usually deployed by different charts, so composition runs per target.
	composed, composeGaps, err := run.ports.Manifests.Compose(ctx, ComposeRequest{Manifests: manifests, Environment: target.Environment, Cluster: target.Cluster})
	result.inventoryGaps = append(result.inventoryGaps, composeGaps...)
	if err != nil {
		result.inventoryGaps = append(result.inventoryGaps, collectionGap("manifest_composition_failed", target.Name, "Crossplane composition expansion did not complete"))
	}
	manifests = append(manifests, composed...)
	workloads, gaps := Inventory(InventoryRequest{Manifests: manifests, Environment: target.Environment, Cluster: target.Cluster, Region: target.Region, Provider: target.Provider, Project: target.Project, Account: target.Account, Services: services})
	result.workloads = workloads
	result.inventoryGaps = append(result.inventoryGaps, gaps...)
	crossplane, declarationGaps := DeclarationsFromManifests(manifests, target.Account, target.Project)
	result.declarations = append(result.declarations, crossplane...)
	result.declarationGaps = append(result.declarationGaps, declarationGaps...)
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
		declarations, gaps, err := run.ports.Declarations.ReadDeclarations(ctx, TerraformInput{Repository: repository, Root: root.Root, Variables: root.Variables, Account: target.Account, Project: target.Project, Region: root.Region, ResolvedIdentifiers: identifiers, MetadataBindings: root.MetadataBindings})
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
