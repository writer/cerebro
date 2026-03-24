package reposcan

import (
	"context"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
)

const repoScanGraphSourceSystem = "cerebro_repo_scan"

func (r *Runner) integrateGraph(_ context.Context, run *RunRecord) (*GraphIntegration, error) {
	if r == nil || r.graph == nil || r.lineage == nil || run == nil || run.Analysis == nil || run.Analysis.Catalog == nil {
		return nil, nil
	}
	if len(run.Analysis.Catalog.Misconfigurations) == 0 {
		return nil, nil
	}

	linkedAssets := linkedRuntimeAssets(r.lineage, run)
	if len(linkedAssets) == 0 {
		return nil, nil
	}

	integration := &GraphIntegration{
		Links: make([]GraphLink, 0, len(linkedAssets)),
	}
	observedAt := r.now().UTC()
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		observedAt = run.CompletedAt.UTC()
	}
	for _, asset := range linkedAssets {
		if asset == nil || strings.TrimSpace(asset.AssetID) == "" {
			continue
		}
		if _, ok := r.graph.GetNode(asset.AssetID); !ok {
			continue
		}

		link := GraphLink{
			AssetID:   asset.AssetID,
			AssetType: asset.AssetType,
			AssetName: asset.AssetName,
			Provider:  asset.Provider,
			Region:    asset.Region,
			MatchedBy: linkMatchKind(run, asset),
		}
		for _, finding := range run.Analysis.Catalog.Misconfigurations {
			observationID := repoFindingObservationID(run.ID, asset.AssetID, finding.ID)
			result, err := graph.WriteObservation(r.graph, graph.ObservationWriteRequest{
				ID:              observationID,
				SubjectID:       asset.AssetID,
				ObservationType: "repo_iac_finding",
				Summary:         firstNonEmpty(strings.TrimSpace(finding.Title), strings.TrimSpace(finding.Type)),
				SourceSystem:    repoScanGraphSourceSystem,
				SourceEventID:   run.ID,
				ObservedAt:      observedAt,
				ValidFrom:       observedAt,
				Confidence:      0.95,
				Metadata: map[string]any{
					"run_id":        run.ID,
					"repository":    repositoryName(run),
					"repo_url":      repositoryURL(run),
					"commit_sha":    commitSHA(run),
					"finding_id":    finding.ID,
					"finding_type":  finding.Type,
					"severity":      finding.Severity,
					"file_path":     finding.Path,
					"line":          finding.Line,
					"end_line":      finding.EndLine,
					"resource_type": finding.ResourceType,
					"artifact_type": finding.ArtifactType,
					"format":        finding.Format,
				},
			})
			if err != nil {
				return nil, err
			}
			link.ObservationID = result.ObservationID
			integration.ObservationCount++
		}
		integration.Links = append(integration.Links, link)
		integration.LinkedResources++
	}

	if integration.LinkedResources == 0 {
		return nil, nil
	}
	r.graph.BuildIndex()
	return integration, nil
}

func linkedRuntimeAssets(resolver LineageResolver, run *RunRecord) []*lineage.AssetLineage {
	if resolver == nil || run == nil {
		return nil
	}
	seen := make(map[string]*lineage.AssetLineage)
	addMatches := func(items []*lineage.AssetLineage) {
		for _, item := range items {
			if item == nil || strings.TrimSpace(item.AssetID) == "" {
				continue
			}
			if _, ok := seen[item.AssetID]; ok {
				continue
			}
			seen[item.AssetID] = item
		}
	}

	if commit := commitSHA(run); commit != "" {
		addMatches(resolver.GetLineageByCommit(commit))
	}
	for _, candidate := range repositoryCandidates(run) {
		addMatches(resolver.GetLineageByRepository(candidate))
	}

	assets := make([]*lineage.AssetLineage, 0, len(seen))
	for _, asset := range seen {
		assets = append(assets, asset)
	}
	return assets
}

func repositoryCandidates(run *RunRecord) []string {
	if run == nil {
		return nil
	}
	values := []string{
		repositoryName(run),
		repositoryURL(run),
		inferRepositoryName(repositoryURL(run)),
		strings.TrimSpace(run.Target.Repository),
		strings.TrimSpace(run.Target.RepoURL),
		inferRepositoryName(run.Target.RepoURL),
	}
	seen := make(map[string]struct{})
	candidates := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			candidates = append(candidates, trimmed)
		}
	}
	return candidates
}

func repositoryName(run *RunRecord) string {
	if run != nil && run.Descriptor != nil {
		if repository := strings.TrimSpace(run.Descriptor.Repository); repository != "" {
			return repository
		}
	}
	if run != nil {
		return strings.TrimSpace(run.Target.Repository)
	}
	return ""
}

func repositoryURL(run *RunRecord) string {
	if run != nil && run.Descriptor != nil {
		if repoURL := strings.TrimSpace(run.Descriptor.RepoURL); repoURL != "" {
			return repoURL
		}
	}
	if run != nil {
		return strings.TrimSpace(run.Target.RepoURL)
	}
	return ""
}

func commitSHA(run *RunRecord) string {
	if run == nil || run.Descriptor == nil {
		return ""
	}
	return strings.TrimSpace(run.Descriptor.CommitSHA)
}

func repoFindingObservationID(runID, assetID, findingID string) string {
	return fmt.Sprintf("repo_scan_observation:%s:%s:%s", sanitizeRunID(runID), sanitizeRunID(assetID), sanitizeRunID(findingID))
}

func linkMatchKind(run *RunRecord, asset *lineage.AssetLineage) string {
	if asset == nil {
		return ""
	}
	if commit := commitSHA(run); commit != "" && strings.EqualFold(strings.TrimSpace(asset.CommitSHA), commit) {
		return "commit"
	}
	return "repository"
}
