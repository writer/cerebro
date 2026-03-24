package imagescan

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
)

const imageScanGraphSourceSystem = "cerebro_image_scan"

const (
	graphNodeKindContainerImage    graph.NodeKind = "container_image"
	graphNodeKindContainerRegistry graph.NodeKind = "container_registry"
)

type ImageLineageResolver interface {
	GetLineageByImageDigest(digest string) []*lineage.AssetLineage
	GetLineageByImageURI(uri string) []*lineage.AssetLineage
}

type GraphMaterializationResult struct {
	RunsConsidered        int `json:"runs_considered"`
	RunsMaterialized      int `json:"runs_materialized"`
	RunsSkipped           int `json:"runs_skipped"`
	RegistryNodesUpserted int `json:"registry_nodes_upserted"`
	ImageNodesUpserted    int `json:"image_nodes_upserted"`
	ObservationNodes      int `json:"observation_nodes"`
	RuntimeLinksCreated   int `json:"runtime_links_created"`
	RegistryLinksCreated  int `json:"registry_links_created"`
}

type imageAggregate struct {
	run        RunRecord
	observedAt time.Time
	tags       map[string]struct{}
}

func init() {
	_, _ = graph.RegisterNodeKindDefinition(graph.NodeKindDefinition{
		Kind:        graphNodeKindContainerRegistry,
		Categories:  []graph.NodeKindCategory{graph.NodeCategoryResource},
		Description: "Container registry discovered through image scanning.",
	})
	_, _ = graph.RegisterNodeKindDefinition(graph.NodeKindDefinition{
		Kind:        graphNodeKindContainerImage,
		Categories:  []graph.NodeKindCategory{graph.NodeCategoryResource},
		Description: "Container image observed through image scanning.",
	})
}

func MaterializeRunsIntoGraph(g *graph.Graph, resolver ImageLineageResolver, runs []RunRecord, now time.Time) GraphMaterializationResult {
	result := GraphMaterializationResult{}
	if g == nil || len(runs) == 0 {
		return result
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	aggregates := make(map[string]*imageAggregate)
	for _, run := range runs {
		result.RunsConsidered++
		digest := imageDigest(run)
		if run.Status != RunStatusSucceeded || digest == "" {
			result.RunsSkipped++
			continue
		}
		key := imageAggregateKey(run.Target.RegistryHost, run.Target.Repository, digest)
		if key == "" {
			result.RunsSkipped++
			continue
		}
		observed := observedAt(run)
		if observed.IsZero() {
			observed = now.UTC()
		}
		aggregate, ok := aggregates[key]
		if !ok {
			aggregate = &imageAggregate{
				run:        run,
				observedAt: observed,
				tags:       map[string]struct{}{},
			}
			aggregates[key] = aggregate
		}
		if tag := strings.TrimSpace(run.Target.Tag); tag != "" {
			aggregate.tags[tag] = struct{}{}
		}
		if aggregateOlderThan(*aggregate, observed, run.ID) {
			aggregate.run = run
			aggregate.observedAt = observed
		}
	}

	for _, aggregate := range aggregates {
		run := aggregate.run
		tags := sortedTagSet(aggregate.tags)
		host := normalizeRegistryHost(run.Target.RegistryHost)

		registryID := ""
		if host != "" {
			registryID = registryNodeID(host)
			g.AddNode(&graph.Node{
				ID:       registryID,
				Kind:     graphNodeKindContainerRegistry,
				Name:     host,
				Provider: string(run.Registry),
				Properties: map[string]any{
					"host":     host,
					"registry": string(run.Registry),
				},
				Risk: graph.RiskNone,
			})
			result.RegistryNodesUpserted++
		}

		imageID := imageNodeID(host, run.Target.Repository, imageDigest(run))
		imageNode := &graph.Node{
			ID:       imageID,
			Kind:     graphNodeKindContainerImage,
			Name:     imageDisplayName(run.Target.Repository, imageDigest(run)),
			Provider: string(run.Registry),
			Risk:     riskFromRun(run),
			Properties: map[string]any{
				"registry":              string(run.Registry),
				"registry_host":         host,
				"repository":            strings.TrimSpace(run.Target.Repository),
				"digest":                imageDigest(run),
				"tags":                  tags,
				"last_scan_run_id":      strings.TrimSpace(run.ID),
				"last_scanned_at":       aggregate.observedAt.UTC().Format(time.RFC3339Nano),
				"vulnerability_count":   vulnCount(run.Analysis),
				"native_vuln_count":     nativeVulnCount(run.Analysis),
				"filesystem_vuln_count": filesystemVulnCount(run.Analysis),
				"os":                    imageOS(run.Analysis),
				"architecture":          imageArchitecture(run.Analysis),
			},
		}
		g.AddNode(imageNode)
		result.ImageNodesUpserted++

		if registryID != "" && graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", imageID, registryID, graph.EdgeKindLocatedIn),
			Source: imageID,
			Target: registryID,
			Kind:   graph.EdgeKindLocatedIn,
			Effect: graph.EdgeEffectAllow,
		}) {
			result.RegistryLinksCreated++
		}

		if _, err := graph.WriteObservation(g, graph.ObservationWriteRequest{
			ID:              fmt.Sprintf("image_scan_observation:%s", sanitizeImageGraphComponent(imageID)),
			SubjectID:       imageID,
			ObservationType: "image_scan_summary",
			Summary:         "Container image scan summary",
			SourceSystem:    imageScanGraphSourceSystem,
			SourceEventID:   firstNonEmpty(strings.TrimSpace(run.ID), imageID),
			ObservedAt:      aggregate.observedAt,
			ValidFrom:       aggregate.observedAt,
			Confidence:      0.95,
			Metadata: map[string]any{
				"run_id":                strings.TrimSpace(run.ID),
				"repository":            strings.TrimSpace(run.Target.Repository),
				"digest":                imageDigest(run),
				"tags":                  tags,
				"registry":              string(run.Registry),
				"registry_host":         host,
				"vulnerability_count":   vulnCount(run.Analysis),
				"native_vuln_count":     nativeVulnCount(run.Analysis),
				"filesystem_vuln_count": filesystemVulnCount(run.Analysis),
			},
		}); err == nil {
			result.ObservationNodes++
		}

		result.RuntimeLinksCreated += linkRuntimeAssets(g, resolver, imageNode, run, tags)
		result.RunsMaterialized++
	}

	g.BuildIndex()
	meta := g.Metadata()
	if meta.BuiltAt.IsZero() {
		meta.BuiltAt = now.UTC()
	}
	meta.NodeCount = g.NodeCount()
	meta.EdgeCount = g.EdgeCount()
	g.SetMetadata(meta)
	return result
}

func linkRuntimeAssets(g *graph.Graph, resolver ImageLineageResolver, imageNode *graph.Node, run RunRecord, tags []string) int {
	if g == nil || resolver == nil || imageNode == nil {
		return 0
	}
	matches := make(map[string]string)
	if digest := imageDigest(run); digest != "" {
		for _, asset := range resolver.GetLineageByImageDigest(digest) {
			if asset == nil || strings.TrimSpace(asset.AssetID) == "" {
				continue
			}
			matches[asset.AssetID] = "digest"
		}
	}
	for _, candidate := range imageURIResolverCandidates(run, tags) {
		for _, asset := range resolver.GetLineageByImageURI(candidate) {
			if asset == nil || strings.TrimSpace(asset.AssetID) == "" {
				continue
			}
			if _, ok := matches[asset.AssetID]; !ok {
				matches[asset.AssetID] = "image_uri"
			}
		}
	}
	created := 0
	for assetID, matchKind := range matches {
		if _, ok := g.GetNode(assetID); !ok {
			continue
		}
		if graph.AddEdgeIfMissing(g, &graph.Edge{
			ID:     fmt.Sprintf("%s->%s:%s", assetID, imageNode.ID, graph.EdgeKindDeployedFrom),
			Source: assetID,
			Target: imageNode.ID,
			Kind:   graph.EdgeKindDeployedFrom,
			Effect: graph.EdgeEffectAllow,
			Properties: map[string]any{
				"match_kind":   matchKind,
				"image_digest": imageDigest(run),
			},
		}) {
			created++
		}
	}
	return created
}

func aggregateOlderThan(aggregate imageAggregate, observedAt time.Time, runID string) bool {
	if !aggregate.observedAt.Equal(observedAt) {
		return aggregate.observedAt.Before(observedAt)
	}
	return strings.TrimSpace(aggregate.run.ID) < strings.TrimSpace(runID)
}

func imageAggregateKey(host, repository, digest string) string {
	repository = strings.TrimSpace(repository)
	digest = strings.TrimSpace(digest)
	if repository == "" || digest == "" {
		return ""
	}
	host = normalizeRegistryHost(host)
	if host == "" {
		return repository + "@" + digest
	}
	return host + "/" + repository + "@" + digest
}

func imageNodeID(host, repository, digest string) string {
	return "container_image:" + sanitizeImageGraphComponent(imageAggregateKey(host, repository, digest))
}

func registryNodeID(host string) string {
	return "container_registry:" + sanitizeImageGraphComponent(normalizeRegistryHost(host))
}

func imageDisplayName(repository, digest string) string {
	repository = strings.TrimSpace(repository)
	digest = strings.TrimSpace(digest)
	if repository == "" {
		return digest
	}
	if digest == "" {
		return repository
	}
	return repository + "@" + digest
}

func sanitizeImageGraphComponent(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer("/", "_", ":", "_", "@", "_", " ", "_")
	return replacer.Replace(value)
}

func observedAt(run RunRecord) time.Time {
	if run.CompletedAt != nil && !run.CompletedAt.IsZero() {
		return run.CompletedAt.UTC()
	}
	if run.StartedAt != nil && !run.StartedAt.IsZero() {
		return run.StartedAt.UTC()
	}
	if !run.UpdatedAt.IsZero() {
		return run.UpdatedAt.UTC()
	}
	if !run.SubmittedAt.IsZero() {
		return run.SubmittedAt.UTC()
	}
	return time.Time{}
}

func imageDigest(run RunRecord) string {
	if digest := strings.TrimSpace(run.Target.Digest); digest != "" {
		return digest
	}
	if run.Manifest != nil {
		return strings.TrimSpace(run.Manifest.Digest)
	}
	return ""
}

func imageURIResolverCandidates(run RunRecord, tags []string) []string {
	repository := strings.TrimSpace(run.Target.Repository)
	if repository == "" {
		return nil
	}
	host := normalizeRegistryHost(run.Target.RegistryHost)
	bases := []string{repository}
	if host != "" {
		bases = append(bases, host+"/"+repository)
	}
	if host == "docker.io" && !strings.Contains(repository, "/") {
		bases = append(bases, "library/"+repository, "docker.io/library/"+repository)
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(bases)*(len(tags)+1))
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if digest := imageDigest(run); digest != "" {
		for _, base := range bases {
			add(base + "@" + digest)
		}
	}
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "" {
			continue
		}
		for _, base := range bases {
			add(base + ":" + strings.TrimSpace(tag))
		}
	}
	return out
}

func sortedTagSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func vulnCount(report *AnalysisReport) int {
	if report == nil {
		return 0
	}
	return report.Result.Summary.Total
}

func nativeVulnCount(report *AnalysisReport) int {
	if report == nil {
		return 0
	}
	return report.NativeVulnerabilityCount
}

func filesystemVulnCount(report *AnalysisReport) int {
	if report == nil {
		return 0
	}
	return report.FilesystemVulnerabilityCount
}

func imageOS(report *AnalysisReport) string {
	if report == nil {
		return ""
	}
	return strings.TrimSpace(report.Result.OS)
}

func imageArchitecture(report *AnalysisReport) string {
	if report == nil {
		return ""
	}
	return strings.TrimSpace(report.Result.Architecture)
}

func riskFromRun(run RunRecord) graph.RiskLevel {
	if run.Analysis == nil {
		return graph.RiskNone
	}
	summary := run.Analysis.Result.Summary
	switch {
	case summary.Critical > 0:
		return graph.RiskCritical
	case summary.High > 0:
		return graph.RiskHigh
	case summary.Medium > 0:
		return graph.RiskMedium
	case summary.Low > 0 || summary.Unknown > 0:
		return graph.RiskLow
	default:
		return graph.RiskNone
	}
}
