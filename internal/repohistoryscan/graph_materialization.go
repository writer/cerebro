package repohistoryscan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
)

type GraphMaterializationResult struct {
	RunsConsidered          int `json:"runs_considered"`
	RunsMaterialized        int `json:"runs_materialized"`
	RepositoryNodesUpserted int `json:"repository_nodes_upserted"`
	SecretNodesUpserted     int `json:"secret_nodes_upserted"`
	AuthorNodesUpserted     int `json:"author_nodes_upserted"`
	RepositorySecretEdges   int `json:"repository_secret_edges"`
	AuthorSecretEdges       int `json:"author_secret_edges"`
	ServiceSecretEdges      int `json:"service_secret_edges"`
}

func MaterializeRunsIntoGraph(g *graph.Graph, runs []RunRecord, lineageMapper *lineage.LineageMapper, now time.Time) GraphMaterializationResult {
	result := GraphMaterializationResult{}
	if g == nil || len(runs) == 0 {
		return result
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	for _, run := range runs {
		result.RunsConsidered++
		if run.Status != RunStatusSucceeded || run.Analysis == nil || len(run.Analysis.Findings) == 0 {
			continue
		}
		repoNode := buildRepositoryNode(run, now)
		g.AddNode(repoNode)
		result.RepositoryNodesUpserted++

		for _, finding := range run.Analysis.Findings {
			secretNode := buildLeakedSecretNode(repoNode, finding, now)
			g.AddNode(secretNode)
			result.SecretNodesUpserted++

			if graph.AddEdgeIfMissing(g, &graph.Edge{
				ID:         leakedSecretEdgeID(repoNode.ID, secretNode.ID, graph.EdgeKindHasLeakedSecret),
				Source:     repoNode.ID,
				Target:     secretNode.ID,
				Kind:       graph.EdgeKindHasLeakedSecret,
				Effect:     graph.EdgeEffectAllow,
				Risk:       secretNode.Risk,
				CreatedAt:  now.UTC(),
				Properties: map[string]any{"commit_sha": strings.TrimSpace(finding.CommitSHA)},
			}) {
				result.RepositorySecretEdges++
			}

			if authorNode, ok := buildAuthorNode(finding, now); ok {
				g.AddNode(authorNode)
				result.AuthorNodesUpserted++
				if graph.AddEdgeIfMissing(g, &graph.Edge{
					ID:        leakedSecretEdgeID(secretNode.ID, authorNode.ID, graph.EdgeKindOriginatedFrom),
					Source:    secretNode.ID,
					Target:    authorNode.ID,
					Kind:      graph.EdgeKindOriginatedFrom,
					Effect:    graph.EdgeEffectAllow,
					Risk:      secretNode.Risk,
					CreatedAt: now.UTC(),
				}) {
					result.AuthorSecretEdges++
				}
			}

			for _, assetID := range affectedAssetIDs(lineageMapper, repoNode.ID, finding) {
				if _, ok := g.GetNode(assetID); !ok {
					continue
				}
				if graph.AddEdgeIfMissing(g, &graph.Edge{
					ID:         leakedSecretEdgeID(secretNode.ID, assetID, graph.EdgeKindTargets),
					Source:     secretNode.ID,
					Target:     assetID,
					Kind:       graph.EdgeKindTargets,
					Effect:     graph.EdgeEffectAllow,
					Risk:       secretNode.Risk,
					CreatedAt:  now.UTC(),
					Properties: map[string]any{"reason": "deployment_lineage"},
				}) {
					result.ServiceSecretEdges++
				}
			}
		}
		result.RunsMaterialized++
	}

	g.BuildIndex()
	return result
}

func buildRepositoryNode(run RunRecord, now time.Time) *graph.Node {
	repoID := repositoryNodeID(run)
	name := strings.TrimSpace(run.Target.Repository)
	if run.Descriptor != nil && strings.TrimSpace(run.Descriptor.Repository) != "" {
		name = strings.TrimSpace(run.Descriptor.Repository)
	}
	if name == "" {
		name = repoID
	}
	properties := map[string]any{
		"url":        repoID,
		"repository": name,
	}
	if run.Descriptor != nil && strings.TrimSpace(run.Descriptor.CommitSHA) != "" {
		properties["commit_sha"] = strings.TrimSpace(run.Descriptor.CommitSHA)
	}
	return &graph.Node{
		ID:         repoID,
		Kind:       graph.NodeKindRepository,
		Name:       name,
		Provider:   "scm",
		Risk:       graph.RiskMedium,
		CreatedAt:  now.UTC(),
		UpdatedAt:  now.UTC(),
		Properties: properties,
	}
}

func buildLeakedSecretNode(repoNode *graph.Node, finding filesystemanalyzer.GitHistoryFinding, now time.Time) *graph.Node {
	properties := map[string]any{
		"finding_id":          strings.TrimSpace(finding.ID),
		"secret_type":         strings.TrimSpace(finding.Type),
		"severity":            strings.TrimSpace(finding.Severity),
		"match_fingerprint":   strings.TrimSpace(finding.Match),
		"path":                strings.TrimSpace(finding.Path),
		"line":                finding.Line,
		"commit_sha":          strings.TrimSpace(finding.CommitSHA),
		"author_name":         strings.TrimSpace(finding.AuthorName),
		"author_email":        strings.TrimSpace(finding.AuthorEmail),
		"verification_status": strings.TrimSpace(finding.VerificationStatus),
		"repository_id":       repoNode.ID,
		"repository_name":     repoNode.Name,
		"committed_at":        formatHistoryTime(finding.CommittedAt),
	}
	if strings.TrimSpace(finding.Description) != "" {
		properties["description"] = strings.TrimSpace(finding.Description)
	}
	if len(finding.References) > 0 {
		properties["references"] = secretReferenceMaps(finding.References)
	}
	return &graph.Node{
		ID:         leakedSecretNodeID(repoNode.ID, finding),
		Kind:       graph.NodeKindSecret,
		Name:       leakedSecretName(finding),
		Provider:   repoNode.Provider,
		Account:    repoNode.Account,
		Region:     repoNode.Region,
		Risk:       leakedSecretRisk(finding.Severity),
		CreatedAt:  now.UTC(),
		UpdatedAt:  now.UTC(),
		Properties: properties,
	}
}

func buildAuthorNode(finding filesystemanalyzer.GitHistoryFinding, now time.Time) (*graph.Node, bool) {
	email := strings.ToLower(strings.TrimSpace(finding.AuthorEmail))
	if email == "" {
		return nil, false
	}
	name := strings.TrimSpace(finding.AuthorName)
	if name == "" {
		name = email
	}
	return &graph.Node{
		ID:        "person:" + email,
		Kind:      graph.NodeKindPerson,
		Name:      name,
		Provider:  "scm",
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
		Properties: map[string]any{
			"email": email,
		},
	}, true
}

func affectedAssetIDs(mapper *lineage.LineageMapper, repoID string, finding filesystemanalyzer.GitHistoryFinding) []string {
	if mapper == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	appendAssets := func(assets []*lineage.AssetLineage) {
		for _, asset := range assets {
			if asset == nil {
				continue
			}
			assetID := strings.TrimSpace(asset.AssetID)
			if assetID == "" {
				continue
			}
			if _, ok := seen[assetID]; ok {
				continue
			}
			seen[assetID] = struct{}{}
			out = append(out, assetID)
		}
	}
	if commitSHA := strings.TrimSpace(finding.CommitSHA); commitSHA != "" {
		appendAssets(mapper.GetLineageByCommit(commitSHA))
	}
	appendAssets(mapper.GetLineageByRepository(repoID))
	return out
}

func repositoryNodeID(run RunRecord) string {
	for _, candidate := range []string{
		func() string {
			if run.Descriptor != nil {
				return sanitizeRepositoryURL(run.Descriptor.RepoURL)
			}
			return ""
		}(),
		sanitizeRepositoryURL(run.Target.RepoURL),
		func() string {
			if run.Descriptor != nil {
				return strings.TrimSpace(run.Descriptor.Repository)
			}
			return ""
		}(),
		strings.TrimSpace(run.Target.Repository),
	} {
		if trimmed := strings.TrimSpace(candidate); trimmed != "" {
			return trimmed
		}
	}
	return "repository:unknown"
}

func leakedSecretNodeID(repoID string, finding filesystemanalyzer.GitHistoryFinding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(repoID),
		strings.TrimSpace(finding.CommitSHA),
		strings.TrimSpace(finding.Path),
		fmt.Sprintf("%d", finding.Line),
		strings.TrimSpace(finding.Type),
		strings.TrimSpace(finding.Match),
	}, "|")))
	return "secret:leaked:" + hex.EncodeToString(sum[:8])
}

func leakedSecretEdgeID(sourceID, targetID string, kind graph.EdgeKind) string {
	sum := sha256.Sum256([]byte(sourceID + "|" + targetID + "|" + string(kind)))
	return "edge:" + hex.EncodeToString(sum[:8]) + ":" + string(kind)
}

func leakedSecretName(finding filesystemanalyzer.GitHistoryFinding) string {
	if finding.Line > 0 && strings.TrimSpace(finding.Path) != "" {
		return fmt.Sprintf("%s %s:%d", firstNonEmpty(strings.TrimSpace(finding.Type), "secret"), strings.TrimSpace(finding.Path), finding.Line)
	}
	if strings.TrimSpace(finding.Path) != "" {
		return fmt.Sprintf("%s %s", firstNonEmpty(strings.TrimSpace(finding.Type), "secret"), strings.TrimSpace(finding.Path))
	}
	return firstNonEmpty(strings.TrimSpace(finding.Type), "secret")
}

func leakedSecretRisk(severity string) graph.RiskLevel {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return graph.RiskCritical
	case "high":
		return graph.RiskHigh
	case "low":
		return graph.RiskLow
	default:
		return graph.RiskMedium
	}
}

func formatHistoryTime(ts *time.Time) string {
	if ts == nil || ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}

func secretReferenceMaps(refs []filesystemanalyzer.SecretReference) []any {
	if len(refs) == 0 {
		return nil
	}
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		entry := map[string]any{"kind": ref.Kind}
		if ref.Provider != "" {
			entry["provider"] = ref.Provider
		}
		if ref.Identifier != "" {
			entry["identifier"] = ref.Identifier
		}
		if ref.Host != "" {
			entry["host"] = ref.Host
		}
		if ref.Port > 0 {
			entry["port"] = ref.Port
		}
		if ref.Database != "" {
			entry["database"] = ref.Database
		}
		if len(ref.Attributes) > 0 {
			attributes := make(map[string]any, len(ref.Attributes))
			for key, value := range ref.Attributes {
				attributes[key] = value
			}
			entry["attributes"] = attributes
		}
		out = append(out, entry)
	}
	return out
}
