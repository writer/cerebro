package repohistoryscan

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
)

func TestMaterializeRunsIntoGraphLinksRepositorySecretsAuthorsAndServices(t *testing.T) {
	now := time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC)
	completedAt := now.Add(-10 * time.Minute)

	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "service:payments",
		Kind:     graph.NodeKindService,
		Name:     "Payments",
		Provider: "application",
	})

	mapper := lineage.NewLineageMapper()
	if _, err := mapper.MapBusinessEntity(context.Background(), map[string]interface{}{
		"entity_id":   "service:payments",
		"entity_type": "service",
		"provider":    "application",
		"repository":  "https://github.com/acme/payments",
		"commit_sha":  "abc123",
	}); err != nil {
		t.Fatalf("MapBusinessEntity: %v", err)
	}

	run := RunRecord{
		ID:          "repo_history_scan:payments",
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		SubmittedAt: now.Add(-15 * time.Minute),
		CompletedAt: &completedAt,
		Target: ScanTarget{
			RepoURL:    "https://github.com/acme/payments",
			Repository: "acme/payments",
		},
		Descriptor: &RepositoryDescriptor{
			RepoURL:    "https://github.com/acme/payments",
			Repository: "acme/payments",
			CommitSHA:  "abc123",
		},
		Analysis: &AnalysisReport{
			Engine: "gitleaks+trufflehog",
			Findings: []filesystemanalyzer.GitHistoryFinding{{
				ID:                 "finding-1",
				Type:               "aws_access_key",
				Severity:           "critical",
				Path:               "keys.env",
				Line:               4,
				Match:              "sha256:deadbeef",
				CommitSHA:          "abc123",
				AuthorName:         "Alice Example",
				AuthorEmail:        "alice@example.com",
				Verified:           true,
				VerificationStatus: "verified_active",
			}},
		},
	}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, mapper, now)
	if summary.SecretNodesUpserted != 1 {
		t.Fatalf("expected one secret node upsert, got %#v", summary)
	}

	repoNode, ok := g.GetNode("https://github.com/acme/payments")
	if !ok || repoNode == nil || repoNode.Kind != graph.NodeKindRepository {
		t.Fatalf("expected repository node to be materialized, got %#v", repoNode)
	}

	var (
		secretNodeID  string
		foundRepoEdge bool
	)
	for _, edge := range g.GetOutEdges(repoNode.ID) {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindHasLeakedSecret {
			foundRepoEdge = true
			secretNodeID = edge.Target
			break
		}
	}
	if !foundRepoEdge {
		t.Fatalf("expected repository leaked secret edge, got %#v", g.GetOutEdges(repoNode.ID))
	}

	secretNode, ok := g.GetNode(secretNodeID)
	if !ok || secretNode == nil || secretNode.Kind != graph.NodeKindSecret {
		t.Fatalf("expected secret node, got %#v", secretNode)
	}
	if got := secretNode.Properties["verification_status"]; got != "verified_active" {
		t.Fatalf("expected verification status to persist, got %#v", secretNode.Properties)
	}

	personNode, ok := g.GetNode("person:alice@example.com")
	if !ok || personNode == nil || personNode.Kind != graph.NodeKindPerson {
		t.Fatalf("expected author person node, got %#v", personNode)
	}

	foundAuthorEdge := false
	foundServiceEdge := false
	for _, edge := range g.GetOutEdges(secretNode.ID) {
		if edge == nil {
			continue
		}
		if edge.Kind == graph.EdgeKindOriginatedFrom && edge.Target == "person:alice@example.com" {
			foundAuthorEdge = true
		}
		if edge.Kind == graph.EdgeKindTargets && edge.Target == "service:payments" {
			foundServiceEdge = true
		}
	}
	if !foundAuthorEdge {
		t.Fatalf("expected secret -> author linkage, got %#v", g.GetOutEdges(secretNode.ID))
	}
	if !foundServiceEdge {
		t.Fatalf("expected secret -> service linkage, got %#v", g.GetOutEdges(secretNode.ID))
	}
}
