package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/repohistoryscan"
)

func TestMaterializePersistedRepositoryHistoryScans(t *testing.T) {
	store, err := executionstore.NewSQLiteStore(filepath.Join(t.TempDir(), "executions.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	runStore := repohistoryscan.NewSQLiteRunStoreWithExecutionStore(store)
	completedAt := time.Date(2026, 3, 21, 18, 0, 0, 0, time.UTC)
	run := &repohistoryscan.RunRecord{
		ID:          "repo_history_scan:payments",
		Status:      repohistoryscan.RunStatusSucceeded,
		Stage:       repohistoryscan.RunStageCompleted,
		SubmittedAt: completedAt.Add(-10 * time.Minute),
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
		Target: repohistoryscan.ScanTarget{
			RepoURL:    "https://github.com/acme/payments",
			Repository: "acme/payments",
		},
		Descriptor: &repohistoryscan.RepositoryDescriptor{
			RepoURL:    "https://github.com/acme/payments",
			Repository: "acme/payments",
			CommitSHA:  "abc123",
		},
		Analysis: &repohistoryscan.AnalysisReport{
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
	if err := runStore.SaveRun(context.Background(), run); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	graphView := graph.New()
	graphView.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})

	lineageMapper := lineage.NewLineageMapper()
	if _, err := lineageMapper.MapBusinessEntity(context.Background(), map[string]interface{}{
		"entity_id":   "service:payments",
		"entity_type": "service",
		"provider":    "application",
		"repository":  "https://github.com/acme/payments",
		"commit_sha":  "abc123",
	}); err != nil {
		t.Fatalf("MapBusinessEntity() error = %v", err)
	}

	application := &App{
		Config:         &Config{},
		ExecutionStore: store,
		Lineage:        lineageMapper,
	}
	summary, err := application.materializePersistedRepositoryHistoryScans(context.Background(), graphView)
	if err != nil {
		t.Fatalf("materializePersistedRepositoryHistoryScans() error = %v", err)
	}
	if summary.RunsMaterialized != 1 {
		t.Fatalf("expected one materialized run, got %#v", summary)
	}
	if _, ok := graphView.GetNode("https://github.com/acme/payments"); !ok {
		t.Fatal("expected repository node to be materialized")
	}
}
