package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/workloadscan"
)

type workloadScanCandidateSource struct{}

func (s *workloadScanCandidateSource) Query(ctx context.Context, query string, args ...any) (*builders.DataQueryResult, error) {
	_ = ctx
	_ = args
	if strings.Contains(strings.ToLower(query), "from aws_ec2_instances") {
		return &builders.DataQueryResult{Rows: []map[string]any{{
			"arn":                  "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
			"instance_id":          "i-abc123",
			"account_id":           "123456789012",
			"region":               "us-east-1",
			"public_ip_address":    "",
			"iam_instance_profile": "",
		}}}, nil
	}
	return &builders.DataQueryResult{Rows: []map[string]any{}}, nil
}

func TestBuildGraphConsistencyCandidateMaterializesPersistedWorkloadScans(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stateFile := filepath.Join(t.TempDir(), "workload-scan.db")
	store, err := workloadscan.NewSQLiteRunStore(stateFile)
	if err != nil {
		t.Fatalf("NewSQLiteRunStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	startedAt := time.Date(2026, 3, 12, 15, 45, 0, 0, time.UTC)
	completedAt := startedAt.Add(15 * time.Minute)
	run := &workloadscan.RunRecord{
		ID:       "workload_scan:consistency",
		Provider: workloadscan.ProviderAWS,
		Status:   workloadscan.RunStatusSucceeded,
		Stage:    workloadscan.RunStageCompleted,
		Target: workloadscan.VMTarget{
			Provider:   workloadscan.ProviderAWS,
			AccountID:  "123456789012",
			Region:     "us-east-1",
			InstanceID: "i-abc123",
		},
		SubmittedAt: startedAt,
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
		UpdatedAt:   completedAt,
		Summary: workloadscan.RunSummary{
			VolumeCount:      1,
			SucceededVolumes: 1,
			Findings:         1,
		},
		Volumes: []workloadscan.VolumeScanRecord{{
			Source:      workloadscan.SourceVolume{ID: "vol-1"},
			Status:      workloadscan.RunStatusSucceeded,
			Stage:       workloadscan.RunStageCompleted,
			StartedAt:   startedAt,
			UpdatedAt:   completedAt,
			CompletedAt: &completedAt,
			Analysis: &workloadscan.AnalysisReport{
				FindingCount: 1,
				Catalog: &filesystemanalyzer.Report{
					OS: filesystemanalyzer.OSInfo{Name: "Ubuntu", Version: "22.04", Architecture: "amd64"},
					Packages: []filesystemanalyzer.PackageRecord{{
						Ecosystem: "deb",
						Name:      "openssl",
						Version:   "3.0.2-0ubuntu1.10",
						PURL:      "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10",
					}},
					Vulnerabilities: []scanner.ImageVulnerability{{
						CVE:              "CVE-2026-0001",
						Severity:         "HIGH",
						Package:          "openssl",
						InstalledVersion: "3.0.2-0ubuntu1.10",
						FixedVersion:     "3.0.2-0ubuntu1.12",
					}},
				},
			},
		}},
	}
	if err := store.SaveRun(ctx, run); err != nil {
		t.Fatalf("SaveRun: %v", err)
	}

	application := &App{
		Config:               &Config{WorkloadScanStateFile: stateFile},
		Logger:               logger,
		SecurityGraphBuilder: builders.NewBuilder(&workloadScanCandidateSource{}, logger),
	}

	candidate, err := application.buildGraphConsistencyCandidate(ctx)
	if err != nil {
		t.Fatalf("buildGraphConsistencyCandidate: %v", err)
	}
	if candidate == nil {
		t.Fatal("expected candidate graph")
	}
	if _, ok := candidate.GetNode(run.ID); !ok {
		t.Fatalf("expected materialized workload scan node %q", run.ID)
	}
	if edge := findGraphOutEdge(candidate, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", graph.EdgeKindHasScan, run.ID); edge == nil {
		t.Fatalf("expected has_scan edge for materialized run, got %#v", candidate.GetOutEdges("arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"))
	}
}

func findGraphOutEdge(g *graph.Graph, source string, kind graph.EdgeKind, target string) *graph.Edge {
	for _, edge := range g.GetOutEdges(source) {
		if edge != nil && edge.Kind == kind && edge.Target == target {
			return edge
		}
	}
	return nil
}
