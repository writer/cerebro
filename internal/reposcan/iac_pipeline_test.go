package reposcan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/lineage"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scm"
)

type fakeConfigScanner struct {
	result *scanner.ConfigScanResult
	err    error
}

func (s fakeConfigScanner) ScanConfig(context.Context, string) (*scanner.ConfigScanResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type fakeAnalyzer struct {
	report *AnalysisReport
	err    error
}

func (a fakeAnalyzer) Analyze(context.Context, AnalysisInput) (*AnalysisReport, error) {
	if a.err != nil {
		return nil, a.err
	}
	return a.report, nil
}

func TestLocalMaterializerShallowClonesRepository(t *testing.T) {
	repoURL, _, head := createIncrementalIaCTestRepo(t)
	materializer := NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient(""))

	descriptor, checkout, err := materializer.Materialize(context.Background(), "repo_scan:shallow", ScanTarget{RepoURL: repoURL})
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if descriptor == nil || descriptor.CommitSHA != head {
		t.Fatalf("expected head commit %q, got %#v", head, descriptor)
	}
	if checkout == nil {
		t.Fatal("expected checkout artifact")
	}
	if count := strings.TrimSpace(runGitOutput(t, checkout.Path, "rev-list", "--count", "HEAD")); count != "1" {
		t.Fatalf("expected shallow clone with one visible commit, got %q", count)
	}
}

func TestFilesystemAnalyzerMapsTrivyIaCFindingsAndFiltersNonIaCPaths(t *testing.T) {
	repoDir := t.TempDir()
	mustWriteRepoFile(t, filepath.Join(repoDir, "infra", "main.tf"), strings.Join([]string{
		`resource "aws_security_group" "public" {`,
		`  ingress {`,
		`    cidr_blocks = ["0.0.0.0/0"]`,
		`  }`,
		`}`,
	}, "\n"))
	mustWriteRepoFile(t, filepath.Join(repoDir, "README.md"), "# docs only\n")

	analyzer := FilesystemAnalyzer{
		ConfigScanner: fakeConfigScanner{result: &scanner.ConfigScanResult{
			Results: []scanner.ConfigScanTargetResult{
				{
					Path:   "infra/main.tf",
					Format: "terraform",
					Findings: []scanner.ConfigScanFinding{{
						ID:          "AVD-AWS-0001",
						Type:        "misconfiguration",
						Severity:    "HIGH",
						Title:       "Security group allows public ingress",
						Description: "Ingress allows 0.0.0.0/0",
						Remediation: "Scope ingress to trusted CIDRs",
						Path:        "infra/main.tf",
						Resource:    "aws_security_group.public",
						StartLine:   3,
						EndLine:     7,
						Format:      "terraform",
					}},
				},
				{
					Path:   "README.md",
					Format: "terraform",
					Findings: []scanner.ConfigScanFinding{{
						ID:        "AVD-IGNORE-0001",
						Severity:  "LOW",
						Title:     "docs finding",
						Path:      "README.md",
						StartLine: 1,
						EndLine:   1,
					}},
				},
			},
		}},
	}

	report, err := analyzer.Analyze(context.Background(), AnalysisInput{
		RunID:      "repo_scan:analyzer",
		Target:     ScanTarget{RepoURL: repoDir},
		Descriptor: RepositoryDescriptor{RepoURL: repoDir, Repository: "repo", CommitSHA: "abc123"},
		Checkout:   &CheckoutArtifact{Path: repoDir, MaterializedAt: time.Now().UTC()},
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if report == nil || report.Catalog == nil {
		t.Fatalf("expected catalog report, got %#v", report)
	}
	if report.MisconfigurationCount != 1 {
		t.Fatalf("expected one IaC finding, got %#v", report)
	}
	finding := report.Catalog.Misconfigurations[0]
	if finding.Path != "infra/main.tf" {
		t.Fatalf("expected finding path infra/main.tf, got %#v", finding)
	}
	if finding.Line != 3 {
		t.Fatalf("expected line 3, got %#v", finding)
	}
	if finding.ResourceType != "aws_security_group.public" {
		t.Fatalf("expected resource address to be preserved, got %#v", finding)
	}
}

func TestRunnerTracksLastSuccessfulCommitAndFiltersIncrementalIaCFindings(t *testing.T) {
	repoURL, firstCommit, secondCommit := createIncrementalIaCTestRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	previousTime := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:          "repo_scan:previous",
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		Target:      ScanTarget{RepoURL: repoURL},
		SubmittedAt: previousTime,
		UpdatedAt:   previousTime,
		Descriptor: &RepositoryDescriptor{
			RepoURL:    repoURL,
			Repository: "repo",
			CommitSHA:  firstCommit,
		},
	}); err != nil {
		t.Fatalf("save previous run: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Analyzer: FilesystemAnalyzer{
			ConfigScanner: fakeConfigScanner{result: &scanner.ConfigScanResult{
				Results: []scanner.ConfigScanTargetResult{
					{
						Path:   "infra/main.tf",
						Format: "terraform",
						Findings: []scanner.ConfigScanFinding{{
							ID:        "AVD-AWS-0001",
							Severity:  "HIGH",
							Title:     "old terraform finding",
							Path:      "infra/main.tf",
							StartLine: 3,
						}},
					},
					{
						Path:   "deploy/service.yaml",
						Format: "kubernetes",
						Findings: []scanner.ConfigScanFinding{{
							ID:        "AVD-KSV-0001",
							Severity:  "HIGH",
							Title:     "new kubernetes finding",
							Path:      "deploy/service.yaml",
							StartLine: 2,
						}},
					},
				},
			}},
		},
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		RequestedBy: "alice",
		Target:      ScanTarget{RepoURL: repoURL},
	})
	if err != nil {
		t.Fatalf("run repository scan: %v", err)
	}
	if run.Descriptor == nil || run.Descriptor.CommitSHA != secondCommit {
		t.Fatalf("expected commit %q, got %#v", secondCommit, run.Descriptor)
	}
	if run.Target.SinceCommit != firstCommit {
		t.Fatalf("expected since_commit %q, got %#v", firstCommit, run.Target)
	}
	if run.Analysis == nil {
		t.Fatal("expected analysis report")
	}
	if run.Analysis.IncrementalBaseCommit != firstCommit {
		t.Fatalf("expected incremental base commit %q, got %#v", firstCommit, run.Analysis)
	}
	if len(run.Analysis.ChangedPaths) != 1 || run.Analysis.ChangedPaths[0] != "deploy/service.yaml" {
		t.Fatalf("expected only changed kubernetes file, got %#v", run.Analysis.ChangedPaths)
	}
	if len(run.Analysis.Catalog.Misconfigurations) != 1 || run.Analysis.Catalog.Misconfigurations[0].Path != "deploy/service.yaml" {
		t.Fatalf("expected only changed-file finding, got %#v", run.Analysis.Catalog.Misconfigurations)
	}
}

func TestRunnerWritesGraphObservationsForLinkedRuntimeResources(t *testing.T) {
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 13, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-linked",
		Kind:     graph.NodeKindInstance,
		Name:     "i-linked",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})
	g.BuildIndex()

	mapper := lineage.NewLineageMapper()
	if _, err := mapper.MapBusinessEntity(context.Background(), map[string]interface{}{
		"asset_id":   "arn:aws:ec2:us-east-1:123456789012:instance/i-linked",
		"asset_type": "instance",
		"name":       "i-linked",
		"provider":   "aws",
		"region":     "us-east-1",
		"repository": "platform",
		"commit_sha": "abc123",
		"iac_type":   "terraform",
	}); err != nil {
		t.Fatalf("map lineage: %v", err)
	}

	runner := NewRunner(RunnerOptions{
		Store: store,
		Materializer: stubMaterializer{
			descriptor: &RepositoryDescriptor{
				RepoURL:    "https://github.com/acme/platform.git",
				Repository: "platform",
				CommitSHA:  "abc123",
			},
			checkout: &CheckoutArtifact{
				Path:           filepath.Join(t.TempDir(), "checkout"),
				MaterializedAt: now,
			},
		},
		Analyzer: fakeAnalyzer{report: &AnalysisReport{
			Analyzer:              "iac_trivy",
			IaCArtifactCount:      1,
			MisconfigurationCount: 1,
			Catalog: &filesystemanalyzer.Report{
				IaCArtifacts: []filesystemanalyzer.IaCArtifact{{
					ID:     "artifact:terraform",
					Type:   "terraform",
					Path:   "infra/main.tf",
					Format: "hcl",
				}},
				Misconfigurations: []filesystemanalyzer.ConfigFinding{{
					ID:           "finding:public-exposure",
					Type:         "misconfiguration",
					Severity:     "high",
					Path:         "infra/main.tf",
					Line:         4,
					Title:        "Security group allows public ingress",
					ResourceType: "aws_security_group.public",
					ArtifactType: "terraform",
					Format:       "hcl",
				}},
			},
		}},
		Graph:   g,
		Lineage: mapper,
		Now: func() time.Time {
			return now
		},
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: "https://github.com/acme/platform.git"},
	})
	if err != nil {
		t.Fatalf("run repository scan: %v", err)
	}
	if run.Analysis == nil || run.Analysis.GraphIntegration == nil {
		t.Fatalf("expected graph integration metadata, got %#v", run.Analysis)
	}
	if run.Analysis.GraphIntegration.LinkedResources != 1 || run.Analysis.GraphIntegration.ObservationCount != 1 {
		t.Fatalf("expected one linked resource and one observation, got %#v", run.Analysis.GraphIntegration)
	}
	if len(run.Analysis.GraphIntegration.Links) != 1 {
		t.Fatalf("expected graph links, got %#v", run.Analysis.GraphIntegration)
	}
	link := run.Analysis.GraphIntegration.Links[0]
	if link.AssetID != "arn:aws:ec2:us-east-1:123456789012:instance/i-linked" {
		t.Fatalf("unexpected linked asset %#v", link)
	}

	found := false
	for _, node := range g.GetNodesByKind(graph.NodeKindObservation) {
		if got, ok := node.PropertyValue("file_path"); !ok || got != "infra/main.tf" {
			continue
		}
		if got, ok := node.PropertyValue("line"); !ok || got != 4 {
			t.Fatalf("expected observation line=4, got %#v", node.Properties)
		}
		if edge := findGraphEdge(g, node.ID, link.AssetID, graph.EdgeKindTargets); edge == nil {
			t.Fatalf("expected observation edge to linked asset for node %#v", node)
		}
		found = true
	}
	if !found {
		t.Fatalf("expected graph observation for linked asset, got nodes %#v", g.GetNodesByKind(graph.NodeKindObservation))
	}
}

func createIncrementalIaCTestRepo(t *testing.T) (string, string, string) {
	t.Helper()
	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@example.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	mustWriteRepoFile(t, filepath.Join(repoDir, "infra", "main.tf"), strings.Join([]string{
		`resource "aws_security_group" "public" {`,
		`  ingress {`,
		`    cidr_blocks = ["0.0.0.0/0"]`,
		`  }`,
		`}`,
	}, "\n"))
	runGit(t, repoDir, "add", "infra/main.tf")
	runGit(t, repoDir, "commit", "-m", "add terraform")
	firstCommit := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	mustWriteRepoFile(t, filepath.Join(repoDir, "deploy", "service.yaml"), strings.Join([]string{
		`apiVersion: apps/v1`,
		`kind: Deployment`,
		`metadata:`,
		`  name: api`,
		`spec: {}`,
	}, "\n"))
	runGit(t, repoDir, "add", "deploy/service.yaml")
	runGit(t, repoDir, "commit", "-m", "add kubernetes manifest")
	secondCommit := strings.TrimSpace(runGitOutput(t, repoDir, "rev-parse", "HEAD"))

	return "file://" + repoDir, firstCommit, secondCommit
}

func TestRunnerSkipsAnalysisWhenHeadMatchesLastSuccessfulCommit(t *testing.T) {
	repoURL, _, head := createIncrementalIaCTestRepo(t)
	store, err := NewSQLiteRunStore(filepath.Join(t.TempDir(), "repo-scan.db"))
	if err != nil {
		t.Fatalf("new sqlite run store: %v", err)
	}
	defer func() { _ = store.Close() }()

	now := time.Date(2026, 3, 21, 14, 0, 0, 0, time.UTC)
	if err := store.SaveRun(context.Background(), &RunRecord{
		ID:          "repo_scan:previous",
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		Target:      ScanTarget{RepoURL: repoURL},
		SubmittedAt: now.Add(-1 * time.Hour),
		UpdatedAt:   now.Add(-1 * time.Hour),
		Descriptor: &RepositoryDescriptor{
			RepoURL:   repoURL,
			CommitSHA: head,
		},
	}); err != nil {
		t.Fatalf("save previous run: %v", err)
	}

	analyzerCalled := false
	runner := NewRunner(RunnerOptions{
		Store:        store,
		Materializer: NewLocalMaterializer(filepath.Join(t.TempDir(), "checkouts"), scm.NewLocalClient("")),
		Analyzer: fakeAnalyzer{report: &AnalysisReport{
			Analyzer: "should_not_run",
		}},
		Now: func() time.Time {
			return now
		},
	})
	runner.analyzer = analyzerFunc(func(context.Context, AnalysisInput) (*AnalysisReport, error) {
		analyzerCalled = true
		return &AnalysisReport{Analyzer: "should_not_run"}, nil
	})

	run, err := runner.RunRepositoryScan(context.Background(), ScanRequest{
		Target: ScanTarget{RepoURL: repoURL},
	})
	if err != nil {
		t.Fatalf("run repository scan: %v", err)
	}
	if analyzerCalled {
		t.Fatal("expected incremental no-op to skip analysis")
	}
	if run.Analysis == nil {
		t.Fatal("expected incremental no-op analysis report")
	}
	if !run.Analysis.Skipped || run.Analysis.IncrementalBaseCommit != head {
		t.Fatalf("expected skipped incremental analysis, got %#v", run.Analysis)
	}
}

type analyzerFunc func(context.Context, AnalysisInput) (*AnalysisReport, error)

func (f analyzerFunc) Analyze(ctx context.Context, input AnalysisInput) (*AnalysisReport, error) {
	return f(ctx, input)
}

func findGraphEdge(g *graph.Graph, source, target string, kind graph.EdgeKind) *graph.Edge {
	if g == nil {
		return nil
	}
	for _, edge := range g.GetOutEdges(source) {
		if edge != nil && edge.Target == target && edge.Kind == kind {
			return edge
		}
	}
	return nil
}
