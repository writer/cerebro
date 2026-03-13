package workloadscan

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/filesystemanalyzer"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/scanner"
)

func TestMaterializeRunsIntoGraphAddsWorkloadScanNodes(t *testing.T) {
	now := time.Date(2026, 3, 12, 18, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
		Kind:     graph.NodeKindInstance,
		Name:     "i-abc123",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})
	g.BuildIndex()

	run := buildGraphMaterializationTestRun("workload_scan:run-1", now.Add(-2*time.Hour), 1)
	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.RunsMaterialized != 1 {
		t.Fatalf("expected one materialized run, got %#v", summary)
	}
	if _, ok := g.GetNode(run.ID); !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if _, ok := g.GetNode(packageNodeID(filesystemanalyzer.PackageRecord{
		Ecosystem: "deb",
		Name:      "openssl",
		Version:   "3.0.2-0ubuntu1.10",
		PURL:      "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10",
	})); !ok {
		t.Fatal("expected package node to be created")
	}
	if _, ok := g.GetNode(vulnerabilityNodeID(scanner.ImageVulnerability{CVE: "CVE-2026-0001"})); !ok {
		t.Fatal("expected vulnerability node to be created")
	}
}

func TestMaterializeRunsIntoGraphClosesOlderScans(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
		Kind:     graph.NodeKindInstance,
		Name:     "i-abc123",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})
	g.BuildIndex()

	firstCompleted := time.Date(2026, 3, 10, 10, 0, 0, 0, time.UTC)
	secondCompleted := time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC)
	first := buildGraphMaterializationTestRun("workload_scan:first", firstCompleted, 1)
	second := buildGraphMaterializationTestRun("workload_scan:second", secondCompleted, 0)

	MaterializeRunsIntoGraph(g, []RunRecord{first, second}, secondCompleted.Add(2*time.Hour))

	firstNode, ok := g.GetNode(first.ID)
	if !ok {
		t.Fatalf("expected first run node %q", first.ID)
	}
	if got := graphValueString(firstNode.Properties["valid_to"]); got == "" {
		t.Fatalf("expected first run valid_to to be populated, got %#v", firstNode.Properties)
	}
	secondNode, ok := g.GetNode(second.ID)
	if !ok {
		t.Fatalf("expected second run node %q", second.ID)
	}
	if got := graphValueString(secondNode.Properties["valid_to"]); got != "" {
		t.Fatalf("expected latest run valid_to to be empty, got %#v", secondNode.Properties)
	}
}

func TestMaterializeRunsIntoGraphDedupesVulnerabilitiesAcrossVolumes(t *testing.T) {
	now := time.Date(2026, 3, 12, 18, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
		Kind:     graph.NodeKindInstance,
		Name:     "i-abc123",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})
	g.BuildIndex()

	run := buildGraphMaterializationTestRun("workload_scan:run-dedupe", now.Add(-2*time.Hour), 1)
	startedAt := now.Add(-2*time.Hour - 15*time.Minute)
	completedAt := now.Add(-2 * time.Hour)
	run.Summary.VolumeCount = 2
	run.Summary.SucceededVolumes = 2
	run.Volumes = append(run.Volumes, VolumeScanRecord{
		Source:      SourceVolume{ID: "vol-2"},
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		StartedAt:   startedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
		Analysis: &AnalysisReport{
			FindingCount: 1,
			SBOMRef:      "embedded:cyclonedx",
			Catalog: &filesystemanalyzer.Report{
				OS: filesystemanalyzer.OSInfo{Name: "Ubuntu", Version: "22.04", Architecture: "amd64"},
				Packages: []filesystemanalyzer.PackageRecord{
					{Ecosystem: "deb", Name: "openssl", Version: "3.0.2-0ubuntu1.10", PURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"},
				},
				Vulnerabilities: []scanner.ImageVulnerability{
					{
						CVE:              "CVE-2026-0001",
						Severity:         "HIGH",
						Package:          "openssl",
						InstalledVersion: "3.0.2-0ubuntu1.10",
						FixedVersion:     "3.0.2-0ubuntu1.12",
						Exploitable:      true,
						InKEV:            true,
					},
				},
			},
		},
	})

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.RunsMaterialized != 1 {
		t.Fatalf("expected one materialized run, got %#v", summary)
	}

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if got := graphValueInt(scanNode.Properties["vulnerability_count"]); got != 1 {
		t.Fatalf("expected deduped vulnerability_count=1, got %d", got)
	}
	if got := graphValueInt(scanNode.Properties["critical_vulnerability_count"]); got != 1 {
		t.Fatalf("expected deduped critical_vulnerability_count=1, got %d", got)
	}
	if got := graphValueInt(scanNode.Properties["known_exploited_count"]); got != 1 {
		t.Fatalf("expected deduped known_exploited_count=1, got %d", got)
	}
	if got := graphValueInt(scanNode.Properties["fixable_vulnerability_count"]); got != 1 {
		t.Fatalf("expected deduped fixable_vulnerability_count=1, got %d", got)
	}
}

func buildGraphMaterializationTestRun(id string, completedAt time.Time, vulnerabilityCount int) RunRecord {
	startedAt := completedAt.Add(-15 * time.Minute)
	catalog := &filesystemanalyzer.Report{
		OS: filesystemanalyzer.OSInfo{Name: "Ubuntu", Version: "22.04", Architecture: "amd64"},
		Packages: []filesystemanalyzer.PackageRecord{
			{Ecosystem: "deb", Name: "openssl", Version: "3.0.2-0ubuntu1.10", PURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10"},
		},
		Summary: filesystemanalyzer.Summary{
			PackageCount:       1,
			VulnerabilityCount: vulnerabilityCount,
		},
	}
	if vulnerabilityCount > 0 {
		catalog.Vulnerabilities = []scanner.ImageVulnerability{
			{
				CVE:              "CVE-2026-0001",
				Severity:         "CRITICAL",
				Package:          "openssl",
				InstalledVersion: "3.0.2-0ubuntu1.10",
				FixedVersion:     "3.0.2-0ubuntu1.12",
				Exploitable:      true,
				InKEV:            true,
			},
		}
	}
	return RunRecord{
		ID:       id,
		Provider: ProviderAWS,
		Status:   RunStatusSucceeded,
		Stage:    RunStageCompleted,
		Target: VMTarget{
			Provider:   ProviderAWS,
			AccountID:  "123456789012",
			Region:     "us-east-1",
			InstanceID: "i-abc123",
		},
		SubmittedAt: startedAt.Add(-2 * time.Minute),
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
		UpdatedAt:   completedAt,
		Summary: RunSummary{
			VolumeCount:      1,
			SucceededVolumes: 1,
			Findings:         int64(vulnerabilityCount),
		},
		Volumes: []VolumeScanRecord{
			{
				Source:      SourceVolume{ID: "vol-1"},
				Status:      RunStatusSucceeded,
				Stage:       RunStageCompleted,
				StartedAt:   startedAt,
				UpdatedAt:   completedAt,
				CompletedAt: &completedAt,
				Analysis: &AnalysisReport{
					FindingCount: int64(vulnerabilityCount),
					SBOMRef:      "embedded:cyclonedx",
					Catalog:      catalog,
				},
			},
		},
	}
}

func graphValueString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func graphValueInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}
