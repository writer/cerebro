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

func TestMaterializeRunsIntoGraphAddsCredentialPivotEdges(t *testing.T) {
	now := time.Date(2026, 3, 12, 18, 0, 0, 0, time.UTC)
	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet", Provider: "external", Risk: graph.RiskCritical})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
		Kind:     graph.NodeKindInstance,
		Name:     "i-abc123",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:iam::123456789012:user/alice",
		Kind:     graph.NodeKindUser,
		Name:     "alice",
		Provider: "aws",
		Account:  "123456789012",
		Properties: map[string]any{
			"access_keys": []any{"AKIA1234567890ABCDEF"},
		},
	})
	g.AddNode(&graph.Node{
		ID:       "arn:aws:s3:::prod-data",
		Kind:     graph.NodeKindBucket,
		Name:     "prod-data",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     graph.RiskHigh,
	})
	g.AddEdge(&graph.Edge{ID: "internet->instance", Source: "internet", Target: "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "user->bucket", Source: "arn:aws:iam::123456789012:user/alice", Target: "arn:aws:s3:::prod-data", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})
	g.BuildIndex()

	run := buildGraphMaterializationTestRun("workload_scan:run-credential", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Secrets = []filesystemanalyzer.SecretFinding{{
		ID:       "secret:aws-access-key",
		Type:     "aws_access_key",
		Severity: "critical",
		Path:     "home/user/.env",
		Line:     1,
		Match:    "AKIA1234567890ABCDEF",
		References: []filesystemanalyzer.SecretReference{{
			Kind:       "cloud_identity",
			Provider:   "aws",
			Identifier: "AKIA1234567890ABCDEF",
		}},
	}}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.SecretNodesUpserted != 1 {
		t.Fatalf("expected one secret node, got %#v", summary)
	}
	if summary.CredentialPivotEdges == 0 {
		t.Fatalf("expected credential pivot edges, got %#v", summary)
	}

	secretID := discoveredSecretNodeID("arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", run.Volumes[0].Analysis.Catalog.Secrets[0])
	secretNode, ok := g.GetNode(secretID)
	if !ok {
		t.Fatalf("expected discovered secret node %q", secretID)
	}
	if got := graphValueString(secretNode.Properties["match_fingerprint"]); got == "AKIA1234567890ABCDEF" || got == "" {
		t.Fatalf("expected sanitized fingerprint on secret node, got %#v", secretNode.Properties)
	}
	if edge := findOutEdge(g, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", graph.EdgeKindHasCredentialFor, "arn:aws:s3:::prod-data"); edge == nil {
		t.Fatal("expected workload credential pivot edge to bucket")
	} else if got := graphValueString(edge.Properties["match_fingerprint"]); got == "AKIA1234567890ABCDEF" || got == "" {
		t.Fatalf("expected sanitized fingerprint on pivot edge, got %#v", edge.Properties)
	}

	sim := graph.NewAttackPathSimulator(g)
	result := sim.Simulate(4)
	found := false
	for _, path := range result.Paths {
		for _, step := range path.Steps {
			if step.EdgeKind == graph.EdgeKindHasCredentialFor && step.ToNode == "arn:aws:s3:::prod-data" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatalf("expected attack-path simulation to include credential pivot, got %#v", result.Paths)
	}
}

func TestMaterializeRunsIntoGraphAddsIaCFindingObservations(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-iac", now.Add(-2*time.Hour), 0)
	run.Summary.Findings = 2
	run.Volumes[0].Analysis.FindingCount = 2
	run.Volumes[0].Analysis.Catalog.IaCArtifacts = []filesystemanalyzer.IaCArtifact{
		{ID: "artifact:terraform", Type: "terraform", Path: "infra/main.tf", Format: "hcl", ResourceType: "firewall_rule"},
		{ID: "artifact:terraform-state", Type: "terraform_state", Path: "infra/terraform.tfstate", Format: "json", ResourceType: "terraform_state"},
	}
	run.Volumes[0].Analysis.Catalog.Misconfigurations = []filesystemanalyzer.ConfigFinding{
		{
			ID:           "finding:terraform-state",
			Type:         "terraform_state",
			Severity:     "high",
			Path:         "infra/terraform.tfstate",
			Title:        "Terraform state file detected",
			ArtifactType: "terraform_state",
			Format:       "json",
			ResourceType: "terraform_state",
		},
		{
			ID:           "finding:public-exposure",
			Type:         "iac_public_exposure",
			Severity:     "high",
			Path:         "infra/main.tf",
			Title:        "Public network exposure in IaC or config",
			ArtifactType: "terraform",
			Format:       "hcl",
			ResourceType: "firewall_rule",
		},
	}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.ObservationNodesUpserted != 2 {
		t.Fatalf("expected two IaC observation nodes, got %#v", summary)
	}
	if summary.ScanObservationEdges != 2 {
		t.Fatalf("expected two IaC observation edges, got %#v", summary)
	}

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if scanNode.Risk != graph.RiskHigh {
		t.Fatalf("expected scan node risk high from IaC findings, got %#v", scanNode)
	}
	if got := graphValueInt(scanNode.Properties["iac_artifact_count"]); got != 2 {
		t.Fatalf("expected iac_artifact_count=2, got %#v", scanNode.Properties)
	}

	observationID := iacFindingObservationNodeID(run.ID, run.Volumes[0].Analysis.Catalog.Misconfigurations[0])
	observationNode, ok := g.GetNode(observationID)
	if !ok {
		t.Fatalf("expected observation node %q", observationID)
	}
	if observationNode.Kind != graph.NodeKindObservation {
		t.Fatalf("expected observation kind, got %#v", observationNode)
	}
	if got := graphValueString(observationNode.Properties["observation_type"]); got != "workload_iac_finding" {
		t.Fatalf("expected observation_type workload_iac_finding, got %#v", observationNode.Properties)
	}
	if got := graphValueString(observationNode.Properties["resource_type"]); got != "terraform_state" {
		t.Fatalf("expected observation resource_type terraform_state, got %#v", observationNode.Properties)
	}
	if edge := findOutEdge(g, observationID, graph.EdgeKindTargets, run.ID); edge == nil {
		t.Fatalf("expected observation to target scan node, got %#v", g.GetOutEdges(observationID))
	}
}

func TestMaterializeRunsIntoGraphAppliesLegacyMisconfigurationRiskWithoutObservation(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-legacy-misconfig", now.Add(-2*time.Hour), 0)
	run.Summary.Findings = 1
	run.Volumes[0].Analysis.FindingCount = 1
	run.Volumes[0].Analysis.Catalog.Misconfigurations = []filesystemanalyzer.ConfigFinding{{
		ID:       "finding:ssh-root-login",
		Type:     "ssh",
		Severity: "high",
		Path:     "etc/ssh/sshd_config",
		Title:    "SSH root login enabled",
	}}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.ObservationNodesUpserted != 0 {
		t.Fatalf("expected no IaC observations for legacy config finding, got %#v", summary)
	}

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if scanNode.Risk != graph.RiskHigh {
		t.Fatalf("expected legacy misconfiguration to raise scan risk, got %#v", scanNode)
	}
}

func TestMaterializeRunsIntoGraphMapsDatabaseConnectionStrings(t *testing.T) {
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
	g.AddNode(&graph.Node{
		ID:       "database:prod-db",
		Kind:     graph.NodeKindDatabase,
		Name:     "prod-db",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
		Risk:     graph.RiskCritical,
	})
	g.BuildIndex()

	run := buildGraphMaterializationTestRun("workload_scan:run-db", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Secrets = []filesystemanalyzer.SecretFinding{{
		ID:       "secret:db-connection",
		Type:     "database_connection_string",
		Severity: "critical",
		Path:     "srv/app/.env",
		Line:     2,
		Match:    "sha256:feedface",
		References: []filesystemanalyzer.SecretReference{{
			Kind:       "database",
			Identifier: "prod-db.internal",
			Host:       "prod-db.internal",
			Port:       5432,
			Database:   "appdb",
		}},
	}}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.CredentialPivotEdges != 1 {
		t.Fatalf("expected one database credential pivot edge, got %#v", summary)
	}
	if edge := findOutEdge(g, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", graph.EdgeKindHasCredentialFor, "database:prod-db"); edge == nil {
		t.Fatal("expected workload credential pivot edge to database")
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

func findOutEdge(g *graph.Graph, source string, kind graph.EdgeKind, target string) *graph.Edge {
	for _, edge := range g.GetOutEdges(source) {
		if edge != nil && edge.Kind == kind && edge.Target == target {
			return edge
		}
	}
	return nil
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
