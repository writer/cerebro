package workloadscan

import (
	"strings"
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

func TestMaterializeRunsIntoGraphAddsPackageDependencyEdgesAndUsageHints(t *testing.T) {
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

	express := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "express",
		Version:          "4.18.2",
		PURL:             "pkg:npm/express@4.18.2",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  1,
	}
	bodyParser := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "body-parser",
		Version:          "1.20.2",
		PURL:             "pkg:npm/body-parser@1.20.2",
		Location:         "srv/app/package-lock.json",
		DirectDependency: false,
		Reachable:        true,
		DependencyDepth:  2,
		ImportFileCount:  1,
	}
	lodash := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "lodash",
		Version:          "4.17.21",
		PURL:             "pkg:npm/lodash@4.17.21",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        false,
		DependencyDepth:  1,
		ImportFileCount:  0,
	}

	run := buildGraphMaterializationTestRun("workload_scan:run-dependency-graph", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{express, bodyParser, lodash}
	run.Volumes[0].Analysis.Catalog.SBOM = filesystemanalyzer.SBOMDocument{
		Format:      "cyclonedx-json",
		SpecVersion: "1.5",
		GeneratedAt: now.Add(-2 * time.Hour),
		Components: []filesystemanalyzer.SBOMComponent{
			{BOMRef: testSBOMComponentRef(express), Type: "library", Name: express.Name, Version: express.Version, PURL: express.PURL, Ecosystem: express.Ecosystem, Location: express.Location, DirectDependency: express.DirectDependency, Reachable: express.Reachable, DependencyDepth: express.DependencyDepth},
			{BOMRef: testSBOMComponentRef(bodyParser), Type: "library", Name: bodyParser.Name, Version: bodyParser.Version, PURL: bodyParser.PURL, Ecosystem: bodyParser.Ecosystem, Location: bodyParser.Location, DirectDependency: bodyParser.DirectDependency, Reachable: bodyParser.Reachable, DependencyDepth: bodyParser.DependencyDepth},
			{BOMRef: testSBOMComponentRef(lodash), Type: "library", Name: lodash.Name, Version: lodash.Version, PURL: lodash.PURL, Ecosystem: lodash.Ecosystem, Location: lodash.Location, DirectDependency: lodash.DirectDependency, Reachable: lodash.Reachable, DependencyDepth: lodash.DependencyDepth},
		},
		Dependencies: []filesystemanalyzer.SBOMDependency{
			{Ref: testSBOMComponentRef(express), DependsOn: []string{testSBOMComponentRef(bodyParser)}},
		},
	}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.PackageDependencyEdges != 1 {
		t.Fatalf("expected one package dependency edge, got %#v", summary)
	}

	scanToExpress := findOutEdge(g, run.ID, graph.EdgeKindContainsPkg, packageNodeID(express))
	if scanToExpress == nil {
		t.Fatalf("expected scan -> express edge")
	}
	if got := graphValueBool(scanToExpress.Properties["direct_dependency"]); !got {
		t.Fatalf("expected direct_dependency=true, got %#v", scanToExpress.Properties)
	}
	if got := graphValueBool(scanToExpress.Properties["reachable"]); !got {
		t.Fatalf("expected reachable=true, got %#v", scanToExpress.Properties)
	}
	if got := graphValueInt(scanToExpress.Properties["dependency_depth"]); got != 1 {
		t.Fatalf("expected dependency_depth=1, got %#v", scanToExpress.Properties)
	}
	if got := graphValueInt(scanToExpress.Properties["import_file_count"]); got != 1 {
		t.Fatalf("expected import_file_count=1, got %#v", scanToExpress.Properties)
	}

	scanToBodyParser := findOutEdge(g, run.ID, graph.EdgeKindContainsPkg, packageNodeID(bodyParser))
	if scanToBodyParser == nil {
		t.Fatalf("expected scan -> body-parser edge")
	}
	if got := graphValueBool(scanToBodyParser.Properties["direct_dependency"]); got {
		t.Fatalf("expected direct_dependency=false, got %#v", scanToBodyParser.Properties)
	}
	if got := graphValueInt(scanToBodyParser.Properties["dependency_depth"]); got != 2 {
		t.Fatalf("expected dependency_depth=2, got %#v", scanToBodyParser.Properties)
	}
	if got := graphValueInt(scanToBodyParser.Properties["import_file_count"]); got != 1 {
		t.Fatalf("expected import_file_count=1, got %#v", scanToBodyParser.Properties)
	}

	depEdge := findOutEdge(g, packageNodeID(express), graph.EdgeKindDependsOn, packageNodeID(bodyParser))
	if depEdge == nil {
		t.Fatalf("expected express -> body-parser depends_on edge")
	}
}

func TestPackageFromSBOMComponentMapsManagerFromEcosystem(t *testing.T) {
	component := filesystemanalyzer.SBOMComponent{
		BOMRef:           "pkg:golang/github.com/google/uuid@v1.6.0",
		Type:             "library",
		Name:             "github.com/google/uuid",
		Version:          "v1.6.0",
		PURL:             "pkg:golang/github.com%2Fgoogle%2Fuuid@v1.6.0",
		Ecosystem:        "golang",
		Location:         "workspace/go.mod",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  1,
	}

	pkg := packageFromSBOMComponent(component)
	if pkg.Manager != "go" {
		t.Fatalf("expected go manager, got %#v", pkg)
	}
}

func TestMaterializeRunsIntoGraphKeepsUsageHintsOffCanonicalPackageNodes(t *testing.T) {
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

	component := filesystemanalyzer.SBOMComponent{
		BOMRef:           "pkg:golang/github.com/google/uuid@v1.6.0",
		Type:             "library",
		Name:             "github.com/google/uuid",
		Version:          "v1.6.0",
		PURL:             "pkg:golang/github.com%2Fgoogle%2Fuuid@v1.6.0",
		Ecosystem:        "golang",
		Location:         "workspace/go.mod",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  1,
	}

	pkg := filesystemanalyzer.PackageRecord{
		Ecosystem:        component.Ecosystem,
		Manager:          "go",
		Name:             component.Name,
		Version:          component.Version,
		PURL:             component.PURL,
		Location:         component.Location,
		DirectDependency: component.DirectDependency,
		Reachable:        component.Reachable,
		DependencyDepth:  component.DependencyDepth,
		ImportFileCount:  component.ImportFileCount,
	}

	run := buildGraphMaterializationTestRun("workload_scan:run-go-sbom", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{pkg}
	run.Volumes[0].Analysis.Catalog.SBOM = filesystemanalyzer.SBOMDocument{
		Format:      "cyclonedx-json",
		SpecVersion: "1.5",
		GeneratedAt: now.Add(-2 * time.Hour),
		Components:  []filesystemanalyzer.SBOMComponent{component},
	}

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	pkgNode, ok := g.GetNode(packageNodeID(pkg))
	if !ok {
		t.Fatalf("expected package node for %#v", pkg)
	}
	if got := graphValueString(pkgNode.Properties["manager"]); got != "go" {
		t.Fatalf("expected manager=go, got %#v", pkgNode.Properties)
	}
	for _, key := range []string{"direct_dependency", "reachable", "dependency_depth", "import_file_count"} {
		if _, exists := pkgNode.Properties[key]; exists {
			t.Fatalf("expected canonical package node to omit %q, got %#v", key, pkgNode.Properties)
		}
	}

	scanEdge := findOutEdge(g, run.ID, graph.EdgeKindContainsPkg, packageNodeID(pkg))
	if scanEdge == nil {
		t.Fatalf("expected workload scan contains_pkg edge")
	}
	if got := graphValueBool(scanEdge.Properties["direct_dependency"]); !got {
		t.Fatalf("expected direct_dependency=true on usage edge, got %#v", scanEdge.Properties)
	}
	if got := graphValueBool(scanEdge.Properties["reachable"]); !got {
		t.Fatalf("expected reachable=true on usage edge, got %#v", scanEdge.Properties)
	}
	if got := graphValueInt(scanEdge.Properties["dependency_depth"]); got != 1 {
		t.Fatalf("expected dependency_depth=1 on usage edge, got %#v", scanEdge.Properties)
	}
	if got := graphValueInt(scanEdge.Properties["import_file_count"]); got != 1 {
		t.Fatalf("expected import_file_count=1 on usage edge, got %#v", scanEdge.Properties)
	}
}

func TestMaterializeRunsIntoGraphIgnoresNonLibrarySBOMComponents(t *testing.T) {
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

	component := filesystemanalyzer.SBOMComponent{
		BOMRef:           "pkg:golang/github.com/google/uuid@v1.6.0",
		Type:             "library",
		Name:             "github.com/google/uuid",
		Version:          "v1.6.0",
		PURL:             "pkg:golang/github.com%2Fgoogle%2Fuuid@v1.6.0",
		Ecosystem:        "golang",
		Location:         "workspace/go.mod",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  1,
	}

	pkg := packageFromSBOMComponent(component)
	run := buildGraphMaterializationTestRun("workload_scan:run-go-app-sbom", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{pkg}
	run.Volumes[0].Analysis.Catalog.SBOM = filesystemanalyzer.SBOMDocument{
		Format:      "cyclonedx-json",
		SpecVersion: "1.5",
		GeneratedAt: now.Add(-2 * time.Hour),
		Components: []filesystemanalyzer.SBOMComponent{
			{
				BOMRef:    "app:golang/example.com/demo",
				Type:      "application",
				Name:      "example.com/demo",
				Ecosystem: "golang",
				Location:  "workspace/go.mod",
			},
			component,
		},
		Dependencies: []filesystemanalyzer.SBOMDependency{
			{Ref: "app:golang/example.com/demo", DependsOn: []string{component.BOMRef}},
		},
	}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.PackageDependencyEdges != 0 {
		t.Fatalf("expected non-library SBOM components to be ignored for package dependency edges, got %#v", summary)
	}
	appNodeID := packageNodeID(filesystemanalyzer.PackageRecord{Ecosystem: "golang", Name: "example.com/demo"})
	if edge := findOutEdge(g, appNodeID, graph.EdgeKindDependsOn, packageNodeID(pkg)); edge != nil {
		t.Fatalf("expected no package node/edge synthesized for application component, got %#v", edge)
	}
	if findOutEdge(g, run.ID, graph.EdgeKindContainsPkg, packageNodeID(pkg)) == nil {
		t.Fatalf("expected library component package to remain materialized")
	}
}

func TestMaterializeRunsIntoGraphCarriesPriorityAssessment(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-priority", now.Add(-2*time.Hour), 0)
	lastScannedAt := now.Add(-48 * time.Hour)
	run.Priority = &PriorityAssessment{
		Score:            84,
		Priority:         ScanPriorityCritical,
		Eligible:         true,
		Source:           "graph",
		Reasons:          []string{"workload is directly internet-facing"},
		Exposure:         "internet_facing",
		Privilege:        "privileged",
		Criticality:      "high",
		ComplianceScopes: []string{"pci"},
		Staleness:        "stale",
		LastScannedAt:    &lastScannedAt,
	}

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if got := graphValueString(scanNode.Properties["priority"]); got != "critical" {
		t.Fatalf("expected priority property, got %#v", scanNode.Properties)
	}
	if got := graphValueInt(scanNode.Properties["priority_score"]); got != 84 {
		t.Fatalf("expected priority_score=84, got %#v", scanNode.Properties)
	}
	if got := graphValueString(scanNode.Properties["priority_staleness"]); got != "stale" {
		t.Fatalf("expected priority staleness, got %#v", scanNode.Properties)
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
	if got := graphNodePropertyString(firstNode, "valid_to"); got == "" {
		t.Fatalf("expected first run valid_to to be populated, got %#v", firstNode.PropertyMap())
	}
	secondNode, ok := g.GetNode(second.ID)
	if !ok {
		t.Fatalf("expected second run node %q", second.ID)
	}
	if got := graphNodePropertyString(secondNode, "valid_to"); got != "" {
		t.Fatalf("expected latest run valid_to to be empty, got %#v", secondNode.PropertyMap())
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

func TestMaterializeRunsIntoGraphMergesVulnerabilityAliasesIntoCanonicalNode(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-vuln-alias-merge", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "express",
		Version:          "4.18.2",
		PURL:             "pkg:npm/express@4.18.2",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  1,
	}}
	ghsaOnly := scanner.ImageVulnerability{
		ID:               "GHSA-1234-5678-9012",
		Severity:         "HIGH",
		Package:          "express",
		InstalledVersion: "4.18.2",
	}
	withCVE := scanner.ImageVulnerability{
		ID:               "GHSA-1234-5678-9012",
		CVE:              "CVE-2026-3300",
		Severity:         "CRITICAL",
		Package:          "express",
		InstalledVersion: "4.18.2",
		FixedVersion:     "4.18.3",
	}
	run.Volumes[0].Analysis.Catalog.Vulnerabilities = []scanner.ImageVulnerability{ghsaOnly, withCVE}

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if got := graphValueInt(scanNode.Properties["vulnerability_count"]); got != 1 {
		t.Fatalf("expected aliased vulnerabilities to merge, got %#v", scanNode.Properties)
	}
	if got := graphValueInt(scanNode.Properties["critical_vulnerability_count"]); got != 1 {
		t.Fatalf("expected merged vulnerability severity to keep the highest rank, got %#v", scanNode.Properties)
	}

	if _, ok := g.GetNode(vulnerabilityNodeID(ghsaOnly)); ok {
		t.Fatalf("expected GHSA-only vulnerability node to collapse into canonical CVE node")
	}
	vulnNode, ok := g.GetNode(vulnerabilityNodeID(withCVE))
	if !ok {
		t.Fatalf("expected canonical CVE vulnerability node")
	}
	if got := graphValueString(vulnNode.Properties["cve_id"]); got != "CVE-2026-3300" {
		t.Fatalf("expected merged vulnerability node to preserve CVE identifier, got %#v", vulnNode.Properties)
	}
	scanEdge := findOutEdge(g, run.ID, graph.EdgeKindFoundVuln, vulnerabilityNodeID(withCVE))
	if scanEdge == nil {
		t.Fatalf("expected scan -> merged vulnerability edge")
	}
	if got := graphValueBool(scanEdge.Properties["reachable"]); !got {
		t.Fatalf("expected merged vulnerability edge to preserve reachable package context, got %#v", scanEdge.Properties)
	}
}

func TestMaterializeRunsIntoGraphCarriesVulnerabilityReachabilityPriority(t *testing.T) {
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

	reachableDirect := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "express",
		Version:          "4.18.2",
		PURL:             "pkg:npm/express@4.18.2",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  2,
	}
	unreachableDirect := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "lodash",
		Version:          "4.17.21",
		PURL:             "pkg:npm/lodash@4.17.21",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        false,
		DependencyDepth:  1,
		ImportFileCount:  0,
	}
	reachableVuln := scanner.ImageVulnerability{
		CVE:              "CVE-2026-1000",
		Severity:         "CRITICAL",
		Package:          "express",
		InstalledVersion: "4.18.2",
		FixedVersion:     "4.18.3",
		Exploitable:      true,
		InKEV:            true,
	}
	unreachableVuln := scanner.ImageVulnerability{
		CVE:              "CVE-2026-2000",
		Severity:         "CRITICAL",
		Package:          "lodash",
		InstalledVersion: "4.17.21",
		FixedVersion:     "4.17.22",
	}

	run := buildGraphMaterializationTestRun("workload_scan:run-vuln-priority", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{reachableDirect, unreachableDirect}
	run.Volumes[0].Analysis.Catalog.Vulnerabilities = []scanner.ImageVulnerability{reachableVuln, unreachableVuln}
	run.Summary.Findings = 2
	run.Volumes[0].Analysis.FindingCount = 2

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if got := graphValueInt(scanNode.Properties["reachable_vulnerability_count"]); got != 1 {
		t.Fatalf("expected reachable_vulnerability_count=1, got %#v", scanNode.Properties)
	}
	if got := graphValueInt(scanNode.Properties["reachable_critical_vulnerability_count"]); got != 1 {
		t.Fatalf("expected reachable_critical_vulnerability_count=1, got %#v", scanNode.Properties)
	}
	if got := graphValueInt(scanNode.Properties["reachable_known_exploited_count"]); got != 1 {
		t.Fatalf("expected reachable_known_exploited_count=1, got %#v", scanNode.Properties)
	}
	if got := graphValueInt(scanNode.Properties["direct_reachable_vulnerability_count"]); got != 1 {
		t.Fatalf("expected direct_reachable_vulnerability_count=1, got %#v", scanNode.Properties)
	}

	reachableScanEdge := findOutEdge(g, run.ID, graph.EdgeKindFoundVuln, vulnerabilityNodeID(reachableVuln))
	if reachableScanEdge == nil {
		t.Fatalf("expected scan -> reachable vulnerability edge")
	}
	if got := graphValueBool(reachableScanEdge.Properties["reachable"]); !got {
		t.Fatalf("expected reachable scan vulnerability edge, got %#v", reachableScanEdge.Properties)
	}
	if got := graphValueBool(reachableScanEdge.Properties["direct_dependency"]); !got {
		t.Fatalf("expected direct_dependency=true on reachable scan vulnerability edge, got %#v", reachableScanEdge.Properties)
	}
	if got := graphValueInt(reachableScanEdge.Properties["dependency_depth"]); got != 1 {
		t.Fatalf("expected dependency_depth=1 on reachable scan vulnerability edge, got %#v", reachableScanEdge.Properties)
	}
	if got := graphValueInt(reachableScanEdge.Properties["import_file_count"]); got != 2 {
		t.Fatalf("expected import_file_count=2 on reachable scan vulnerability edge, got %#v", reachableScanEdge.Properties)
	}
	if got := graphValueInt(reachableScanEdge.Properties["affected_package_count"]); got != 1 {
		t.Fatalf("expected affected_package_count=1 on reachable scan vulnerability edge, got %#v", reachableScanEdge.Properties)
	}
	if got := graphValueInt(reachableScanEdge.Properties["reachable_package_count"]); got != 1 {
		t.Fatalf("expected reachable_package_count=1 on reachable scan vulnerability edge, got %#v", reachableScanEdge.Properties)
	}
	if got := graphValueString(reachableScanEdge.Properties["priority_hint"]); got != "reachable_direct" {
		t.Fatalf("expected reachable_direct priority_hint, got %#v", reachableScanEdge.Properties)
	}
	if reachableScanEdge.Risk != graph.RiskCritical {
		t.Fatalf("expected reachable scan vulnerability edge risk critical, got %#v", reachableScanEdge)
	}

	reachablePkgEdge := findOutEdge(g, packageNodeID(reachableDirect), graph.EdgeKindAffectedBy, vulnerabilityNodeID(reachableVuln))
	if reachablePkgEdge == nil {
		t.Fatalf("expected package -> reachable vulnerability edge")
	}
	if got := graphValueBool(reachablePkgEdge.Properties["reachable"]); !got {
		t.Fatalf("expected reachable=true on package vulnerability edge, got %#v", reachablePkgEdge.Properties)
	}
	if got := graphValueBool(reachablePkgEdge.Properties["direct_dependency"]); !got {
		t.Fatalf("expected direct_dependency=true on package vulnerability edge, got %#v", reachablePkgEdge.Properties)
	}
	if got := graphValueString(reachablePkgEdge.Properties["priority_hint"]); got != "reachable_direct" {
		t.Fatalf("expected reachable_direct priority_hint on package vulnerability edge, got %#v", reachablePkgEdge.Properties)
	}
	if reachablePkgEdge.Risk != graph.RiskCritical {
		t.Fatalf("expected reachable package vulnerability edge risk critical, got %#v", reachablePkgEdge)
	}

	unreachableScanEdge := findOutEdge(g, run.ID, graph.EdgeKindFoundVuln, vulnerabilityNodeID(unreachableVuln))
	if unreachableScanEdge == nil {
		t.Fatalf("expected scan -> unreachable vulnerability edge")
	}
	if got := graphValueBool(unreachableScanEdge.Properties["reachable"]); got {
		t.Fatalf("expected unreachable scan vulnerability edge, got %#v", unreachableScanEdge.Properties)
	}
	if got := graphValueString(unreachableScanEdge.Properties["priority_hint"]); got != "unreachable_direct" {
		t.Fatalf("expected unreachable_direct priority_hint, got %#v", unreachableScanEdge.Properties)
	}
	if unreachableScanEdge.Risk != graph.RiskHigh {
		t.Fatalf("expected unreachable scan vulnerability edge risk high, got %#v", unreachableScanEdge)
	}

	unreachablePkgEdge := findOutEdge(g, packageNodeID(unreachableDirect), graph.EdgeKindAffectedBy, vulnerabilityNodeID(unreachableVuln))
	if unreachablePkgEdge == nil {
		t.Fatalf("expected package -> unreachable vulnerability edge")
	}
	if unreachablePkgEdge.Risk != graph.RiskHigh {
		t.Fatalf("expected unreachable package vulnerability edge risk high, got %#v", unreachablePkgEdge)
	}
}

func TestMaterializeRunsIntoGraphDownranksUnreachableCriticalVulnerabilities(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-unreachable-critical", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "lodash",
		Version:          "4.17.21",
		PURL:             "pkg:npm/lodash@4.17.21",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        false,
		DependencyDepth:  1,
	}}
	run.Volumes[0].Analysis.Catalog.Vulnerabilities = []scanner.ImageVulnerability{{
		CVE:              "CVE-2026-3000",
		Severity:         "CRITICAL",
		Package:          "lodash",
		InstalledVersion: "4.17.21",
		FixedVersion:     "4.17.22",
	}}
	run.Summary.Findings = 1
	run.Volumes[0].Analysis.FindingCount = 1

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if scanNode.Risk != graph.RiskHigh {
		t.Fatalf("expected unreachable critical vulnerability to downrank scan risk to high, got %#v", scanNode)
	}
	if got := graphValueInt(scanNode.Properties["reachable_vulnerability_count"]); got != 0 {
		t.Fatalf("expected reachable_vulnerability_count=0, got %#v", scanNode.Properties)
	}
}

func TestMaterializeRunsIntoGraphKeepsKnownExploitedVulnerabilitiesCriticalWithoutReachability(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-unreachable-kev", now.Add(-2*time.Hour), 0)
	pkg := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "lodash",
		Version:          "4.17.21",
		PURL:             "pkg:npm/lodash@4.17.21",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        false,
		DependencyDepth:  1,
	}
	vuln := scanner.ImageVulnerability{
		CVE:              "CVE-2026-3150",
		Severity:         "HIGH",
		Package:          "lodash",
		InstalledVersion: "4.17.21",
		FixedVersion:     "4.17.22",
		InKEV:            true,
	}
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{pkg}
	run.Volumes[0].Analysis.Catalog.Vulnerabilities = []scanner.ImageVulnerability{vuln}

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if scanNode.Risk != graph.RiskCritical {
		t.Fatalf("expected known-exploited vulnerability to keep scan risk critical, got %#v", scanNode)
	}
	scanEdge := findOutEdge(g, run.ID, graph.EdgeKindFoundVuln, vulnerabilityNodeID(vuln))
	if scanEdge == nil {
		t.Fatalf("expected scan -> vulnerability edge")
	}
	if scanEdge.Risk != graph.RiskCritical {
		t.Fatalf("expected known-exploited scan edge to remain critical, got %#v", scanEdge)
	}
	pkgEdge := findOutEdge(g, packageNodeID(pkg), graph.EdgeKindAffectedBy, vulnerabilityNodeID(vuln))
	if pkgEdge == nil {
		t.Fatalf("expected package -> vulnerability edge")
	}
	if pkgEdge.Risk != graph.RiskCritical {
		t.Fatalf("expected known-exploited package edge to remain critical, got %#v", pkgEdge)
	}
}

func TestMaterializeRunsIntoGraphKeepsReachableLowVulnerabilitiesLowRisk(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-reachable-low", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "lodash",
		Version:          "4.17.21",
		PURL:             "pkg:npm/lodash@4.17.21",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  1,
	}}
	run.Volumes[0].Analysis.Catalog.Vulnerabilities = []scanner.ImageVulnerability{{
		CVE:              "CVE-2026-3100",
		Severity:         "LOW",
		Package:          "lodash",
		InstalledVersion: "4.17.21",
		FixedVersion:     "4.17.22",
	}}

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if scanNode.Risk != graph.RiskLow {
		t.Fatalf("expected reachable low vulnerability to keep scan risk low, got %#v", scanNode)
	}
}

func TestMaterializeRunsIntoGraphPrefersReachableDuplicatePackageContext(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-duplicate-package-priority", now.Add(-2*time.Hour), 0)
	reachablePkg := filesystemanalyzer.PackageRecord{
		Ecosystem:        "npm",
		Manager:          "npm",
		Name:             "express",
		Version:          "4.18.2",
		PURL:             "pkg:npm/express@4.18.2",
		Location:         "srv/app/package-lock.json",
		DirectDependency: true,
		Reachable:        true,
		DependencyDepth:  1,
		ImportFileCount:  2,
	}
	unreachablePkg := reachablePkg
	unreachablePkg.Reachable = false
	unreachablePkg.ImportFileCount = 0
	run.Volumes[0].Analysis.Catalog.Packages = []filesystemanalyzer.PackageRecord{unreachablePkg}
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
				Packages: []filesystemanalyzer.PackageRecord{reachablePkg},
				Vulnerabilities: []scanner.ImageVulnerability{{
					CVE:              "CVE-2026-3200",
					Severity:         "CRITICAL",
					Package:          "express",
					InstalledVersion: "4.18.2",
					FixedVersion:     "4.18.3",
				}},
			},
		},
	})
	run.Volumes[0].Analysis.Catalog.Vulnerabilities = []scanner.ImageVulnerability{{
		CVE:              "CVE-2026-3200",
		Severity:         "CRITICAL",
		Package:          "express",
		InstalledVersion: "4.18.2",
		FixedVersion:     "4.18.3",
	}}

	MaterializeRunsIntoGraph(g, []RunRecord{run}, now)

	vuln := scanner.ImageVulnerability{CVE: "CVE-2026-3200"}
	scanEdge := findOutEdge(g, run.ID, graph.EdgeKindFoundVuln, vulnerabilityNodeID(vuln))
	if scanEdge == nil {
		t.Fatalf("expected scan -> vulnerability edge")
	}
	if got := graphValueBool(scanEdge.Properties["reachable"]); !got {
		t.Fatalf("expected reachable duplicate package context to win, got %#v", scanEdge.Properties)
	}
	if got := graphValueString(scanEdge.Properties["priority_hint"]); got != "reachable_direct" {
		t.Fatalf("expected reachable_direct priority_hint, got %#v", scanEdge.Properties)
	}
	if got := graphValueInt(scanEdge.Properties["import_file_count"]); got != 2 {
		t.Fatalf("expected reachable duplicate package import_file_count=2, got %#v", scanEdge.Properties)
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
	if got, ok := observationNode.PropertyValue("observation_type"); !ok || graphValueString(got) != "workload_iac_finding" {
		t.Fatalf("expected observation_type workload_iac_finding, got %#v ok=%t", got, ok)
	}
	if got := graphValueString(observationNode.Properties["resource_type"]); got != "terraform_state" {
		t.Fatalf("expected observation resource_type terraform_state, got %#v", observationNode.Properties)
	}
	if edge := findOutEdge(g, observationID, graph.EdgeKindTargets, run.ID); edge == nil {
		t.Fatalf("expected observation to target scan node, got %#v", g.GetOutEdges(observationID))
	}
}

func TestMaterializeRunsIntoGraphAddsMalwareObservations(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-malware", now.Add(-2*time.Hour), 0)
	run.Summary.Findings = 1
	run.Volumes[0].Analysis.FindingCount = 1
	run.Volumes[0].Analysis.Catalog.Malware = []filesystemanalyzer.MalwareFinding{{
		ID:          "malware:/bin/payload.sh",
		Path:        "bin/payload.sh",
		Hash:        "abc123",
		MalwareType: "signature_match",
		MalwareName: "Eicar-Test-Signature",
		Severity:    "critical",
		Confidence:  90,
		Engine:      "clamav_binary",
	}}

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.ObservationNodesUpserted != 1 {
		t.Fatalf("expected one malware observation node, got %#v", summary)
	}
	if summary.ScanObservationEdges != 1 {
		t.Fatalf("expected one malware observation edge, got %#v", summary)
	}

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if scanNode.Risk != graph.RiskCritical {
		t.Fatalf("expected malware to raise scan risk to critical, got %#v", scanNode)
	}
	if got := graphValueInt(scanNode.Properties["malware_count"]); got != 1 {
		t.Fatalf("expected malware_count=1, got %#v", scanNode.Properties)
	}

	observationID := malwareObservationNodeID(run.ID, run.Volumes[0].Analysis.Catalog.Malware[0])
	observationNode, ok := g.GetNode(observationID)
	if !ok {
		t.Fatalf("expected malware observation node %q", observationID)
	}
	if got, ok := observationNode.PropertyValue("observation_type"); !ok || graphValueString(got) != "workload_malware_finding" {
		t.Fatalf("expected malware observation type, got %#v ok=%t", got, ok)
	}
	if got := graphValueString(observationNode.Properties["malware_name"]); got != "Eicar-Test-Signature" {
		t.Fatalf("expected malware name property, got %#v", observationNode.Properties)
	}
	if edge := findOutEdge(g, observationID, graph.EdgeKindTargets, run.ID); edge == nil {
		t.Fatalf("expected malware observation to target scan node, got %#v", g.GetOutEdges(observationID))
	}
}

func TestMaterializeRunsIntoGraphAddsTechnologyInventory(t *testing.T) {
	now := time.Date(2026, 3, 12, 18, 0, 0, 0, time.UTC)
	targetID := "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123"
	g := graph.New()
	g.AddNode(&graph.Node{
		ID:       targetID,
		Kind:     graph.NodeKindInstance,
		Name:     "i-abc123",
		Provider: "aws",
		Account:  "123456789012",
		Region:   "us-east-1",
	})
	g.BuildIndex()

	run := buildGraphMaterializationTestRun("workload_scan:run-tech", now.Add(-2*time.Hour), 0)
	run.Volumes[0].Analysis.Catalog.Technologies = []filesystemanalyzer.TechnologyRecord{
		{Name: "nginx", Category: "web_server", Path: "etc/nginx/nginx.conf"},
		{Name: "nodejs", Category: "runtime", Version: "20.11.1", Path: "srv/app/package.json"},
	}
	startedAt := now.Add(-2*time.Hour - 15*time.Minute)
	completedAt := now.Add(-2 * time.Hour)
	run.Volumes = append(run.Volumes, VolumeScanRecord{
		Source:      SourceVolume{ID: "vol-2"},
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		StartedAt:   startedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
		Analysis: &AnalysisReport{
			Catalog: &filesystemanalyzer.Report{
				Technologies: []filesystemanalyzer.TechnologyRecord{
					{Name: "nginx", Category: "web_server", Path: "usr/local/etc/nginx/nginx.conf"},
					{Name: "postgresql", Category: "database", Version: "16", Path: "var/lib/postgresql/data/PG_VERSION"},
				},
			},
		},
	})
	run.Summary.VolumeCount = 2
	run.Summary.SucceededVolumes = 2

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.TechnologyNodesUpserted != 3 {
		t.Fatalf("expected 3 technology nodes, got %#v", summary)
	}
	if summary.WorkloadTechnologyEdges != 3 {
		t.Fatalf("expected 3 workload technology edges, got %#v", summary)
	}

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if got := graphValueInt(scanNode.Properties["technology_count"]); got != 3 {
		t.Fatalf("expected technology_count=3, got %#v", scanNode.Properties)
	}

	nodejsID := technologyNodeID(filesystemanalyzer.TechnologyRecord{Name: "nodejs", Category: "runtime", Version: "20.11.1"})
	nodejsNode, ok := g.GetNode(nodejsID)
	if !ok {
		t.Fatalf("expected technology node %q", nodejsID)
	}
	if nodejsNode.Kind != graph.NodeKindTechnology {
		t.Fatalf("expected technology node kind, got %#v", nodejsNode)
	}
	if edge := findOutEdge(g, targetID, graph.EdgeKindRuns, nodejsID); edge == nil {
		t.Fatalf("expected workload->technology runs edge, got %#v", g.GetOutEdges(targetID))
	}
}

func TestMaterializeRunsIntoGraphKeepsTechnologyNodesCanonicalAcrossWorkloads(t *testing.T) {
	now := time.Date(2026, 3, 14, 18, 0, 0, 0, time.UTC)
	g := graph.New()
	firstTargetID := "arn:aws:ec2:us-east-1:123456789012:instance/i-first"
	secondTargetID := "arn:aws:ec2:us-east-1:123456789012:instance/i-second"
	for _, id := range []string{firstTargetID, secondTargetID} {
		g.AddNode(&graph.Node{
			ID:       id,
			Kind:     graph.NodeKindInstance,
			Name:     strings.TrimPrefix(id[strings.LastIndex(id, "/")+1:], "/"),
			Provider: "aws",
			Account:  "123456789012",
			Region:   "us-east-1",
		})
	}
	g.BuildIndex()

	buildRun := func(id, instanceID, path string, completedAt time.Time) RunRecord {
		run := buildGraphMaterializationTestRun(id, completedAt, 0)
		run.Target.InstanceID = instanceID
		run.Volumes[0].Analysis.Catalog.Technologies = []filesystemanalyzer.TechnologyRecord{
			{Name: "nodejs", Category: "runtime", Version: "20.11.1", Path: path},
		}
		return run
	}

	firstRun := buildRun("workload_scan:first-tech", "i-first", "srv/app/package.json", now.Add(-2*time.Hour))
	secondRun := buildRun("workload_scan:second-tech", "i-second", "workspace/package.json", now.Add(-1*time.Hour))

	summary := MaterializeRunsIntoGraph(g, []RunRecord{firstRun, secondRun}, now)
	if summary.TechnologyNodesUpserted != 2 {
		t.Fatalf("expected two technology upserts across workloads, got %#v", summary)
	}

	techID := technologyNodeID(filesystemanalyzer.TechnologyRecord{Name: "nodejs", Category: "runtime", Version: "20.11.1"})
	techNode, ok := g.GetNode(techID)
	if !ok {
		t.Fatalf("expected technology node %q", techID)
	}
	if got := graphNodePropertyString(techNode, "source_event_id"); got != "" {
		t.Fatalf("expected canonical technology node to omit source_event_id, got %#v", techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "source_system"); got != graphMaterializationSourceSystem {
		t.Fatalf("expected canonical technology node source_system=%q, got %#v", graphMaterializationSourceSystem, techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "observed_at"); got != formatTime(observedAt(firstRun)) {
		t.Fatalf("expected canonical technology node observed_at=%q, got %#v", formatTime(observedAt(firstRun)), techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "valid_from"); got != formatTime(runValidFrom(firstRun, observedAt(firstRun))) {
		t.Fatalf("expected canonical technology node valid_from=%q, got %#v", formatTime(runValidFrom(firstRun, observedAt(firstRun))), techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "recorded_at"); got != formatTime(observedAt(firstRun)) {
		t.Fatalf("expected canonical technology node recorded_at=%q, got %#v", formatTime(observedAt(firstRun)), techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "transaction_from"); got != formatTime(observedAt(firstRun)) {
		t.Fatalf("expected canonical technology node transaction_from=%q, got %#v", formatTime(observedAt(firstRun)), techNode.PropertyMap())
	}
	if got := graphValueString(techNode.Properties["file_path"]); got != "" {
		t.Fatalf("expected canonical technology node to omit workload file_path, got %#v", techNode.Properties)
	}

	firstEdge := findOutEdge(g, firstTargetID, graph.EdgeKindRuns, techID)
	if firstEdge == nil {
		t.Fatalf("expected first workload -> technology edge")
	}
	if got := graphValueString(firstEdge.Properties["file_path"]); got != "srv/app/package.json" {
		t.Fatalf("expected first edge file_path, got %#v", firstEdge.Properties)
	}
	secondEdge := findOutEdge(g, secondTargetID, graph.EdgeKindRuns, techID)
	if secondEdge == nil {
		t.Fatalf("expected second workload -> technology edge")
	}
	if got := graphValueString(secondEdge.Properties["file_path"]); got != "workspace/package.json" {
		t.Fatalf("expected second edge file_path, got %#v", secondEdge.Properties)
	}
}

func TestMaterializeRunsIntoGraphAcceptsCanonicalTechnologyNodesUnderSchemaEnforcement(t *testing.T) {
	now := time.Date(2026, 3, 14, 18, 0, 0, 0, time.UTC)
	g := graph.New()
	g.SetSchemaValidationMode(graph.SchemaValidationEnforce)
	firstTargetID := "arn:aws:ec2:us-east-1:123456789012:instance/i-first"
	secondTargetID := "arn:aws:ec2:us-east-1:123456789012:instance/i-second"
	for _, id := range []string{firstTargetID, secondTargetID} {
		g.AddNode(&graph.Node{
			ID:       id,
			Kind:     graph.NodeKindInstance,
			Name:     strings.TrimPrefix(id[strings.LastIndex(id, "/")+1:], "/"),
			Provider: "aws",
			Account:  "123456789012",
			Region:   "us-east-1",
		})
	}
	g.BuildIndex()

	buildRun := func(id, instanceID, path string, completedAt time.Time) RunRecord {
		run := buildGraphMaterializationTestRun(id, completedAt, 0)
		run.Target.InstanceID = instanceID
		run.Volumes[0].Analysis.Catalog.Technologies = []filesystemanalyzer.TechnologyRecord{
			{Name: "nodejs", Category: "runtime", Version: "20.11.1", Path: path},
		}
		return run
	}

	laterRun := buildRun("workload_scan:later-tech", "i-first", "srv/app/package.json", now.Add(-1*time.Hour))
	earlierRun := buildRun("workload_scan:earlier-tech", "i-second", "workspace/package.json", now.Add(-2*time.Hour))

	summary := MaterializeRunsIntoGraph(g, []RunRecord{laterRun}, now)
	if summary.TechnologyNodesUpserted != 1 {
		t.Fatalf("expected first materialization to upsert one technology node, got %#v", summary)
	}
	summary = MaterializeRunsIntoGraph(g, []RunRecord{earlierRun}, now)
	if summary.TechnologyNodesUpserted != 1 {
		t.Fatalf("expected second materialization to upsert one technology node, got %#v", summary)
	}

	techID := technologyNodeID(filesystemanalyzer.TechnologyRecord{Name: "nodejs", Category: "runtime", Version: "20.11.1"})
	techNode, ok := g.GetNode(techID)
	if !ok {
		t.Fatalf("expected technology node %q to survive schema enforcement", techID)
	}
	if got := graphNodePropertyString(techNode, "observed_at"); got != formatTime(observedAt(earlierRun)) {
		t.Fatalf("expected earliest observed_at to be preserved, got %#v", techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "valid_from"); got != formatTime(runValidFrom(earlierRun, observedAt(earlierRun))) {
		t.Fatalf("expected earliest valid_from to be preserved, got %#v", techNode.PropertyMap())
	}
	if got := graphNodePropertyString(techNode, "source_event_id"); got != "" {
		t.Fatalf("expected canonical technology node to omit workload-specific source_event_id, got %#v", techNode.PropertyMap())
	}
}

func TestMaterializeRunsIntoGraphCountsMalwareFindingsAcrossVolumes(t *testing.T) {
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

	run := buildGraphMaterializationTestRun("workload_scan:run-malware-duplicate", now.Add(-2*time.Hour), 0)
	run.Summary.VolumeCount = 2
	run.Summary.SucceededVolumes = 2
	run.Summary.Findings = 2
	run.Volumes[0].Analysis.FindingCount = 1
	run.Volumes[0].Analysis.Catalog.Malware = []filesystemanalyzer.MalwareFinding{{
		ID:          "malware:/bin/payload.sh",
		Path:        "bin/payload.sh",
		Hash:        "abc123",
		MalwareType: "signature_match",
		MalwareName: "Eicar-Test-Signature",
		Severity:    "critical",
		Confidence:  90,
		Engine:      "clamav_binary",
	}}

	startedAt := now.Add(-2*time.Hour - 15*time.Minute)
	completedAt := now.Add(-2 * time.Hour)
	run.Volumes = append(run.Volumes, VolumeScanRecord{
		Source:      SourceVolume{ID: "vol-2"},
		Status:      RunStatusSucceeded,
		Stage:       RunStageCompleted,
		StartedAt:   startedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
		Analysis: &AnalysisReport{
			FindingCount: 1,
			Catalog: &filesystemanalyzer.Report{
				Malware: []filesystemanalyzer.MalwareFinding{{
					ID:          "malware:/bin/payload.sh",
					Path:        "bin/payload.sh",
					Hash:        "abc123",
					MalwareType: "signature_match",
					MalwareName: "Eicar-Test-Signature",
					Severity:    "critical",
					Confidence:  90,
					Engine:      "clamav_binary",
				}},
			},
		},
	})

	summary := MaterializeRunsIntoGraph(g, []RunRecord{run}, now)
	if summary.ObservationNodesUpserted != 1 {
		t.Fatalf("expected deduped malware observation node, got %#v", summary)
	}

	scanNode, ok := g.GetNode(run.ID)
	if !ok {
		t.Fatalf("expected workload scan node %q", run.ID)
	}
	if got := graphValueInt(scanNode.Properties["malware_count"]); got != 2 {
		t.Fatalf("expected malware_count=2 across volumes, got %#v", scanNode.Properties)
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

func graphNodePropertyString(node *graph.Node, key string) string {
	if node == nil {
		return ""
	}
	value, ok := node.PropertyValue(key)
	if !ok {
		return ""
	}
	return graphValueString(value)
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

func graphValueBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		return false
	}
}

func testSBOMComponentRef(pkg filesystemanalyzer.PackageRecord) string {
	value := strings.ToLower(strings.TrimSpace(pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version + "|" + pkg.Location))
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "@", "_", ".", "_", "=", "_", "|", "_")
	return "pkg:" + replacer.Replace(value)
}
