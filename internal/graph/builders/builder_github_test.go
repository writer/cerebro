package builders

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestBuilderBuildsGitHubDependabotGraph(t *testing.T) {
	ctx := context.Background()
	source := newMockDataSource()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	source.setResult(`SELECT id, name, full_name, private, visibility, default_branch, archived, disabled, fork, language, topics, created_at, updated_at, pushed_at FROM github_repositories`, &DataQueryResult{
		Rows: []map[string]any{{
			"id":             1,
			"name":           "cerebro",
			"full_name":      "writer/cerebro",
			"private":        false,
			"visibility":     "public",
			"default_branch": "main",
			"archived":       false,
			"disabled":       false,
		}},
	})
	source.setResult(`SELECT number, repository, state, severity, package_name, package_ecosystem, vulnerable_version_range, patched_version, cve_id, ghsa_id, cvss_score, created_at, updated_at, fixed_at FROM github_dependabot_alerts`, &DataQueryResult{
		Rows: []map[string]any{{
			"number":                   7,
			"repository":               "writer/cerebro",
			"state":                    "open",
			"severity":                 "critical",
			"package_name":             "github.com/example/vuln",
			"package_ecosystem":        "go",
			"vulnerable_version_range": "< 1.2.3",
			"patched_version":          "1.2.3",
			"cve_id":                   "CVE-2026-0001",
			"ghsa_id":                  "GHSA-2026-0001",
			"cvss_score":               9.8,
		}},
	})
	source.setResult(`SELECT number, repository, package_name, package_ecosystem, vulnerable_version_range, patched_version, state, severity, cve_id, ghsa_id FROM github_dependabot_alerts`, &DataQueryResult{
		Rows: []map[string]any{{
			"number":                   7,
			"repository":               "writer/cerebro",
			"state":                    "open",
			"severity":                 "critical",
			"package_name":             "github.com/example/vuln",
			"package_ecosystem":        "go",
			"vulnerable_version_range": "< 1.2.3",
			"patched_version":          "1.2.3",
			"cve_id":                   "CVE-2026-0001",
			"ghsa_id":                  "GHSA-2026-0001",
		}},
	})
	source.setResult(`SELECT number, repository, state, severity, package_name, package_ecosystem, vulnerable_version_range, patched_version, cve_id, ghsa_id, cvss_score FROM github_dependabot_alerts`, &DataQueryResult{
		Rows: []map[string]any{{
			"number":                   7,
			"repository":               "writer/cerebro",
			"state":                    "open",
			"severity":                 "critical",
			"package_name":             "github.com/example/vuln",
			"package_ecosystem":        "go",
			"vulnerable_version_range": "< 1.2.3",
			"patched_version":          "1.2.3",
			"cve_id":                   "CVE-2026-0001",
			"ghsa_id":                  "GHSA-2026-0001",
			"cvss_score":               9.8,
		}},
	})

	builder := NewBuilder(source, logger)
	if err := builder.Build(ctx); err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	g := builder.Graph()

	repoID := githubRepositoryNodeID("writer/cerebro")
	pkgID := githubDependabotPackageNodeID(map[string]any{
		"repository":        "writer/cerebro",
		"package_name":      "github.com/example/vuln",
		"package_ecosystem": "go",
	})
	vulnID := "vulnerability:cve-2026-0001"

	for _, expected := range []struct {
		id   string
		kind NodeKind
	}{
		{repoID, NodeKindRepository},
		{pkgID, NodeKindPackage},
		{vulnID, NodeKindVulnerability},
	} {
		node, ok := g.GetNode(expected.id)
		if !ok {
			t.Fatalf("expected node %s", expected.id)
		}
		if node.Kind != expected.kind {
			t.Fatalf("node %s kind = %s, want %s", expected.id, node.Kind, expected.kind)
		}
		if node.Provider != "github" {
			t.Fatalf("node %s provider = %q, want github", expected.id, node.Provider)
		}
	}

	assertEdgeExists(t, g, repoID, pkgID, EdgeKindContainsPkg)
	assertEdgeExists(t, g, pkgID, vulnID, EdgeKindAffectedBy)
}

func TestGitHubDependabotCDCEventToNode(t *testing.T) {
	node := cdcEventToNode("github_dependabot_alerts", cdcEvent{
		TableName:  "github_dependabot_alerts",
		ResourceID: "writer/cerebro|7",
		Provider:   "github",
		Payload: map[string]any{
			"number":            7,
			"repository":        "writer/cerebro",
			"severity":          "high",
			"package_name":      "github.com/example/vuln",
			"package_ecosystem": "go",
			"cve_id":            "CVE-2026-0001",
			"ghsa_id":           "GHSA-2026-0001",
		},
	})
	if node == nil {
		t.Fatal("expected GitHub Dependabot CDC node")
	}
	if node.ID != "vulnerability:cve-2026-0001" {
		t.Fatalf("node ID = %q", node.ID)
	}
	if node.Kind != NodeKindVulnerability {
		t.Fatalf("node kind = %s, want vulnerability", node.Kind)
	}
	if node.Risk != RiskHigh {
		t.Fatalf("node risk = %s, want high", node.Risk)
	}
}
