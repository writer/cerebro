package graph

import (
	"strings"
	"testing"
)

func TestMermaidExportAttackPath(t *testing.T) {
	g := New()

	// Create nodes
	entry := &Node{ID: "entry", Kind: NodeKindUser, Name: "attacker", Provider: "aws"}
	target := &Node{ID: "target", Kind: NodeKindDatabase, Name: "prod-db", Provider: "aws"}
	g.AddNode(entry)
	g.AddNode(target)

	path := &ScoredAttackPath{
		ID:         "path-1",
		EntryPoint: entry,
		Target:     target,
		Steps: []*AttackStep{
			{
				Order:         1,
				FromNode:      "entry",
				ToNode:        "role1",
				Technique:     "AssumeRole",
				MITREAttackID: "T1078",
			},
			{
				Order:         2,
				FromNode:      "role1",
				ToNode:        "target",
				Technique:     "Data Access",
				MITREAttackID: "T1530",
			},
		},
		TotalScore: 85.0,
	}

	exporter := NewMermaidExporter(g)
	mermaid := exporter.ExportAttackPath(path)

	// Verify Mermaid output
	if !strings.Contains(mermaid, "```mermaid") {
		t.Error("output should contain mermaid code block")
	}
	if !strings.Contains(mermaid, "flowchart LR") {
		t.Error("output should be a flowchart")
	}
	if !strings.Contains(mermaid, "attacker") {
		t.Error("output should contain entry point name")
	}
	if !strings.Contains(mermaid, "prod-db") {
		t.Error("output should contain target name")
	}
	if !strings.Contains(mermaid, "AssumeRole") {
		t.Error("output should contain technique")
	}
	if !strings.Contains(mermaid, "T1078") {
		t.Error("output should contain MITRE ATT&CK ID")
	}
}

func TestMermaidExportToxicCombination(t *testing.T) {
	g := New()

	tc := &ToxicCombination{
		ID:          "TC001-test",
		Name:        "Public + Vulnerability",
		Description: "Internet-exposed resource with vulnerability",
		Severity:    SeverityCritical,
		Score:       95.0,
		Factors: []*RiskFactor{
			{Type: RiskFactorExposure, Description: "Public internet exposure"},
			{Type: RiskFactorVulnerability, Description: "CVE-2024-1234"},
		},
		Remediation: []*RemediationStep{
			{Priority: 1, Action: "Patch vulnerability"},
			{Priority: 2, Action: "Restrict network access"},
		},
	}

	exporter := NewMermaidExporter(g)
	mermaid := exporter.ExportToxicCombination(tc)

	if !strings.Contains(mermaid, "```mermaid") {
		t.Error("output should contain mermaid code block")
	}
	if !strings.Contains(mermaid, "flowchart TB") {
		t.Error("output should be a top-bottom flowchart")
	}
	if !strings.Contains(mermaid, "Public + Vulnerability") {
		t.Error("output should contain combination name")
	}
	if !strings.Contains(mermaid, "95") {
		t.Error("output should contain score")
	}
	if !strings.Contains(mermaid, "Remediation") {
		t.Error("output should contain remediation section")
	}
}

func TestMermaidExportBlastRadius(t *testing.T) {
	g := New()

	db := &Node{ID: "db1", Kind: NodeKindDatabase, Name: "prod-db", Provider: "aws", Risk: RiskCritical}
	bucket := &Node{ID: "bucket1", Kind: NodeKindBucket, Name: "data-bucket", Provider: "aws", Risk: RiskMedium}

	g.AddNode(db)
	g.AddNode(bucket)

	result := &BlastRadiusResult{
		PrincipalID:   "user1",
		PrincipalName: "admin-user",
		TotalCount:    2,
		MaxDepth:      2,
		RiskSummary: RiskSummary{
			Critical: 1,
			High:     0,
		},
		ReachableNodes: []*ReachableNode{
			{Node: db, Depth: 1, EdgeKind: EdgeKindCanRead},
			{Node: bucket, Depth: 2, EdgeKind: EdgeKindCanWrite},
		},
	}

	exporter := NewMermaidExporter(g)
	mermaid := exporter.ExportBlastRadius(result)

	if !strings.Contains(mermaid, "admin-user") {
		t.Error("output should contain source node name")
	}
	if !strings.Contains(mermaid, "Distance 1") {
		t.Error("output should contain distance grouping")
	}
	if !strings.Contains(mermaid, "2 reachable nodes") {
		t.Error("output should contain summary")
	}
}

func TestMermaidExportSecurityReport(t *testing.T) {
	g := New()

	// Create minimal graph
	user := &Node{ID: "user1", Kind: NodeKindUser, Name: "test-user", Provider: "aws"}
	g.AddNode(user)

	exporter := NewMermaidExporter(g)

	// Create a mock report
	report := &SecurityReport{
		RiskScore: 65.0,
		GraphStats: &GraphStats{
			TotalNodes:        100,
			TotalEdges:        250,
			IdentityCount:     30,
			ResourceCount:     70,
			CrossAccountEdges: 5,
			PublicExposures:   3,
			CriticalResources: 10,
		},
		ToxicCombinations: []*ToxicCombination{
			{ID: "TC001", Name: "Test Combination", Severity: SeverityCritical, Score: 90.0},
		},
		AttackPaths: &SimulationResult{
			TotalPaths:    5,
			CriticalPaths: 2,
			Paths: []*ScoredAttackPath{
				{ID: "path1", TotalScore: 80.0, Steps: []*AttackStep{}},
			},
		},
		Chokepoints: []*Chokepoint{
			{Node: user, PathsThrough: 3, BlockedPaths: 2, RemediationImpact: 0.6},
		},
		RemediationPlan: &RemediationPlan{
			QuickWins: []*RemediationAction{
				{Action: "Enable MFA"},
			},
			StrategicFixes: []*RemediationAction{
				{Action: "Implement least privilege"},
			},
		},
	}

	mermaid := exporter.ExportSecurityReport(report)

	if !strings.Contains(mermaid, "# Security Report") {
		t.Error("output should have Security Report header")
	}
	if !strings.Contains(mermaid, "Risk Score") {
		t.Error("output should contain risk score section")
	}
	if !strings.Contains(mermaid, "mindmap") {
		t.Error("output should contain mindmap for stats")
	}
	if !strings.Contains(mermaid, "Toxic Combinations") {
		t.Error("output should contain toxic combinations section")
	}
	if !strings.Contains(mermaid, "Chokepoints") {
		t.Error("output should contain chokepoints section")
	}
	if !strings.Contains(mermaid, "gantt") {
		t.Error("output should contain gantt chart for remediation")
	}
}

func TestSanitizeMermaidID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "n_simple"},
		{"with:colon", "n_with_colon"},
		{"with/slash", "n_with_slash"},
		{"arn:aws:iam::123456789:user/admin", "n_arn_aws_iam__123456789_user_admin"},
		{"with space", "n_with_space"},
		{"with[brackets]", "n_with_brackets_"},
	}

	for _, test := range tests {
		result := sanitizeMermaidID(test.input)
		if result != test.expected {
			t.Errorf("sanitizeMermaidID(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}

func TestMermaidExportChokepoints(t *testing.T) {
	g := New()

	nodes := []*Node{
		{ID: "cp1", Kind: NodeKindRole, Name: "admin-role"},
		{ID: "cp2", Kind: NodeKindServiceAccount, Name: "service-sa"},
	}
	for _, n := range nodes {
		g.AddNode(n)
	}

	chokepoints := []*Chokepoint{
		{
			Node:              nodes[0],
			PathsThrough:      10,
			BlockedPaths:      8,
			RemediationImpact: 0.8,
			UpstreamEntries:   []string{"user1", "user2"},
			DownstreamTargets: []string{"db1", "bucket1"},
		},
		{
			Node:              nodes[1],
			PathsThrough:      5,
			BlockedPaths:      4,
			RemediationImpact: 0.6,
			UpstreamEntries:   []string{"lambda1"},
			DownstreamTargets: []string{"secret1"},
		},
	}

	exporter := NewMermaidExporter(g)
	mermaid := exporter.ExportChokepoints(chokepoints)

	if !strings.Contains(mermaid, "Chokepoint Analysis") {
		t.Error("output should have header")
	}
	if !strings.Contains(mermaid, "admin-role") {
		t.Error("output should contain chokepoint node name")
	}
	if !strings.Contains(mermaid, "10 paths") {
		t.Error("output should show paths through")
	}
	if !strings.Contains(mermaid, "80% impact") {
		t.Error("output should show remediation impact")
	}
	if !strings.Contains(mermaid, "| Priority |") {
		t.Error("output should contain summary table")
	}
}
