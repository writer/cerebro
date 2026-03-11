package attackpath

import (
	"context"
	"testing"
)

func TestGraphAddNode(t *testing.T) {
	g := NewGraph()

	node := &Node{
		ID:       "node-1",
		Type:     NodeTypeCompute,
		Name:     "web-server",
		Provider: "aws",
		Account:  "123456789",
		Region:   "us-east-1",
		Risk:     RiskMedium,
	}

	g.AddNode(node)

	got, ok := g.GetNode("node-1")
	if !ok {
		t.Fatal("expected to find node")
	}
	if got.Name != "web-server" {
		t.Errorf("expected name 'web-server', got '%s'", got.Name)
	}
}

func TestGraphAddEdge(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "node-1", Name: "source"})
	g.AddNode(&Node{ID: "node-2", Name: "target"})

	edge := &Edge{
		ID:     "edge-1",
		Source: "node-1",
		Target: "node-2",
		Type:   EdgeTypeCanAssume,
		Risk:   RiskHigh,
	}

	g.AddEdge(edge)

	edges := g.GetEdges("node-1")
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Target != "node-2" {
		t.Errorf("expected target 'node-2', got '%s'", edges[0].Target)
	}
}

func TestGraphAddEdge_IgnoresUnknownNodes(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "known", Name: "known"})

	g.AddEdge(&Edge{
		ID:     "edge-unknown",
		Source: "known",
		Target: "missing",
		Type:   EdgeTypeHasAccess,
		Risk:   RiskHigh,
	})

	edges := g.GetEdges("known")
	if len(edges) != 0 {
		t.Fatalf("expected no edges to be added when target node is missing, got %d", len(edges))
	}
}

func TestGraphGetAllNodes(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "node-1", Name: "server-1"})
	g.AddNode(&Node{ID: "node-2", Name: "server-2"})
	g.AddNode(&Node{ID: "node-3", Name: "server-3"})

	nodes := g.GetAllNodes()
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
}

func TestPathFinderFindEntryPoints(t *testing.T) {
	g := NewGraph()

	// External node (entry point)
	g.AddNode(&Node{
		ID:   "external-1",
		Type: NodeTypeExternal,
		Name: "internet",
	})

	// Public resource (entry point)
	g.AddNode(&Node{
		ID:   "public-bucket",
		Type: NodeTypeStorage,
		Name: "public-data",
		Properties: map[string]interface{}{
			"public": true,
		},
	})

	// Private resource (not entry point)
	g.AddNode(&Node{
		ID:   "private-db",
		Type: NodeTypeDatabase,
		Name: "internal-db",
	})

	// Critical finding (entry point)
	g.AddNode(&Node{
		ID:       "vuln-server",
		Type:     NodeTypeCompute,
		Name:     "vuln-server",
		Risk:     RiskCritical,
		Findings: []string{"CVE-2024-1234"},
	})

	pf := NewPathFinder(g, 5)
	entries := pf.findEntryPoints()

	if len(entries) != 3 {
		t.Errorf("expected 3 entry points, got %d", len(entries))
	}

	// Verify entry point IDs
	entryIDs := make(map[string]bool)
	for _, e := range entries {
		entryIDs[e.ID] = true
	}

	if !entryIDs["external-1"] {
		t.Error("expected external-1 to be an entry point")
	}
	if !entryIDs["public-bucket"] {
		t.Error("expected public-bucket to be an entry point")
	}
	if !entryIDs["vuln-server"] {
		t.Error("expected vuln-server to be an entry point")
	}
}

func TestPathFinderBFS(t *testing.T) {
	g := NewGraph()

	// Create a simple graph: A -> B -> C
	g.AddNode(&Node{ID: "A", Name: "A"})
	g.AddNode(&Node{ID: "B", Name: "B"})
	g.AddNode(&Node{ID: "C", Name: "C"})

	g.AddEdge(&Edge{ID: "e1", Source: "A", Target: "B", Type: EdgeTypeCanAssume})
	g.AddEdge(&Edge{ID: "e2", Source: "B", Target: "C", Type: EdgeTypeHasAccess})

	pf := NewPathFinder(g, 5)
	discovered := pf.bfs(context.Background(), "A", 5)

	if _, ok := discovered["B"]; !ok {
		t.Error("expected to discover B from A")
	}
	if _, ok := discovered["C"]; !ok {
		t.Error("expected to discover C from A")
	}

	// Check path to C
	pathToC := discovered["C"]
	if len(pathToC) != 3 {
		t.Errorf("expected path length 3, got %d", len(pathToC))
	}
	if pathToC[0] != "A" || pathToC[1] != "B" || pathToC[2] != "C" {
		t.Errorf("expected path [A, B, C], got %v", pathToC)
	}
}

func TestPathFinderFindPaths(t *testing.T) {
	g := NewGraph()

	// External -> Role -> Admin bucket
	g.AddNode(&Node{
		ID:   "external",
		Type: NodeTypeExternal,
		Name: "internet",
	})
	g.AddNode(&Node{
		ID:   "role",
		Type: NodeTypeRole,
		Name: "assumable-role",
	})
	g.AddNode(&Node{
		ID:   "admin-bucket",
		Type: NodeTypeStorage,
		Name: "admin-secrets",
	})

	g.AddEdge(&Edge{ID: "e1", Source: "external", Target: "role", Type: EdgeTypeExposedTo, Risk: RiskHigh})
	g.AddEdge(&Edge{ID: "e2", Source: "role", Target: "admin-bucket", Type: EdgeTypeHasAccess, Risk: RiskCritical})

	pf := NewPathFinder(g, 5)
	pf.SetHighValueTargets([]string{"admin-bucket"})

	ctx := context.Background()
	paths := pf.FindPaths(ctx)

	if len(paths) != 1 {
		t.Fatalf("expected 1 attack path, got %d", len(paths))
	}

	path := paths[0]
	if len(path.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(path.Steps))
	}
	if path.Severity != RiskHigh && path.Severity != RiskCritical {
		t.Errorf("expected high/critical severity, got %s", path.Severity)
	}
}

func TestPathFinderFindPaths_ContextCancelled(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "external", Type: NodeTypeExternal, Name: "internet"})
	g.AddNode(&Node{ID: "target", Type: NodeTypeDatabase, Name: "db", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "edge", Source: "external", Target: "target", Type: EdgeTypeHasAccess, Risk: RiskHigh})

	pf := NewPathFinder(g, 5)
	pf.SetHighValueTargets([]string{"target"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	paths := pf.FindPaths(ctx)
	if len(paths) != 0 {
		t.Fatalf("expected no paths when context is canceled, got %d", len(paths))
	}
}

func TestPathFinderScorePath(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "A", Name: "A"})
	g.AddNode(&Node{ID: "B", Name: "B"})
	g.AddNode(&Node{ID: "C", Name: "C"})
	g.AddEdge(&Edge{ID: "e1", Source: "A", Target: "B", Type: EdgeTypeCanAssume, Risk: RiskHigh})
	g.AddEdge(&Edge{ID: "e2", Source: "B", Target: "C", Type: EdgeTypeHasAccess, Risk: RiskCritical})

	pf := NewPathFinder(g, 5)
	score := pf.ScorePath([]string{"A", "B", "C"})
	if score != 70 { // high (30) + critical (40)
		t.Fatalf("expected score 70, got %d", score)
	}
}

func TestRiskScore(t *testing.T) {
	tests := []struct {
		risk     RiskLevel
		expected int
	}{
		{RiskCritical, 40},
		{RiskHigh, 30},
		{RiskMedium, 20},
		{RiskLow, 10},
		{RiskNone, 5},
	}

	for _, tt := range tests {
		got := riskScore(tt.risk)
		if got != tt.expected {
			t.Errorf("riskScore(%s) = %d, want %d", tt.risk, got, tt.expected)
		}
	}
}

func TestScoreSeverity(t *testing.T) {
	tests := []struct {
		score    int
		expected RiskLevel
	}{
		{100, RiskCritical},
		{150, RiskCritical},
		{70, RiskHigh},
		{99, RiskHigh},
		{40, RiskMedium},
		{69, RiskMedium},
		{10, RiskLow},
		{39, RiskLow},
	}

	for _, tt := range tests {
		got := scoreSeverity(tt.score)
		if got != tt.expected {
			t.Errorf("scoreSeverity(%d) = %s, want %s", tt.score, got, tt.expected)
		}
	}
}

func TestMapToMITRE(t *testing.T) {
	tests := []struct {
		edgeType   EdgeType
		targetType NodeType
		expected   string
	}{
		{EdgeTypeCanAssume, NodeTypeRole, "T1078"},
		{EdgeTypeExposedTo, NodeTypeCompute, "T1190"},
		{EdgeTypeNetworkAccess, NodeTypeCompute, "T1021"},
		{"unknown", NodeTypeCompute, ""},
	}

	for _, tt := range tests {
		got := mapToMITRE(tt.edgeType, tt.targetType)
		if got != tt.expected {
			t.Errorf("mapToMITRE(%s, %s) = %s, want %s", tt.edgeType, tt.targetType, got, tt.expected)
		}
	}
}

func TestGenerateRemediation(t *testing.T) {
	path := &AttackPath{
		Steps: []AttackStep{
			{Action: string(EdgeTypeCanAssume)},
			{Action: string(EdgeTypeExposedTo)},
			{Action: string(EdgeTypeCanAssume)}, // Duplicate
		},
	}

	remediation := generateRemediation(path)

	// Should deduplicate
	if len(remediation) != 2 {
		t.Errorf("expected 2 unique remediation steps, got %d", len(remediation))
	}
}
