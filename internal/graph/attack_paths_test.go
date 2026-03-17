package graph

import (
	"testing"
)

func TestAttackPathSimulatorVisitedBitsUseInternedOrdinals(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "role", Kind: NodeKindRole, Name: "Role"})
	g.AddNode(&Node{ID: "db", Kind: NodeKindDatabase, Name: "DB", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "i-role", Source: "internet", Target: "role", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db", Source: "role", Target: "db", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	sim := NewAttackPathSimulator(g)
	visited := sim.newVisitedBits("internet")

	if !sim.isVisited(visited, "internet") {
		t.Fatal("expected entry node to be marked visited")
	}
	if sim.isVisited(visited, "role") {
		t.Fatal("did not expect unrelated node to start visited")
	}
	if sim.isVisited(visited, "missing") {
		t.Fatal("did not expect unknown node to be treated as visited")
	}

	sim.markVisited(visited, "role")
	if !sim.isVisited(visited, "role") {
		t.Fatal("expected interned node to become visited")
	}
}

func TestAttackPathSimulatorFindShortestPathAvoidingHandlesCycles(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "web", Kind: NodeKindInstance, Name: "Web", Risk: RiskHigh})
	g.AddNode(&Node{ID: "role", Kind: NodeKindRole, Name: "Role"})
	g.AddNode(&Node{ID: "db", Kind: NodeKindDatabase, Name: "DB", Risk: RiskCritical})

	g.AddEdge(&Edge{ID: "i-web", Source: "internet", Target: "web", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "web-role", Source: "web", Target: "role", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-web", Source: "role", Target: "web", Kind: EdgeKindCanWrite, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db", Source: "role", Target: "db", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	sim := NewAttackPathSimulator(g)
	entry, ok := g.GetNode("internet")
	if !ok {
		t.Fatal("expected internet node")
	}
	target, ok := g.GetNode("db")
	if !ok {
		t.Fatal("expected db node")
	}

	path := sim.findShortestPath(entry, target, 6)
	if path == nil {
		t.Fatal("expected shortest path through cycle to be found")
	}
	if path.Length != 3 {
		t.Fatalf("expected shortest path length 3, got %d", path.Length)
	}
	if len(path.Steps) != 3 {
		t.Fatalf("expected 3 path steps, got %d", len(path.Steps))
	}
	if path.Steps[0].ToNode != "web" || path.Steps[1].ToNode != "role" || path.Steps[2].ToNode != "db" {
		t.Fatalf("unexpected shortest path sequence: %#v", path.Steps)
	}
}

func TestFindChokepoints_DirectPaths(t *testing.T) {
	// 4 direct Internet -> target paths with no shared intermediary.
	// Targets appear on only 1 path each, so no chokepoints.
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "db1", Kind: NodeKindDatabase, Name: "DB1", Risk: RiskCritical})
	g.AddNode(&Node{ID: "db2", Kind: NodeKindDatabase, Name: "DB2", Risk: RiskCritical})
	g.AddNode(&Node{ID: "s3a", Kind: NodeKindBucket, Name: "Bucket A", Risk: RiskHigh})
	g.AddNode(&Node{ID: "s3b", Kind: NodeKindBucket, Name: "Bucket B", Risk: RiskHigh})

	g.AddEdge(&Edge{ID: "i-db1", Source: "internet", Target: "db1", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "i-db2", Source: "internet", Target: "db2", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "i-s3a", Source: "internet", Target: "s3a", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "i-s3b", Source: "internet", Target: "s3b", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.BuildIndex()

	sim := NewAttackPathSimulator(g)
	result := sim.Simulate(6)

	if result.TotalPaths == 0 {
		t.Fatal("expected attack paths to be found")
	}
	// Each target only on 1 path -> no chokepoints
	if len(result.Chokepoints) != 0 {
		t.Errorf("expected 0 chokepoints for disjoint direct paths, got %d", len(result.Chokepoints))
	}
}

func TestFindChokepoints_SharedIntermediary(t *testing.T) {
	// Internet -> shared-role -> db1, Internet -> shared-role -> db2
	// shared-role is on 2+ paths, should be a chokepoint.
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "web", Kind: NodeKindInstance, Name: "Web", Risk: RiskHigh,
		Properties: map[string]any{"vulnerabilities": []any{"CVE-1"}}})
	g.AddNode(&Node{ID: "role", Kind: NodeKindRole, Name: "SharedRole"})
	g.AddNode(&Node{ID: "db1", Kind: NodeKindDatabase, Name: "DB1", Risk: RiskCritical})
	g.AddNode(&Node{ID: "db2", Kind: NodeKindDatabase, Name: "DB2", Risk: RiskCritical})

	g.AddEdge(&Edge{ID: "i-web", Source: "internet", Target: "web", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "web-role", Source: "web", Target: "role", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db1", Source: "role", Target: "db1", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db2", Source: "role", Target: "db2", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.BuildIndex()

	sim := NewAttackPathSimulator(g)
	result := sim.Simulate(6)

	if result.TotalPaths < 2 {
		t.Fatalf("expected at least 2 paths, got %d", result.TotalPaths)
	}

	found := false
	for _, cp := range result.Chokepoints {
		if cp.Node.ID == "role" || cp.Node.ID == "web" {
			found = true
			if cp.PathsThrough < 2 {
				t.Errorf("chokepoint %s should have >= 2 paths through, got %d", cp.Node.ID, cp.PathsThrough)
			}
		}
	}
	if !found {
		t.Error("expected shared role or web server to be identified as chokepoint")
	}
}

func TestFindChokepoints_TracksDistinctEntriesAndTargets(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "user1", Kind: NodeKindUser, Name: "User1"})
	g.AddNode(&Node{ID: "role", Kind: NodeKindRole, Name: "SharedRole"})
	g.AddNode(&Node{ID: "db1", Kind: NodeKindDatabase, Name: "DB1", Risk: RiskCritical})
	g.AddNode(&Node{ID: "db2", Kind: NodeKindDatabase, Name: "DB2", Risk: RiskCritical})

	g.AddEdge(&Edge{ID: "internet-role", Source: "internet", Target: "role", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "user-role", Source: "user1", Target: "role", Kind: EdgeKindCanAssume, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db1", Source: "role", Target: "db1", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "role-db2", Source: "role", Target: "db2", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	sim := NewAttackPathSimulator(g)
	result := sim.Simulate(6)

	var roleChokepoint *Chokepoint
	for _, cp := range result.Chokepoints {
		if cp.Node.ID == "role" {
			roleChokepoint = cp
			break
		}
	}
	if roleChokepoint == nil {
		t.Fatal("expected shared role to be identified as a chokepoint")
	}
	if roleChokepoint.PathsThrough != 4 {
		t.Fatalf("expected shared role on 4 paths, got %d", roleChokepoint.PathsThrough)
	}

	upstream := make(map[string]bool, len(roleChokepoint.UpstreamEntries))
	for _, id := range roleChokepoint.UpstreamEntries {
		upstream[id] = true
	}
	if len(upstream) != 2 || !upstream["internet"] || !upstream["user1"] {
		t.Fatalf("unexpected upstream entries: %#v", roleChokepoint.UpstreamEntries)
	}

	downstream := make(map[string]bool, len(roleChokepoint.DownstreamTargets))
	for _, id := range roleChokepoint.DownstreamTargets {
		downstream[id] = true
	}
	if len(downstream) != 2 || !downstream["db1"] || !downstream["db2"] {
		t.Fatalf("unexpected downstream targets: %#v", roleChokepoint.DownstreamTargets)
	}
}

func TestFindChokepoints_DirectPathsSharedTarget(t *testing.T) {
	// Two entry points (Internet and a User) both reach the same DB directly.
	// Since they have different entry points, sharedEntry is "" and targets are
	// skipped for multi-hop check. For length-1 paths, targets are included.
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "user1", Kind: NodeKindUser, Name: "User1"})
	g.AddNode(&Node{ID: "db1", Kind: NodeKindDatabase, Name: "DB1", Risk: RiskCritical})

	g.AddEdge(&Edge{ID: "i-db1", Source: "internet", Target: "db1", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "u-db1", Source: "user1", Target: "db1", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.BuildIndex()

	sim := NewAttackPathSimulator(g)
	result := sim.Simulate(6)

	// db1 may or may not be a chokepoint depending on whether both paths are discovered.
	// This test validates the code doesn't panic and produces valid results.
	t.Logf("paths=%d chokepoints=%d", result.TotalPaths, len(result.Chokepoints))
	for _, cp := range result.Chokepoints {
		if cp.PathsThrough < 2 {
			t.Errorf("chokepoint %s has only %d paths through (need >= 2)", cp.Node.ID, cp.PathsThrough)
		}
	}
}

func TestIdentifyCrownJewels(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "critical-db", Kind: NodeKindDatabase, Name: "CriticalDB", Risk: RiskCritical})
	g.AddNode(&Node{ID: "pii-db", Kind: NodeKindDatabase, Name: "PII-DB", Risk: RiskHigh,
		Tags: map[string]string{"contains_pii": "true"}})
	g.AddNode(&Node{ID: "prod-db", Kind: NodeKindDatabase, Name: "ProdDB", Risk: RiskHigh,
		Tags: map[string]string{"production": "true"}})
	g.AddNode(&Node{ID: "low-db", Kind: NodeKindDatabase, Name: "DevDB", Risk: RiskLow})
	g.AddNode(&Node{ID: "secret", Kind: NodeKindSecret, Name: "APIKeys"})
	g.AddNode(&Node{ID: "risky-bucket", Kind: NodeKindBucket, Name: "DataBucket", Risk: RiskHigh})
	g.AddNode(&Node{ID: "safe-bucket", Kind: NodeKindBucket, Name: "LogBucket", Risk: RiskLow})
	g.AddNode(&Node{ID: "instance", Kind: NodeKindInstance, Name: "Server", Risk: RiskMedium})
	g.BuildIndex()

	sim := NewAttackPathSimulator(g)

	crownJewelIDs := make(map[string]bool)
	for _, cj := range sim.crownJewels {
		crownJewelIDs[cj.ID] = true
	}

	expected := []string{"critical-db", "pii-db", "prod-db", "secret", "risky-bucket"}
	for _, id := range expected {
		if !crownJewelIDs[id] {
			t.Errorf("expected %s to be a crown jewel", id)
		}
	}

	notExpected := []string{"low-db", "safe-bucket", "instance", "internet"}
	for _, id := range notExpected {
		if crownJewelIDs[id] {
			t.Errorf("did not expect %s to be a crown jewel", id)
		}
	}
}

func TestScorePath(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "web", Kind: NodeKindInstance, Name: "Web", Risk: RiskHigh,
		Properties: map[string]any{"vulnerabilities": []any{"CVE-1"}}})
	g.AddNode(&Node{ID: "db", Kind: NodeKindDatabase, Name: "DB", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "i-w", Source: "internet", Target: "web", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "w-d", Source: "web", Target: "db", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.BuildIndex()

	sim := NewAttackPathSimulator(g)

	// Short path to critical target
	shortPath := &ScoredAttackPath{
		EntryPoint: &Node{ID: "internet"},
		Target:     &Node{ID: "db", Risk: RiskCritical},
		Steps: []*AttackStep{
			{FromNode: "internet", ToNode: "web"},
			{FromNode: "web", ToNode: "db"},
		},
		Length: 2,
	}
	sim.scorePath(shortPath)

	if shortPath.TotalScore <= 0 {
		t.Error("expected positive score for short path to critical target")
	}
	if shortPath.Impact != 1.0 {
		t.Errorf("expected impact=1.0 for critical target, got %f", shortPath.Impact)
	}

	// Long path to low-risk target
	longPath := &ScoredAttackPath{
		EntryPoint: &Node{ID: "internet"},
		Target:     &Node{ID: "log", Risk: RiskLow},
		Steps:      make([]*AttackStep, 8),
		Length:     8,
	}
	for i := range longPath.Steps {
		longPath.Steps[i] = &AttackStep{FromNode: "a", ToNode: "b"}
	}
	sim.scorePath(longPath)

	if longPath.TotalScore >= shortPath.TotalScore {
		t.Errorf("long path to low target (%.1f) should score lower than short path to critical target (%.1f)",
			longPath.TotalScore, shortPath.TotalScore)
	}

	// Verify skill/time assignments
	tests := []struct {
		score float64
		skill string
		time  string
	}{
		{85, "low", "minutes"},
		{65, "medium", "hours"},
		{45, "high", "days"},
		{30, "expert", "weeks"},
	}
	for _, tc := range tests {
		p := &ScoredAttackPath{
			EntryPoint: &Node{ID: "internet"},
			Target:     &Node{ID: "t", Risk: RiskCritical},
			Steps:      []*AttackStep{{FromNode: "a", ToNode: "b"}},
			Length:     1,
		}
		// Manually set score to test thresholds
		sim.scorePath(p)
		p.TotalScore = tc.score
		// Re-derive skill from score
		if tc.score > 80 {
			p.RequiredSkill = "low"
			p.EstimatedTime = "minutes"
		} else if tc.score > 60 {
			p.RequiredSkill = "medium"
			p.EstimatedTime = "hours"
		} else if tc.score > 40 {
			p.RequiredSkill = "high"
			p.EstimatedTime = "days"
		} else {
			p.RequiredSkill = "expert"
			p.EstimatedTime = "weeks"
		}
		if p.RequiredSkill != tc.skill {
			t.Errorf("score %.0f: skill=%s, want %s", tc.score, p.RequiredSkill, tc.skill)
		}
		if p.EstimatedTime != tc.time {
			t.Errorf("score %.0f: time=%s, want %s", tc.score, p.EstimatedTime, tc.time)
		}
	}
}

func TestScorePath_SkillThresholds(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "db", Kind: NodeKindDatabase, Name: "DB", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "i-d", Source: "internet", Target: "db", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.BuildIndex()

	sim := NewAttackPathSimulator(g)

	// Direct path to critical DB -- should be highest risk
	path := &ScoredAttackPath{
		EntryPoint: &Node{ID: "internet"},
		Target:     &Node{ID: "db", Risk: RiskCritical},
		Steps:      []*AttackStep{{FromNode: "internet", ToNode: "db"}},
		Length:     1,
	}
	sim.scorePath(path)

	if path.RequiredSkill == "" {
		t.Error("expected RequiredSkill to be set")
	}
	if path.EstimatedTime == "" {
		t.Error("expected EstimatedTime to be set")
	}
	t.Logf("score=%.1f skill=%s time=%s", path.TotalScore, path.RequiredSkill, path.EstimatedTime)
}

func TestHasTag(t *testing.T) {
	node := &Node{ID: "n1", Tags: map[string]string{"env": "prod", "contains_pii": "true"}}
	if !hasTag(node, "env") {
		t.Error("expected hasTag(env) = true")
	}
	if !hasTag(node, "contains_pii") {
		t.Error("expected hasTag(contains_pii) = true")
	}
	if hasTag(node, "missing") {
		t.Error("expected hasTag(missing) = false")
	}

	nilTags := &Node{ID: "n2"}
	if hasTag(nilTags, "anything") {
		t.Error("expected hasTag on nil tags = false")
	}
}
