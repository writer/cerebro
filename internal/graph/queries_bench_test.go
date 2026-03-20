package graph

import (
	"fmt"
	"runtime"
	"testing"
)

func BenchmarkBlastRadius(b *testing.B) {
	g := newBlastRadiusBenchmarkGraph(4, 12)
	principal, ok := g.GetNode("user:start")
	if !ok {
		b.Fatal("missing benchmark principal")
	}

	configs := []struct {
		name    string
		workers int
	}{
		{name: "workers_1", workers: 1},
		{name: "workers_auto", workers: runtime.GOMAXPROCS(0)},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			previous := parallelTraversalWorkerOverride
			parallelTraversalWorkerOverride = config.workers
			defer func() {
				parallelTraversalWorkerOverride = previous
			}()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				result := computeBlastRadius(g, principal, 4)
				if result.TotalCount == 0 {
					b.Fatal("expected blast radius reachability")
				}
			}
		})
	}
}

func BenchmarkEffectiveAccess(b *testing.B) {
	g := newEffectiveAccessBenchmarkGraph(6, 4)
	configs := []struct {
		name    string
		workers int
	}{
		{name: "workers_1", workers: 1},
		{name: "workers_auto", workers: runtime.GOMAXPROCS(0)},
	}

	for _, config := range configs {
		b.Run(config.name, func(b *testing.B) {
			previous := parallelTraversalWorkerOverride
			parallelTraversalWorkerOverride = config.workers
			defer func() {
				parallelTraversalWorkerOverride = previous
			}()

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				result := EffectiveAccess(g, "user:start", "bucket:target", 8)
				if !result.Allowed {
					b.Fatal("expected effective access path")
				}
			}
		})
	}
}

func BenchmarkCascadingBlastRadius(b *testing.B) {
	g := newCascadingBlastRadiusBenchmarkGraph(6, 3)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		result := CascadingBlastRadius(g, "user:start", 8)
		if result.TotalImpact == 0 {
			b.Fatal("expected cascading blast radius impact")
		}
	}
}

func newEffectiveAccessBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "bucket:target", Kind: NodeKindBucket, Account: "111"})

	currentLevel := []string{"user:start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("query-%d-%d-%d", level, parentIdx, childIdx)
				g.AddNode(&Node{ID: nodeID, Kind: NodeKindRole, Account: "111"})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, nodeID),
					Source: parentID,
					Target: nodeID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
				})
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	lastNodeID := currentLevel[len(currentLevel)-1]
	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("%s->bucket:target", lastNodeID),
		Source: lastNodeID,
		Target: "bucket:target",
		Kind:   EdgeKindCanRead,
		Effect: EdgeEffectAllow,
	})

	return g
}

func newCascadingBlastRadiusBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Account: "111"})

	currentLevel := []string{"user:start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("cascade-%d-%d-%d", level, parentIdx, childIdx)
				account := "111"
				if level%2 == 1 && childIdx == fanout-1 {
					account = "222"
				}
				g.AddNode(&Node{
					ID:      nodeID,
					Kind:    NodeKindRole,
					Account: account,
					Risk:    RiskMedium,
				})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, nodeID),
					Source: parentID,
					Target: nodeID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
				})
				if level > 0 {
					g.AddEdge(&Edge{
						ID:     fmt.Sprintf("%s->%s-cycle", nodeID, parentID),
						Source: nodeID,
						Target: parentID,
						Kind:   EdgeKindCanAssume,
						Effect: EdgeEffectAllow,
					})
				}
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	for i, nodeID := range currentLevel {
		resourceID := fmt.Sprintf("bucket:cascade-%d", i)
		g.AddNode(&Node{
			ID:      resourceID,
			Kind:    NodeKindBucket,
			Account: "111",
			Risk:    RiskHigh,
			Properties: map[string]any{
				"contains_pii": i%2 == 0,
			},
		})
		g.AddEdge(&Edge{
			ID:     fmt.Sprintf("%s->%s-data", nodeID, resourceID),
			Source: nodeID,
			Target: resourceID,
			Kind:   EdgeKindCanRead,
			Effect: EdgeEffectAllow,
		})
	}

	return g
}

func newBlastRadiusBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Account: "111"})
	g.AddNode(&Node{ID: "role:shared", Kind: NodeKindRole, Account: "222"})
	g.AddNode(&Node{ID: "bucket:shared", Kind: NodeKindBucket, Account: "222", Risk: RiskCritical})
	g.AddEdge(&Edge{ID: "shared->bucket", Source: "role:shared", Target: "bucket:shared", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})

	currentLevel := []string{"user:start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				nodeID := fmt.Sprintf("blast-%d-%d-%d", level, parentIdx, childIdx)
				accountID := "111"
				if level == 0 && childIdx%4 == 0 {
					accountID = "222"
				}
				g.AddNode(&Node{ID: nodeID, Kind: NodeKindRole, Account: accountID})
				g.AddEdge(&Edge{
					ID:         fmt.Sprintf("%s->%s", parentID, nodeID),
					Source:     parentID,
					Target:     nodeID,
					Kind:       EdgeKindCanAssume,
					Effect:     EdgeEffectAllow,
					Properties: map[string]any{"cross_account": accountID != "111", "target_account": accountID},
				})
				if level == levels-1 {
					resourceID := fmt.Sprintf("%s-bucket", nodeID)
					g.AddNode(&Node{ID: resourceID, Kind: NodeKindBucket, Account: accountID, Risk: RiskHigh})
					g.AddEdge(&Edge{
						ID:         fmt.Sprintf("%s->%s-read", nodeID, resourceID),
						Source:     nodeID,
						Target:     resourceID,
						Kind:       EdgeKindCanRead,
						Effect:     EdgeEffectAllow,
						Properties: map[string]any{"actions": []string{"s3:GetObject"}},
					})
					if childIdx%3 == 0 {
						g.AddEdge(&Edge{
							ID:         fmt.Sprintf("%s->role:shared", nodeID),
							Source:     nodeID,
							Target:     "role:shared",
							Kind:       EdgeKindCanAssume,
							Effect:     EdgeEffectAllow,
							Properties: map[string]any{"cross_account": true, "target_account": "222"},
						})
					}
				}
				nextLevel = append(nextLevel, nodeID)
			}
		}
		currentLevel = nextLevel
	}

	return g
}
