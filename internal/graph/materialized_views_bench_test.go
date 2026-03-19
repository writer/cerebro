package graph

import (
	"fmt"
	"testing"
)

func BenchmarkBlastRadiusTopN(b *testing.B) {
	b.Run("cold_materialize", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := newBlastRadiusTopNBenchmarkGraph(24, 3, 4)
			view := BlastRadiusTopN(g, 10, 4)
			if len(view.Entries) == 0 {
				b.Fatal("expected blast radius leaderboard entries")
			}
		}
	})

	b.Run("cached_view", func(b *testing.B) {
		g := newBlastRadiusTopNBenchmarkGraph(24, 3, 4)
		view := BlastRadiusTopN(g, 10, 4)
		if len(view.Entries) == 0 {
			b.Fatal("expected blast radius leaderboard entries")
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			view = BlastRadiusTopN(g, 10, 4)
			if len(view.Entries) == 0 {
				b.Fatal("expected cached blast radius leaderboard entries")
			}
		}
	})
}

func newBlastRadiusTopNBenchmarkGraph(principals, levels, fanout int) *Graph {
	g := New()
	for principalIdx := 0; principalIdx < principals; principalIdx++ {
		principalID := fmt.Sprintf("user:%02d", principalIdx)
		accountID := fmt.Sprintf("acct-%02d", principalIdx%4)
		g.AddNode(&Node{ID: principalID, Kind: NodeKindUser, Name: principalID, Account: accountID})

		currentLevel := []string{principalID}
		for level := 0; level < levels; level++ {
			nextLevel := make([]string, 0, len(currentLevel)*fanout)
			for parentIdx, parentID := range currentLevel {
				for childIdx := 0; childIdx < fanout; childIdx++ {
					nodeID := fmt.Sprintf("p%d-l%d-%d-%d", principalIdx, level, parentIdx, childIdx)
					g.AddNode(&Node{
						ID:      nodeID,
						Kind:    NodeKindRole,
						Account: fmt.Sprintf("acct-%02d", (principalIdx+level+childIdx)%4),
						Risk:    RiskLevel([]string{string(RiskLow), string(RiskMedium), string(RiskHigh), string(RiskCritical)}[(principalIdx+level+childIdx)%4]),
					})
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

		for resourceIdx, parentID := range currentLevel {
			resourceID := fmt.Sprintf("resource:%d:%d", principalIdx, resourceIdx)
			g.AddNode(&Node{
				ID:      resourceID,
				Kind:    NodeKindBucket,
				Account: fmt.Sprintf("acct-%02d", (principalIdx+resourceIdx)%4),
				Risk:    []RiskLevel{RiskLow, RiskMedium, RiskHigh, RiskCritical}[(principalIdx+resourceIdx)%4],
			})
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("%s->%s", parentID, resourceID),
				Source: parentID,
				Target: resourceID,
				Kind:   EdgeKindCanRead,
				Effect: EdgeEffectAllow,
			})
		}
	}
	return g
}
