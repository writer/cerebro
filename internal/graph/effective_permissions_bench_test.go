package graph

import (
	"fmt"
	"testing"
)

func BenchmarkEffectivePermissionsCalculatorCalculateWithContext(b *testing.B) {
	g := newEffectivePermissionsBenchmarkGraph(5, 3)
	calc := NewEffectivePermissionsCalculator(g)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ep := calc.CalculateWithContext("user:start", nil)
		if ep == nil || len(ep.Resources) == 0 {
			b.Fatal("expected effective permissions result")
		}
	}
}

func newEffectivePermissionsBenchmarkGraph(levels, fanout int) *Graph {
	g := New()
	g.AddNode(&Node{ID: "user:start", Kind: NodeKindUser, Account: "111", Provider: "aws"})

	currentLevel := []string{"user:start"}
	for level := 0; level < levels; level++ {
		nextLevel := make([]string, 0, len(currentLevel)*fanout)
		for parentIdx, parentID := range currentLevel {
			for childIdx := 0; childIdx < fanout; childIdx++ {
				roleID := fmt.Sprintf("role:%d-%d-%d", level, parentIdx, childIdx)
				g.AddNode(&Node{ID: roleID, Kind: NodeKindRole, Account: "111", Provider: "aws"})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s", parentID, roleID),
					Source: parentID,
					Target: roleID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
				})
				if level > 0 {
					g.AddEdge(&Edge{
						ID:     fmt.Sprintf("%s->%s-cycle", roleID, parentID),
						Source: roleID,
						Target: parentID,
						Kind:   EdgeKindCanAssume,
						Effect: EdgeEffectAllow,
					})
				}
				resourceID := fmt.Sprintf("bucket:%d-%d-%d", level, parentIdx, childIdx)
				g.AddNode(&Node{ID: resourceID, Kind: NodeKindBucket, Account: "111", Provider: "aws"})
				g.AddEdge(&Edge{
					ID:     fmt.Sprintf("%s->%s-read", roleID, resourceID),
					Source: roleID,
					Target: resourceID,
					Kind:   EdgeKindCanRead,
					Effect: EdgeEffectAllow,
				})
				nextLevel = append(nextLevel, roleID)
			}
		}
		currentLevel = nextLevel
	}

	return g
}
