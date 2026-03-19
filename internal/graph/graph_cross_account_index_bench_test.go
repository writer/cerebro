package graph

import (
	"fmt"
	"testing"
)

func BenchmarkGraphIncrementalCrossAccountEdgeIndexAddEdge(b *testing.B) {
	base := New()
	for i := 0; i < 5000; i++ {
		account := "acct-a"
		if i%2 == 1 {
			account = "acct-b"
		}
		base.AddNode(&Node{
			ID:      fmt.Sprintf("role:%d", i),
			Kind:    NodeKindRole,
			Account: account,
		})
	}
	base.AddNode(&Node{ID: "user:attacker", Kind: NodeKindUser, Account: "acct-a"})

	b.Run("incremental_cross_account_query_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("edge:%d", i),
				Source: "user:attacker",
				Target: fmt.Sprintf("role:%d", (2*i+1)%5000),
				Kind:   EdgeKindCanAssume,
				Properties: map[string]any{
					"cross_account": true,
				},
			})
			if got := len(g.GetCrossAccountEdgesIndexed()); got == 0 {
				b.Fatalf("GetCrossAccountEdgesIndexed() = %d, want non-zero", got)
			}
		}
	})

	b.Run("full_rebuild_cross_account_query_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddEdge(&Edge{
				ID:     fmt.Sprintf("edge:%d", i),
				Source: "user:attacker",
				Target: fmt.Sprintf("role:%d", (2*i+1)%5000),
				Kind:   EdgeKindCanAssume,
				Properties: map[string]any{
					"cross_account": true,
				},
			})
			g.BuildIndex()
			if got := len(g.GetCrossAccountEdgesIndexed()); got == 0 {
				b.Fatalf("GetCrossAccountEdgesIndexed() = %d, want non-zero", got)
			}
		}
	})
}
