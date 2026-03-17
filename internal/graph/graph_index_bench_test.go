package graph

import (
	"fmt"
	"testing"
)

func BenchmarkGraphIncrementalNodeLookupIndexAddNode(b *testing.B) {
	base := New()
	for i := 0; i < 10_000; i++ {
		base.AddNode(&Node{
			ID:       fmt.Sprintf("workload:%d", i),
			Kind:     NodeKindWorkload,
			Account:  fmt.Sprintf("acct-%d", i%20),
			Provider: "aws",
			Risk:     RiskLow,
		})
	}

	b.Run("incremental_lookup_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddNode(&Node{
				ID:       fmt.Sprintf("identity:%d", i),
				Kind:     NodeKindUser,
				Account:  "acct-0",
				Provider: "aws",
				Risk:     RiskHigh,
			})
			if got := len(g.GetNodesByAccountIndexed("acct-0")); got == 0 {
				b.Fatalf("GetNodesByAccountIndexed(acct-0) = %d, want non-zero", got)
			}
		}
	})

	b.Run("full_rebuild_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddNode(&Node{
				ID:       fmt.Sprintf("identity:%d", i),
				Kind:     NodeKindUser,
				Account:  "acct-0",
				Provider: "aws",
				Risk:     RiskHigh,
			})
			g.BuildIndex()
			if got := len(g.GetNodesByAccountIndexed("acct-0")); got == 0 {
				b.Fatalf("GetNodesByAccountIndexed(acct-0) = %d, want non-zero", got)
			}
		}
	})
}
