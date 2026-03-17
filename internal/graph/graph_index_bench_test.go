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

func BenchmarkGraphIncrementalDerivedIndexAddNode(b *testing.B) {
	base := New()
	for i := 0; i < 10_000; i++ {
		base.AddNode(&Node{
			ID:       fmt.Sprintf("workload:%05d", i),
			Kind:     NodeKindWorkload,
			Name:     fmt.Sprintf("payments-service-%05d", i),
			Account:  fmt.Sprintf("acct-%d", i%20),
			Provider: "aws",
			Risk:     RiskLow,
		})
	}

	b.Run("incremental_derived_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddNode(&Node{
				ID:       fmt.Sprintf("workload:new-%d", i),
				Kind:     NodeKindWorkload,
				Name:     fmt.Sprintf("public-payments-%d", i),
				Account:  "acct-0",
				Provider: "aws",
				Risk:     RiskHigh,
				Properties: map[string]any{
					"internet_exposed": true,
				},
			})
			if !g.IsIndexBuilt() {
				b.Fatal("expected derived index to remain built")
			}
			if got := len(g.GetInternetFacingNodes()); got == 0 {
				b.Fatalf("GetInternetFacingNodes() = %d, want non-zero", got)
			}
			if got := len(g.GetCrownJewels()); got == 0 {
				b.Fatalf("GetCrownJewels() = %d, want non-zero", got)
			}
			if got := SearchEntities(g, EntitySearchOptions{Query: "public payments", Limit: 5}).Count; got == 0 {
				b.Fatalf("SearchEntities(public payments) = %d, want non-zero", got)
			}
		}
	})

	b.Run("full_rebuild_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddNode(&Node{
				ID:       fmt.Sprintf("workload:new-%d", i),
				Kind:     NodeKindWorkload,
				Name:     fmt.Sprintf("public-payments-%d", i),
				Account:  "acct-0",
				Provider: "aws",
				Risk:     RiskHigh,
				Properties: map[string]any{
					"internet_exposed": true,
				},
			})
			g.InvalidateIndex()
			g.BuildIndex()
			if got := len(g.GetInternetFacingNodes()); got == 0 {
				b.Fatalf("GetInternetFacingNodes() = %d, want non-zero", got)
			}
			if got := len(g.GetCrownJewels()); got == 0 {
				b.Fatalf("GetCrownJewels() = %d, want non-zero", got)
			}
			if got := SearchEntities(g, EntitySearchOptions{Query: "public payments", Limit: 5}).Count; got == 0 {
				b.Fatalf("SearchEntities(public payments) = %d, want non-zero", got)
			}
		}
	})
}
