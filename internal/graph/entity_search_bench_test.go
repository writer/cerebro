package graph

import (
	"fmt"
	"testing"
)

func BenchmarkGraphBuildIndexEntitySearchCorpus(b *testing.B) {
	g := New()
	for i := 0; i < 10000; i++ {
		g.AddNode(&Node{
			ID:       fmt.Sprintf("workload:%05d", i),
			Kind:     NodeKindWorkload,
			Name:     fmt.Sprintf("payments-service-%05d", i),
			Provider: "aws",
			Account:  "123456789012",
			Region:   "us-east-1",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.InvalidateIndex()
		g.BuildIndex()
	}
}

func BenchmarkGraphEntitySearchBootstrapQuery(b *testing.B) {
	query := "09999"
	base := New()
	for i := 0; i < 10000; i++ {
		base.AddNode(&Node{
			ID:       fmt.Sprintf("workload:%05d", i),
			Kind:     NodeKindWorkload,
			Name:     fmt.Sprintf("payments-service-%05d", i),
			Provider: "aws",
			Account:  "123456789012",
			Region:   "us-east-1",
		})
	}

	b.Run("incremental_current_indexes", func(b *testing.B) {
		g := base.Clone()
		if got := SearchEntities(g, EntitySearchOptions{Query: query, Limit: 5}).Count; got == 0 {
			b.Fatalf("SearchEntities() warmup = %d, want non-zero", got)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if got := SearchEntities(g, EntitySearchOptions{Query: query, Limit: 5}).Count; got == 0 {
				b.Fatalf("SearchEntities() = %d, want non-zero", got)
			}
		}
	})

	b.Run("invalidate_then_rebuild_on_query", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			g := base.Clone()
			g.InvalidateIndex()
			b.StartTimer()
			if got := SearchEntities(g, EntitySearchOptions{Query: query, Limit: 5}).Count; got == 0 {
				b.Fatalf("SearchEntities() = %d, want non-zero", got)
			}
		}
	})
}
