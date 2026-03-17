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
