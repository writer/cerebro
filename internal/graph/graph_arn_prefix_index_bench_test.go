package graph

import (
	"fmt"
	"testing"
)

func BenchmarkGraphIncrementalARNPrefixIndexAddNode(b *testing.B) {
	base := New()
	for i := 0; i < 5000; i++ {
		base.AddNode(&Node{
			ID:   fmt.Sprintf("arn:aws:lambda:us-west-2:123456789012:function:service-%d", i),
			Kind: NodeKindFunction,
		})
	}

	pattern := "arn:aws:lambda:us-west-2:123456789012:function:service-*"

	b.Run("incremental_match_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddNode(&Node{
				ID:   fmt.Sprintf("arn:aws:lambda:us-west-2:123456789012:function:new-%d", i),
				Kind: NodeKindFunction,
			})
			if got := len(FindMatchingNodes(g, pattern)); got == 0 {
				b.Fatalf("FindMatchingNodes(%q) = %d, want non-zero", pattern, got)
			}
		}
	})

	b.Run("full_rebuild_match_after_add", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			g := base.Clone()
			g.BuildIndex()
			g.AddNode(&Node{
				ID:   fmt.Sprintf("arn:aws:lambda:us-west-2:123456789012:function:new-%d", i),
				Kind: NodeKindFunction,
			})
			g.BuildIndex()
			if got := len(FindMatchingNodes(g, pattern)); got == 0 {
				b.Fatalf("FindMatchingNodes(%q) = %d, want non-zero", pattern, got)
			}
		}
	})
}
