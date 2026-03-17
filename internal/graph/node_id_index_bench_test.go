package graph

import (
	"fmt"
	"testing"
)

func BenchmarkNodeIDIndexVisitedSetRepresentations(b *testing.B) {
	const count = 100_000

	ids := make([]string, count)
	idx := NewNodeIDIndex()
	ordinals := make([]NodeOrdinal, count)
	for i := range count {
		ids[i] = fmt.Sprintf("deployment:prod/service-%d", i)
		ordinals[i] = idx.Intern(ids[i])
	}

	b.Run("string_map", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			visited := make(map[string]struct{}, len(ids))
			for _, id := range ids {
				visited[id] = struct{}{}
			}
		}
	})

	b.Run("ordinal_map", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			visited := make(map[NodeOrdinal]struct{}, len(ordinals))
			for _, ordinal := range ordinals {
				visited[ordinal] = struct{}{}
			}
		}
	})

	b.Run("bitmap", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			visited := idx.NewBitmap()
			for _, ordinal := range ordinals {
				visited[ordinal] = true
			}
		}
	})
}
