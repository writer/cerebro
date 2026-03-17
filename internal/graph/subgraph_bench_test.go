package graph

import (
	"strconv"
	"testing"
)

func BenchmarkExtractSubgraph(b *testing.B) {
	g := New()
	g.AddNode(&Node{ID: "root", Kind: NodeKindRole})

	for i := range 256 {
		midID := benchmarkNodeID("mid", i)
		g.AddNode(&Node{ID: midID, Kind: NodeKindRole})
		g.AddEdge(&Edge{
			ID:     benchmarkNodeID("root-mid", i),
			Source: "root",
			Target: midID,
			Kind:   EdgeKindCanAssume,
			Effect: EdgeEffectAllow,
		})
		for j := range 4 {
			leafID := benchmarkNodeID(midID+"-leaf", j)
			g.AddNode(&Node{ID: leafID, Kind: NodeKindBucket})
			g.AddEdge(&Edge{
				ID:     benchmarkNodeID(midID+"-leaf-edge", j),
				Source: midID,
				Target: leafID,
				Kind:   EdgeKindCanRead,
				Effect: EdgeEffectAllow,
			})
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sub := ExtractSubgraph(g, "root", ExtractSubgraphOptions{
			MaxDepth:  2,
			Direction: ExtractSubgraphDirectionOutgoing,
		})
		if sub == nil {
			b.Fatal("expected extracted subgraph")
		}
	}
}

func benchmarkNodeID(prefix string, idx int) string {
	return prefix + "-" + strconv.Itoa(idx)
}
