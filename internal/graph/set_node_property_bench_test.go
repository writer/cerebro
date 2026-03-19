package graph

import (
	"strconv"
	"testing"
)

func BenchmarkGraphSetNodePropertyTwentyProperties(b *testing.B) {
	properties := make(map[string]any, 20)
	for i := 0; i < 20; i++ {
		properties["property_"+strconv.Itoa(i)] = "value_" + strconv.Itoa(i)
	}

	g := New()
	g.AddNode(&Node{
		ID:         "node:bench",
		Kind:       NodeKindWorkload,
		Properties: properties,
	})
	g.SetTemporalHistoryConfig(8, DefaultTemporalHistoryTTL)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !g.SetNodeProperty("node:bench", "property_10", "value_"+strconv.Itoa(i&1)) {
			b.Fatal("SetNodeProperty returned false")
		}
	}
}
