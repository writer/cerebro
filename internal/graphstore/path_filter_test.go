package graphstore

import (
	"encoding/json"
	"testing"
)

func TestIngestRunGraphCountsKeepFlatJSONContract(t *testing.T) {
	t.Parallel()
	encoded, err := json.Marshal(IngestRun{
		ID: "run-a",
		IngestRunGraphCounts: IngestRunGraphCounts{
			GraphNodesBefore: 10, GraphLinksBefore: 20, GraphNodesAfter: 11, GraphLinksAfter: 22,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"graph_nodes_before": 10, "graph_links_before": 20, "graph_nodes_after": 11, "graph_links_after": 22,
	} {
		if wire[key] != want {
			t.Fatalf("%s = %#v, want %v", key, wire[key], want)
		}
	}
	if _, exists := wire["ingest_run_graph_counts"]; exists {
		t.Fatalf("embedded counts leaked a nested JSON field: %s", encoded)
	}
}

func TestSuppressTwoHopPath(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
		want   bool
	}{
		{name: "container finding gravity well", first: "belongs_to", second: "has_finding", want: true},
		{name: "identity finding gravity well", first: "represents", second: "has_finding", want: true},
		{name: "package vulnerability gravity well", first: "contains", second: "affected_by", want: true},
		{name: "activity fanout first hop", first: "acted_on", second: "belongs_to", want: true},
		{name: "activity fanout second hop", first: "has_identifier", second: "acted_on", want: true},
		{name: "direct vulnerability signal", first: "affected_by", second: "has_finding", want: false},
		{name: "attack path signal", first: "can_perform", second: "has_finding", want: false},
		{name: "ownership signal", first: "owned_by", second: "has_finding", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SuppressTwoHopPath(test.first, test.second); got != test.want {
				t.Fatalf("SuppressTwoHopPath(%q, %q) = %v, want %v", test.first, test.second, got, test.want)
			}
		})
	}
}
