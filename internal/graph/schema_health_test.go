package graph

import "testing"

func TestAnalyzeSchemaHealth_Recommendations(t *testing.T) {
	g := New()

	const sourceKind = NodeKind("test_schema_health_source_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:               sourceKind,
		Categories:         []NodeKindCategory{NodeCategoryBusiness},
		Properties:         map[string]string{"title": "string"},
		RequiredProperties: []string{"title"},
		Relationships:      []EdgeKind{EdgeKindReportsTo},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}

	g.AddNode(&Node{ID: "node:source", Kind: sourceKind, Name: "Source"}) // missing required title
	g.AddNode(&Node{ID: "node:unknown", Kind: NodeKind("test_schema_health_unknown_kind_v1"), Name: "Unknown"})
	g.AddEdge(&Edge{ID: "edge:unknown", Source: "node:source", Target: "node:unknown", Kind: EdgeKind("test_schema_health_unknown_edge_v1"), Effect: EdgeEffectAllow})

	report := AnalyzeSchemaHealth(g, 20, 0)
	if len(report.Recommendations) == 0 {
		t.Fatal("expected schema recommendations")
	}

	categories := map[string]bool{}
	for _, recommendation := range report.Recommendations {
		categories[recommendation.Category] = true
	}
	if !categories["node_kind_coverage"] {
		t.Fatalf("expected node_kind_coverage recommendation, got %#v", report.Recommendations)
	}
	if !categories["edge_kind_coverage"] {
		t.Fatalf("expected edge_kind_coverage recommendation, got %#v", report.Recommendations)
	}
	if !categories["required_properties"] {
		t.Fatalf("expected required_properties recommendation, got %#v", report.Recommendations)
	}
}

func TestAnalyzeSchemaHealth_EmptyGraphSkipsConformanceRecommendation(t *testing.T) {
	g := New()
	report := AnalyzeSchemaHealth(g, 20, 0)

	for _, recommendation := range report.Recommendations {
		if recommendation.Category == "conformance" {
			t.Fatalf("did not expect conformance recommendation for empty graph: %#v", recommendation)
		}
	}
}
