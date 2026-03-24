package app

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/graph"
)

func TestScanAPISurfaceFindingsGeneratesPolicyFindings(t *testing.T) {
	g := graph.New()
	g.AddNode(&graph.Node{ID: "internet", Kind: graph.NodeKindInternet, Name: "Internet"})
	g.AddNode(&graph.Node{
		ID:       "api_endpoint:https://api.example.com",
		Kind:     graph.NodeKindAPIEndpoint,
		Name:     "https://api.example.com",
		Provider: "aws",
		Properties: map[string]any{
			"url":             "https://api.example.com",
			"host":            "api.example.com",
			"public":          true,
			"auth_type":       "none",
			"cors_permissive": true,
		},
	})
	g.AddEdge(&graph.Edge{ID: "internet->api", Source: "internet", Target: "api_endpoint:https://api.example.com", Kind: graph.EdgeKindExposedTo, Effect: graph.EdgeEffectAllow})

	application := &App{SecurityGraph: g}
	result := application.ScanAPISurfaceFindings(context.Background())
	if result.Endpoints != 1 {
		t.Fatalf("Endpoints = %d, want 1", result.Endpoints)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("len(Findings) = %d, want 2", len(result.Findings))
	}
	if len(result.Errors) != 0 {
		t.Fatalf("Errors = %#v, want none", result.Errors)
	}
}
