package graph

import "testing"

func TestAnalyzeAPISurfaceReportsPublicReachabilityAndFindings(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{
		ID:       "api_endpoint:https://api.example.com",
		Kind:     NodeKindAPIEndpoint,
		Name:     "https://api.example.com",
		Provider: "aws",
		Properties: map[string]any{
			"url":              "https://api.example.com",
			"host":             "api.example.com",
			"public":           true,
			"auth_type":        "none",
			"cors_permissive":  true,
			"provider_service": "aws_apigateway_v2",
		},
	})
	g.AddNode(&Node{ID: "workload:payments", Kind: NodeKindFunction, Name: "payments"})
	g.AddNode(&Node{ID: "db:customers", Kind: NodeKindDatabase, Name: "customers", Risk: RiskHigh})
	g.AddEdge(&Edge{ID: "internet->api", Source: "internet", Target: "api_endpoint:https://api.example.com", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "workload->api", Source: "workload:payments", Target: "api_endpoint:https://api.example.com", Kind: EdgeKindServes, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "api->workload", Source: "api_endpoint:https://api.example.com", Target: "workload:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "workload->db", Source: "workload:payments", Target: "db:customers", Kind: EdgeKindCalls, Effect: EdgeEffectAllow})

	report := AnalyzeAPISurface(g, APISurfaceReportOptions{MaxDepth: 4})
	if report.Count != 1 {
		t.Fatalf("report.Count = %d, want 1", report.Count)
	}
	if report.Summary.PublicEndpointCount != 1 {
		t.Fatalf("PublicEndpointCount = %d, want 1", report.Summary.PublicEndpointCount)
	}
	if got := len(report.Findings); got != 2 {
		t.Fatalf("len(report.Findings) = %d, want 2", got)
	}
	endpoint := report.Endpoints[0]
	if len(endpoint.ServedBy) != 1 || endpoint.ServedBy[0].ID != "workload:payments" {
		t.Fatalf("ServedBy = %#v, want workload:payments", endpoint.ServedBy)
	}
	if len(endpoint.ReachableResources) != 2 {
		t.Fatalf("ReachableResources = %#v, want 2 resources", endpoint.ReachableResources)
	}
}

func TestAnalyzeAPISurfaceExcludesInternalEndpointsByDefault(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:       "api_endpoint:https://internal.example.com",
		Kind:     NodeKindAPIEndpoint,
		Name:     "https://internal.example.com",
		Provider: "gcp",
		Properties: map[string]any{
			"url":    "https://internal.example.com",
			"host":   "internal.example.com",
			"public": false,
		},
	})

	report := AnalyzeAPISurface(g, APISurfaceReportOptions{})
	if report.Count != 0 {
		t.Fatalf("report.Count = %d, want 0", report.Count)
	}

	report = AnalyzeAPISurface(g, APISurfaceReportOptions{IncludeInternal: true})
	if report.Count != 1 {
		t.Fatalf("include_internal report.Count = %d, want 1", report.Count)
	}
}
