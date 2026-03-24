package reports

import "testing"

func TestBuildAIWorkloadInventoryReport(t *testing.T) {
	g := New()
	g.AddNode(&Node{ID: "internet", Kind: NodeKindInternet, Name: "Internet"})
	g.AddNode(&Node{
		ID:       "service:customer-llm-endpoint",
		Kind:     NodeKindService,
		Name:     "SageMaker Endpoint",
		Provider: "aws",
		Properties: map[string]any{
			"model_endpoint_name": "customer-llm-endpoint",
		},
	})
	g.AddNode(&Node{
		ID:   "database:customer-pgvector",
		Kind: NodeKindDatabase,
		Name: "Customer pgvector",
		Properties: map[string]any{
			"engine":              "pgvector",
			"data_classification": "confidential",
		},
	})
	g.AddNode(&Node{
		ID:   "service_account:ml-admin",
		Kind: NodeKindServiceAccount,
		Name: "ml-admin",
	})
	g.AddNode(&Node{
		ID:   "workload:research-agent",
		Kind: NodeKindWorkload,
		Name: "Research Agent",
		Properties: map[string]any{
			"openai_api_key": "sk-test",
		},
	})
	g.AddNode(&Node{
		ID:   "technology:ollama",
		Kind: NodeKindTechnology,
		Name: "Ollama",
	})
	g.AddNode(&Node{
		ID:   "package:cuda",
		Kind: NodeKindPackage,
		Name: "CUDA",
	})
	g.AddEdge(&Edge{ID: "internet-llm", Source: "internet", Target: "service:customer-llm-endpoint", Kind: EdgeKindExposedTo, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "llm-db", Source: "service:customer-llm-endpoint", Target: "database:customer-pgvector", Kind: EdgeKindCanRead, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "llm-admin", Source: "service:customer-llm-endpoint", Target: "service_account:ml-admin", Kind: EdgeKindRuns, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "agent-ollama", Source: "workload:research-agent", Target: "technology:ollama", Kind: EdgeKindContains, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "agent-cuda", Source: "workload:research-agent", Target: "package:cuda", Kind: EdgeKindContainsPkg, Effect: EdgeEffectAllow})

	report := BuildAIWorkloadInventoryReport(g, AIWorkloadInventoryReportOptions{
		MaxWorkloads:  10,
		MinRiskScore:  0,
		IncludeShadow: true,
	})

	if report.Summary.WorkloadCount != 3 {
		t.Fatalf("expected 2 workloads, got %#v", report.Summary)
	}
	if report.Summary.ShadowAIWorkloadCount != 2 {
		t.Fatalf("expected 1 shadow workload, got %#v", report.Summary)
	}
	if report.Summary.InternetExposedWorkloadCount != 1 {
		t.Fatalf("expected 1 internet-exposed workload, got %#v", report.Summary)
	}
	if len(report.Workloads) != 3 {
		t.Fatalf("expected 2 returned workloads, got %#v", report.Workloads)
	}

	first := report.Workloads[0]
	if first.NodeID != "service:customer-llm-endpoint" {
		t.Fatalf("expected internet-exposed service to sort first, got %#v", first)
	}
	if first.AIServiceType != "serving" {
		t.Fatalf("expected serving AI service type, got %#v", first.AIServiceType)
	}
	if !first.InternetExposed || !first.SensitiveDataAccess {
		t.Fatalf("expected cloud endpoint exposure signals, got %#v", first)
	}
	if first.RiskLevel != RiskHigh {
		t.Fatalf("expected high risk level, got %#v", first.RiskLevel)
	}

	records := make(map[string]AIWorkloadRecord, len(report.Workloads))
	for _, record := range report.Workloads {
		records[record.NodeID] = record
	}
	shadow, ok := records["workload:research-agent"]
	if !ok {
		t.Fatalf("expected research agent in workload inventory, got %#v", report.Workloads)
	}
	if !shadow.ShadowAI {
		t.Fatalf("expected shadow AI workload, got %#v", shadow)
	}
	if shadow.DeploymentModel != "self_hosted" {
		t.Fatalf("expected self_hosted deployment model, got %#v", shadow.DeploymentModel)
	}
	if len(shadow.PlaintextProviderKeys) != 1 || shadow.PlaintextProviderKeys[0] != "openai api key" {
		t.Fatalf("expected plaintext provider key detection, got %#v", shadow.PlaintextProviderKeys)
	}
	if len(report.DataExposures) == 0 {
		t.Fatalf("expected data exposures, got %#v", report.DataExposures)
	}
	if len(report.ShadowAIWorkloads) != 2 {
		t.Fatalf("expected shadow slice to include research agent, got %#v", report.ShadowAIWorkloads)
	}
	if len(report.Recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", report.Recommendations)
	}
}

func TestBuildAIWorkloadInventoryReportCanExcludeShadowAI(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:   "workload:research-agent",
		Kind: NodeKindWorkload,
		Name: "Research Agent",
		Properties: map[string]any{
			"openai_api_key": "sk-test",
		},
	})

	report := BuildAIWorkloadInventoryReport(g, AIWorkloadInventoryReportOptions{
		MaxWorkloads:  10,
		IncludeShadow: false,
	})
	if report.Summary.WorkloadCount != 1 {
		t.Fatalf("expected inventory summary to keep total workload count, got %#v", report.Summary)
	}
	if report.Summary.ReturnedWorkloadCount != 0 {
		t.Fatalf("expected returned workload count to exclude shadow AI, got %#v", report.Summary)
	}
	if len(report.Workloads) != 0 {
		t.Fatalf("expected no returned workloads, got %#v", report.Workloads)
	}
}
