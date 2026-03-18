package graph

import (
	"testing"
	"time"
)

func TestMaterializeEventCorrelationsBuildsCausalChain(t *testing.T) {
	g := New()
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddNode(&Node{
		ID:   "pull_request:payments:42",
		Kind: NodeKindPullRequest,
		Name: "payments pr",
		Properties: map[string]any{
			"repository":  "payments",
			"number":      "42",
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "deployment:payments:deploy-1",
		Kind: NodeKindDeploymentRun,
		Name: "deploy-1",
		Properties: map[string]any{
			"deploy_id":   "deploy-1",
			"service_id":  "payments",
			"environment": "prod",
			"status":      "succeeded",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "incident:inc-1",
		Kind: NodeKindIncident,
		Name: "inc-1",
		Properties: map[string]any{
			"incident_id": "inc-1",
			"status":      "open",
			"severity":    "high",
			"service_id":  "payments",
			"observed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(7 * time.Minute).Format(time.RFC3339),
		},
	})

	g.AddEdge(&Edge{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "incident->service", Source: "incident:inc-1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	summary := MaterializeEventCorrelations(g, base.Add(10*time.Minute))
	if summary.CorrelationsCreated != 2 {
		t.Fatalf("expected 2 derived correlations, got %#v", summary)
	}

	incidentEdges := g.GetOutEdges("incident:inc-1")
	if !hasActiveEdge(incidentEdges, EdgeKindCausedBy, "deployment:payments:deploy-1") {
		t.Fatalf("expected incident caused_by deployment edge, got %#v", incidentEdges)
	}
	deployEdges := g.GetOutEdges("deployment:payments:deploy-1")
	if !hasActiveEdge(deployEdges, EdgeKindTriggeredBy, "pull_request:payments:42") {
		t.Fatalf("expected deployment triggered_by pull request edge, got %#v", deployEdges)
	}

	result := QueryEventCorrelations(g, base.Add(10*time.Minute), EventCorrelationQuery{
		EventID:          "incident:inc-1",
		Limit:            10,
		IncludeAnomalies: false,
	})
	if result.Summary.CorrelationCount != 2 {
		t.Fatalf("expected incident neighborhood to include 2 correlations, got %#v", result)
	}

	rerun := MaterializeEventCorrelations(g, base.Add(11*time.Minute))
	if rerun.CorrelationsRemoved != 2 || rerun.CorrelationsCreated != 2 {
		t.Fatalf("expected rerun to replace both derived edges, got %#v", rerun)
	}
	if got := countMaterializedCorrelationEdges(g); got != 2 {
		t.Fatalf("expected 2 active materialized correlation edges after rerun, got %d", got)
	}
	if got := len(g.outEdges["deployment:payments:deploy-1"]); got != 2 {
		t.Fatalf("expected compacted deployment adjacency to keep 2 edges, got %d", got)
	}
	if got := len(g.outEdges["incident:inc-1"]); got != 2 {
		t.Fatalf("expected compacted incident adjacency to keep 2 edges, got %d", got)
	}
}

func TestQueryEventCorrelationsIncludesFailureSpikeAnomaly(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	for i := 0; i < 4; i++ {
		at := now.Add(-time.Duration(i+1) * 24 * time.Hour)
		g.AddNode(&Node{
			ID:   "deployment:payments:current-" + string(rune('a'+i)),
			Kind: NodeKindDeploymentRun,
			Name: "current",
			Properties: map[string]any{
				"deploy_id":   "current",
				"service_id":  "payments",
				"environment": "prod",
				"status":      "failed",
				"observed_at": at.Format(time.RFC3339),
				"valid_from":  at.Format(time.RFC3339),
			},
		})
	}
	for i := 0; i < 4; i++ {
		baselineAt := now.Add(-time.Duration(14+i*5) * 24 * time.Hour)
		g.AddNode(&Node{
			ID:   "deployment:payments:baseline-" + string(rune('a'+i)),
			Kind: NodeKindDeploymentRun,
			Name: "baseline",
			Properties: map[string]any{
				"deploy_id":   "baseline",
				"service_id":  "payments",
				"environment": "prod",
				"status":      "failed",
				"observed_at": baselineAt.Format(time.RFC3339),
				"valid_from":  baselineAt.Format(time.RFC3339),
			},
		})
	}

	result := QueryEventCorrelations(g, now, EventCorrelationQuery{
		EntityID:         "service:payments",
		Limit:            10,
		IncludeAnomalies: true,
	})
	if len(result.Anomalies) == 0 {
		t.Fatalf("expected anomalies, got %#v", result)
	}
	foundFailureSpike := false
	for _, anomaly := range result.Anomalies {
		if anomaly.Classification == "failure_spike" {
			foundFailureSpike = true
			if anomaly.EntityID != "service:payments" {
				t.Fatalf("expected service:payments anomaly, got %#v", anomaly)
			}
		}
	}
	if !foundFailureSpike {
		t.Fatalf("expected failure_spike anomaly, got %#v", result.Anomalies)
	}
}

func TestQueryEventCorrelationsSortsAnomaliesBySeverityRank(t *testing.T) {
	g := New()
	now := time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC)
	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})

	for i := 0; i < 3; i++ {
		at := now.Add(-time.Duration(i+1) * 24 * time.Hour)
		g.AddNode(&Node{
			ID:   "deployment:payments:failed-" + string(rune('a'+i)),
			Kind: NodeKindDeploymentRun,
			Name: "failed",
			Properties: map[string]any{
				"deploy_id":   "failed",
				"service_id":  "payments",
				"environment": "prod",
				"status":      "failed",
				"observed_at": at.Format(time.RFC3339),
				"valid_from":  at.Format(time.RFC3339),
			},
		})
	}
	for i := 0; i < 4; i++ {
		at := now.Add(-time.Duration(14+i*5) * 24 * time.Hour)
		g.AddNode(&Node{
			ID:   "deployment:payments:baseline-failed-" + string(rune('a'+i)),
			Kind: NodeKindDeploymentRun,
			Name: "baseline-failed",
			Properties: map[string]any{
				"deploy_id":   "baseline-failed",
				"service_id":  "payments",
				"environment": "prod",
				"status":      "failed",
				"observed_at": at.Format(time.RFC3339),
				"valid_from":  at.Format(time.RFC3339),
			},
		})
	}
	g.AddNode(&Node{
		ID:   "incident:inc-current",
		Kind: NodeKindIncident,
		Name: "inc-current",
		Properties: map[string]any{
			"incident_id": "inc-current",
			"status":      "open",
			"severity":    "high",
			"service_id":  "payments",
			"observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})

	result := QueryEventCorrelations(g, now, EventCorrelationQuery{
		EntityID:         "service:payments",
		Limit:            10,
		IncludeAnomalies: true,
	})
	if len(result.Anomalies) < 2 {
		t.Fatalf("expected at least 2 anomalies, got %#v", result.Anomalies)
	}
	if result.Anomalies[0].Severity != "high" {
		t.Fatalf("expected highest severity anomaly first, got %#v", result.Anomalies)
	}
}

func TestQueryEventCorrelationsFailsClosedForUnknownScope(t *testing.T) {
	g := New()
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddNode(&Node{
		ID:   "pull_request:payments:42",
		Kind: NodeKindPullRequest,
		Name: "payments pr",
		Properties: map[string]any{
			"state":       "merged",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "deployment:payments:deploy-1",
		Kind: NodeKindDeploymentRun,
		Name: "deploy-1",
		Properties: map[string]any{
			"service_id":  "payments",
			"status":      "failed",
			"observed_at": base.Add(5 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(5 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddEdge(&Edge{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	MaterializeEventCorrelations(g, base.Add(10*time.Minute))

	result := QueryEventCorrelations(g, base.Add(10*time.Minute), EventCorrelationQuery{
		EventID:          "incident:does-not-exist",
		IncludeAnomalies: true,
		Limit:            10,
	})
	if len(result.Correlations) != 0 || len(result.Anomalies) != 0 {
		t.Fatalf("expected unknown event scope to fail closed, got %#v", result)
	}

	result = QueryEventCorrelations(g, base.Add(10*time.Minute), EventCorrelationQuery{
		EntityID:         "service:does-not-exist",
		IncludeAnomalies: true,
		Limit:            10,
	})
	if len(result.Correlations) != 0 || len(result.Anomalies) != 0 {
		t.Fatalf("expected unknown entity scope to fail closed, got %#v", result)
	}
}

func hasActiveEdge(edges []*Edge, kind EdgeKind, target string) bool {
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		if edge.Kind == kind && edge.Target == target && edge.DeletedAt == nil {
			return true
		}
	}
	return false
}

func countMaterializedCorrelationEdges(g *Graph) int {
	count := 0
	for _, edges := range g.GetAllEdges() {
		for _, edge := range edges {
			if isMaterializedEventCorrelationEdge(edge) {
				count++
			}
		}
	}
	return count
}
