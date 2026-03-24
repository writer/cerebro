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

func TestMaterializeEventCorrelationsSelectsClosestCandidateAndScoresAmbiguity(t *testing.T) {
	g := New()
	base := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)

	g.AddNode(&Node{ID: "service:payments", Kind: NodeKindService, Name: "Payments"})
	g.AddNode(&Node{
		ID:   "pipeline_run:payments:1",
		Kind: NodeKindPipelineRun,
		Name: "pipeline-1",
		Properties: map[string]any{
			"pipeline_id": "pipeline-1",
			"service_id":  "payments",
			"status":      "succeeded",
			"observed_at": base.Format(time.RFC3339),
			"valid_from":  base.Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "pipeline_run:payments:2",
		Kind: NodeKindPipelineRun,
		Name: "pipeline-2",
		Properties: map[string]any{
			"pipeline_id": "pipeline-2",
			"service_id":  "payments",
			"status":      "succeeded",
			"observed_at": base.Add(2 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(2 * time.Minute).Format(time.RFC3339),
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
			"observed_at": base.Add(10 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(10 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddEdge(&Edge{ID: "pipeline-1->service", Source: "pipeline_run:payments:1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "pipeline-2->service", Source: "pipeline_run:payments:2", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})
	g.AddEdge(&Edge{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow})

	MaterializeEventCorrelations(g, base.Add(12*time.Minute))

	result := QueryEventCorrelations(g, base.Add(12*time.Minute), EventCorrelationQuery{
		EventID:   "deployment:payments:deploy-1",
		PatternID: "pipeline_deploy_chain",
		Limit:     10,
	})
	if len(result.Correlations) != 1 {
		t.Fatalf("expected one pipeline correlation, got %#v", result.Correlations)
	}
	record := result.Correlations[0]
	if record.Cause.ID != "pipeline_run:payments:2" {
		t.Fatalf("expected closest pipeline candidate to win, got %#v", record)
	}
	if record.CandidateCount != 2 {
		t.Fatalf("expected two pipeline candidates to be considered, got %#v", record)
	}
	if record.ScopeOverlap != 1 {
		t.Fatalf("expected full scope overlap, got %#v", record)
	}
	if record.AmbiguityPenalty <= 0 {
		t.Fatalf("expected ambiguity penalty for competing candidates, got %#v", record)
	}
	if record.Confidence <= 0 || record.Confidence >= 1 {
		t.Fatalf("expected bounded confidence score, got %#v", record)
	}
}

func TestQueryEventCorrelationChainsTraversesExpandedIncidentResponseLineage(t *testing.T) {
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
		ID:   "check_run:payments:lint",
		Kind: NodeKindCheckRun,
		Name: "lint",
		Properties: map[string]any{
			"check_id":    "lint",
			"service_id":  "payments",
			"status":      "passed",
			"observed_at": base.Add(1 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(1 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "pipeline_run:payments:ci",
		Kind: NodeKindPipelineRun,
		Name: "ci",
		Properties: map[string]any{
			"pipeline_id": "ci",
			"service_id":  "payments",
			"status":      "succeeded",
			"observed_at": base.Add(2 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(2 * time.Minute).Format(time.RFC3339),
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
			"service_id":  "payments",
			"status":      "open",
			"observed_at": base.Add(7 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(7 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "decision:inc-1:rollback",
		Kind: NodeKindDecision,
		Name: "rollback",
		Properties: map[string]any{
			"service_id":  "payments",
			"status":      "approved",
			"observed_at": base.Add(12 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(12 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "action:inc-1:rollback",
		Kind: NodeKindAction,
		Name: "rollback action",
		Properties: map[string]any{
			"service_id":  "payments",
			"status":      "completed",
			"observed_at": base.Add(15 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(15 * time.Minute).Format(time.RFC3339),
		},
	})
	g.AddNode(&Node{
		ID:   "outcome:inc-1:restored",
		Kind: NodeKindOutcome,
		Name: "service restored",
		Properties: map[string]any{
			"service_id":  "payments",
			"status":      "resolved",
			"observed_at": base.Add(18 * time.Minute).Format(time.RFC3339),
			"valid_from":  base.Add(18 * time.Minute).Format(time.RFC3339),
		},
	})

	for _, edge := range []*Edge{
		{ID: "pr->service", Source: "pull_request:payments:42", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "check->service", Source: "check_run:payments:lint", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "pipeline->service", Source: "pipeline_run:payments:ci", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "deploy->service", Source: "deployment:payments:deploy-1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "incident->service", Source: "incident:inc-1", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "decision->service", Source: "decision:inc-1:rollback", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "action->service", Source: "action:inc-1:rollback", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
		{ID: "outcome->service", Source: "outcome:inc-1:restored", Target: "service:payments", Kind: EdgeKindTargets, Effect: EdgeEffectAllow},
	} {
		g.AddEdge(edge)
	}

	summary := MaterializeEventCorrelations(g, base.Add(20*time.Minute))
	if summary.CorrelationsCreated != 7 {
		t.Fatalf("expected seven derived correlations across the full chain, got %#v", summary)
	}

	result := QueryEventCorrelationChains(g, base.Add(20*time.Minute), EventCorrelationChainQuery{
		EventID:   "outcome:inc-1:restored",
		Direction: "upstream",
		MaxDepth:  5,
		Limit:     10,
	})
	if result.Summary.ChainCount != 3 {
		t.Fatalf("expected three upstream chains from outcome through deployment lineage, got %#v", result)
	}
	if result.Summary.MaxDepth != 5 {
		t.Fatalf("expected maximum depth of five edges, got %#v", result.Summary)
	}

	terminalKinds := make(map[NodeKind]struct{})
	for _, chain := range result.Chains {
		if chain.Depth != 5 {
			t.Fatalf("expected five-edge chains, got %#v", chain)
		}
		if len(chain.Events) != 6 {
			t.Fatalf("expected seed plus five upstream events, got %#v", chain.Events)
		}
		terminalKinds[chain.Events[len(chain.Events)-1].Kind] = struct{}{}
	}
	for _, kind := range []NodeKind{NodeKindPullRequest, NodeKindCheckRun, NodeKindPipelineRun} {
		if _, ok := terminalKinds[kind]; !ok {
			t.Fatalf("expected terminal kind %s in traversed chains, got %#v", kind, terminalKinds)
		}
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
