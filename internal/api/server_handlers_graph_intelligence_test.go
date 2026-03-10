package api

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/graphingest"
)

func TestGraphIntelligenceInsightsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:ops", Kind: graph.NodeKindRole, Name: "Ops Role"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod DB", Risk: graph.RiskCritical})
	g.AddNode(&graph.Node{ID: "node:unknown", Kind: graph.NodeKind("api_intel_unknown_kind_v1"), Name: "Unknown"})
	g.AddEdge(&graph.Edge{ID: "alice-role", Source: "user:alice", Target: "role:ops", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "role-db", Source: "role:ops", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?window_days=30&include_counterfactual=false&max_insights=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	if _, ok := body["risk_score"].(float64); !ok {
		t.Fatalf("expected risk_score, got %#v", body["risk_score"])
	}
	if _, ok := body["coverage"].(float64); !ok {
		t.Fatalf("expected coverage, got %#v", body["coverage"])
	}
	insights, ok := body["insights"].([]any)
	if !ok || len(insights) == 0 {
		t.Fatalf("expected insights, got %#v", body["insights"])
	}
	if len(insights) != 1 {
		t.Fatalf("expected max_insights=1 to limit result to one insight, got %d", len(insights))
	}
	first, ok := insights[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first insight object, got %T", insights[0])
	}
	if _, ok := first["confidence"].(float64); !ok {
		t.Fatalf("expected insight confidence, got %#v", first["confidence"])
	}
	if _, ok := first["coverage"].(float64); !ok {
		t.Fatalf("expected insight coverage, got %#v", first["coverage"])
	}
	if _, ok := first["evidence"].([]any); !ok {
		t.Fatalf("expected insight evidence array, got %#v", first["evidence"])
	}
}

func TestGraphIntelligenceInsightsEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?window_days=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for window_days=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?from=2026-03-01T00:00:00Z", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when from is missing to, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?include_counterfactual=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid include_counterfactual, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/insights?max_insights=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_insights=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceQualityEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":  now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "decision:rollback",
		Kind: graph.NodeKindDecision,
		Name: "Rollback",
		Properties: map[string]any{
			"decision_type": "rollback",
			"status":        "approved",
			"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
			"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "outcome:rollback",
		Kind: graph.NodeKindOutcome,
		Name: "Rollback outcome",
		Properties: map[string]any{
			"outcome_type": "deployment_result",
			"verdict":      "positive",
			"observed_at":  now.Add(-1 * time.Hour).Format(time.RFC3339),
			"valid_from":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{ID: "node:unknown", Kind: graph.NodeKind("api_graph_quality_unknown_kind_v1"), Name: "Unknown"})

	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "outcome-evaluates", Source: "outcome:rollback", Target: "decision:rollback", Kind: graph.EdgeKindEvaluates, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?history_limit=10&stale_after_hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if _, ok := summary["maturity_score"].(float64); !ok {
		t.Fatalf("expected summary.maturity_score, got %#v", summary["maturity_score"])
	}
	if nodes, ok := summary["nodes"].(float64); !ok || nodes < 1 {
		t.Fatalf("expected summary.nodes >= 1, got %#v", summary["nodes"])
	}

	temporal, ok := body["temporal"].(map[string]any)
	if !ok {
		t.Fatalf("expected temporal object, got %#v", body["temporal"])
	}
	if hours, ok := temporal["stale_after_hours"].(float64); !ok || int(hours) != 24 {
		t.Fatalf("expected stale_after_hours=24, got %#v", temporal["stale_after_hours"])
	}

	recommendations, ok := body["recommendations"].([]any)
	if !ok || len(recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", body["recommendations"])
	}
}

func TestGraphIntelligenceQualityEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?history_limit=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for history_limit=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?since_version=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for since_version=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?stale_after_hours=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for stale_after_hours=0, got %d", w.Code)
	}
}

func TestPlatformIntelligenceQualityEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 16, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email":       "alice@example.com",
			"observed_at": now.Format(time.RFC3339),
			"valid_from":  now.Format(time.RFC3339),
		},
	})

	platformResp := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/quality?stale_after_hours=24", nil)
	if platformResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for platform intelligence quality, got %d: %s", platformResp.Code, platformResp.Body.String())
	}
	if got := platformResp.Header().Get("Deprecation"); got != "" {
		t.Fatalf("did not expect deprecation header on platform endpoint, got %q", got)
	}
}

func TestPlatformIntelligenceReportsCatalog(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	if count, ok := body["count"].(float64); !ok || int(count) < 6 {
		t.Fatalf("expected at least 6 built-in reports, got %#v", body["count"])
	}
	reports, ok := body["reports"].([]any)
	if !ok || len(reports) == 0 {
		t.Fatalf("expected report definitions, got %#v", body["reports"])
	}
	first, ok := reports[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first report definition object, got %#v", reports[0])
	}
	if _, ok := first["endpoint"].(map[string]any); !ok {
		t.Fatalf("expected endpoint metadata on first report, got %#v", first["endpoint"])
	}
}

func TestPlatformIntelligenceReportDefinition(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/reports/leverage", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	if got := body["id"]; got != "leverage" {
		t.Fatalf("expected leverage definition, got %#v", got)
	}
	measures, ok := body["measures"].([]any)
	if !ok || len(measures) == 0 {
		t.Fatalf("expected measures, got %#v", body["measures"])
	}
}

func TestGraphIntelligenceMetadataQualityEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 17, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":    "payments",
			"source_system": "github",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "deployment:1",
		Kind: graph.NodeKindDeploymentRun,
		Name: "Deploy #1",
		Properties: map[string]any{
			"deploy_id":       "dep-1",
			"service_id":      "payments",
			"environment":     "production",
			"status":          "mystery_status", // invalid enum for deployment status profile
			"source_system":   "github",
			"source_event_id": "evt-deploy-1",
			"observed_at":     "not-a-time", // invalid timestamp for metadata profile
			"valid_from":      now.Format(time.RFC3339),
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/metadata-quality?top_kinds=10", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if _, ok := summary["profiled_kinds"].(float64); !ok {
		t.Fatalf("expected summary.profiled_kinds, got %#v", summary["profiled_kinds"])
	}
	if _, ok := summary["required_key_coverage_percent"].(float64); !ok {
		t.Fatalf("expected summary.required_key_coverage_percent, got %#v", summary["required_key_coverage_percent"])
	}
	if _, ok := summary["timestamp_validity_percent"].(float64); !ok {
		t.Fatalf("expected summary.timestamp_validity_percent, got %#v", summary["timestamp_validity_percent"])
	}
	if _, ok := summary["enum_validity_percent"].(float64); !ok {
		t.Fatalf("expected summary.enum_validity_percent, got %#v", summary["enum_validity_percent"])
	}

	kinds, ok := body["kinds"].([]any)
	if !ok || len(kinds) == 0 {
		t.Fatalf("expected kinds array, got %#v", body["kinds"])
	}
	recommendations, ok := body["recommendations"].([]any)
	if !ok || len(recommendations) == 0 {
		t.Fatalf("expected recommendations, got %#v", body["recommendations"])
	}
}

func TestGraphIntelligenceMetadataQualityEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/metadata-quality?top_kinds=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for top_kinds=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceClaimConflictsEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":    "payments",
			"source_system": "cmdb",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "evidence:doc:1",
		Kind: graph.NodeKindEvidence,
		Name: "Doc 1",
		Properties: map[string]any{
			"evidence_type": "document",
			"source_system": "docs",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "evidence:doc:2",
		Kind: graph.NodeKindEvidence,
		Name: "Doc 2",
		Properties: map[string]any{
			"evidence_type": "document",
			"source_system": "docs",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})

	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:           "claim:tier:1",
		SubjectID:    "service:payments",
		Predicate:    "service_tier",
		ObjectValue:  "tier1",
		EvidenceIDs:  []string{"evidence:doc:1"},
		SourceID:     "source:cmdb:1",
		SourceName:   "CMDB",
		SourceType:   "system",
		SourceSystem: "api",
	}); err != nil {
		t.Fatalf("write claim 1: %v", err)
	}
	if _, err := graph.WriteClaim(g, graph.ClaimWriteRequest{
		ID:           "claim:tier:2",
		SubjectID:    "service:payments",
		Predicate:    "service_tier",
		ObjectValue:  "tier0",
		EvidenceIDs:  []string{"evidence:doc:2"},
		SourceID:     "source:sheet:1",
		SourceName:   "Ops Sheet",
		SourceType:   "document",
		SourceSystem: "api",
	}); err != nil {
		t.Fatalf("write claim 2: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?max_conflicts=10&stale_after_hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if groups, ok := summary["conflict_groups"].(float64); !ok || int(groups) != 1 {
		t.Fatalf("expected one conflict group, got %#v", summary["conflict_groups"])
	}
	conflicts, ok := body["conflicts"].([]any)
	if !ok || len(conflicts) != 1 {
		t.Fatalf("expected one conflict, got %#v", body["conflicts"])
	}
}

func TestGraphIntelligenceClaimConflictsEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?max_conflicts=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for max_conflicts=0, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?include_resolved=maybe", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid include_resolved, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/platform/intelligence/claim-conflicts?valid_at=nope", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid valid_at, got %d", w.Code)
	}
}

func TestGraphIntelligenceLeverageEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 19, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice", Properties: map[string]any{
		"email":         "alice@example.com",
		"source_system": "github",
		"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "identity_alias:github:alice", Kind: graph.NodeKindIdentityAlias, Name: "alice", Properties: map[string]any{
		"source_system": "github",
		"external_id":   "alice",
		"email":         "alice@example.com",
		"observed_at":   now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments", Properties: map[string]any{
		"service_id":    "payments",
		"source_system": "ci",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "decision:rollback", Kind: graph.NodeKindDecision, Name: "Rollback", Properties: map[string]any{
		"decision_type": "rollback",
		"status":        "approved",
		"observed_at":   now.Add(-2 * time.Hour).Format(time.RFC3339),
		"valid_from":    now.Add(-2 * time.Hour).Format(time.RFC3339),
	}})
	g.AddNode(&graph.Node{ID: "outcome:rollback", Kind: graph.NodeKindOutcome, Name: "Rollback outcome", Properties: map[string]any{
		"outcome_type": "deployment_result",
		"verdict":      "positive",
		"observed_at":  now.Add(-1 * time.Hour).Format(time.RFC3339),
		"valid_from":   now.Add(-1 * time.Hour).Format(time.RFC3339),
	}})
	g.AddEdge(&graph.Edge{ID: "alias-link", Source: "identity_alias:github:alice", Target: "person:alice@example.com", Kind: graph.EdgeKindAliasOf, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "outcome-evaluates", Source: "outcome:rollback", Target: "decision:rollback", Kind: graph.EdgeKindEvaluates, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/leverage?identity_queue_limit=10&recent_window_hours=24", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := decodeJSON(t, w)
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %#v", body["summary"])
	}
	if _, ok := summary["leverage_score"].(float64); !ok {
		t.Fatalf("expected leverage_score, got %#v", summary["leverage_score"])
	}
	query, ok := body["query"].(map[string]any)
	if !ok {
		t.Fatalf("expected query object, got %#v", body["query"])
	}
	if count, ok := query["template_count"].(float64); !ok || count < 1 {
		t.Fatalf("expected query template count >0, got %#v", query["template_count"])
	}
}

func TestGraphQueryTemplatesEndpoint(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/graph/query/templates", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if count, ok := body["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected template count >0, got %#v", body["count"])
	}
	templates, ok := body["templates"].([]any)
	if !ok || len(templates) == 0 {
		t.Fatalf("expected templates array, got %#v", body["templates"])
	}
}

func TestGraphIntelligenceLeverageEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/leverage?identity_suggest_threshold=2", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid identity_suggest_threshold, got %d", w.Code)
	}
}

func TestGraphIngestHealthEndpoint(t *testing.T) {
	s := newTestServer(t)
	dlqPath := filepath.Join(t.TempDir(), "graph-mapper.dlq.jsonl")
	s.app.Config.GraphEventMapperValidationMode = "enforce"
	s.app.Config.GraphEventMapperDeadLetterPath = dlqPath

	mapper, err := graphingest.NewMapperWithOptions(graphingest.MappingConfig{
		Mappings: []graphingest.EventMapping{
			{
				Name:   "invalid_kind",
				Source: "ensemble.tap.test.invalid",
				Nodes: []graphingest.NodeMapping{
					{
						ID:       "test:entity:1",
						Kind:     "nonexistent_kind",
						Name:     "Invalid",
						Provider: "test",
					},
				},
			},
		},
	}, nil, graphingest.MapperOptions{
		ValidationMode: graphingest.MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}
	s.app.TapEventMapper = mapper

	if _, err := mapper.Apply(s.app.SecurityGraph, events.CloudEvent{
		ID:     "evt-invalid-1",
		Type:   "ensemble.tap.test.invalid",
		Time:   time.Date(2026, 3, 9, 22, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"id": "1"},
	}); err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/health?tail_limit=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	mapperBody, ok := body["mapper"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapper object, got %#v", body["mapper"])
	}
	if initialized, _ := mapperBody["initialized"].(bool); !initialized {
		t.Fatalf("expected mapper initialized=true, got %#v", mapperBody["initialized"])
	}
	if mode, _ := mapperBody["validation_mode"].(string); mode != "enforce" {
		t.Fatalf("expected enforce validation mode, got %#v", mapperBody["validation_mode"])
	}

	stats, ok := mapperBody["stats"].(map[string]any)
	if !ok {
		t.Fatalf("expected mapper stats object, got %#v", mapperBody["stats"])
	}
	if deadLettered, ok := stats["dead_lettered"].(float64); !ok || deadLettered < 1 {
		t.Fatalf("expected dead_lettered >= 1, got %#v", stats["dead_lettered"])
	}
	sourceSLO, ok := mapperBody["source_slo"].([]any)
	if !ok || len(sourceSLO) == 0 {
		t.Fatalf("expected mapper source_slo entries, got %#v", mapperBody["source_slo"])
	}
	firstSource, ok := sourceSLO[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first source_slo object, got %#v", sourceSLO[0])
	}
	if _, ok := firstSource["match_rate_percent"].(float64); !ok {
		t.Fatalf("expected source_slo.match_rate_percent, got %#v", firstSource["match_rate_percent"])
	}

	deadLetter, ok := body["dead_letter"].(map[string]any)
	if !ok {
		t.Fatalf("expected dead_letter object, got %#v", body["dead_letter"])
	}
	if exists, ok := deadLetter["exists"].(bool); !ok || !exists {
		t.Fatalf("expected dead_letter.exists=true, got %#v", deadLetter["exists"])
	}
	if parsed, ok := deadLetter["records_parsed"].(float64); !ok || parsed < 1 {
		t.Fatalf("expected dead_letter.records_parsed >= 1, got %#v", deadLetter["records_parsed"])
	}
	issueCounts, ok := deadLetter["issue_code_counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected dead_letter.issue_code_counts object, got %#v", deadLetter["issue_code_counts"])
	}
	if _, ok := issueCounts[string(graph.SchemaIssueUnknownNodeKind)]; !ok {
		t.Fatalf("expected unknown_node_kind issue count, got %#v", issueCounts)
	}
}

func TestGraphIngestDeadLetterEndpoint(t *testing.T) {
	s := newTestServer(t)
	dlqPath := filepath.Join(t.TempDir(), "graph-mapper.dlq.db")
	s.app.Config.GraphEventMapperValidationMode = "enforce"
	s.app.Config.GraphEventMapperDeadLetterPath = dlqPath

	mapper, err := graphingest.NewMapperWithOptions(graphingest.MappingConfig{
		Mappings: []graphingest.EventMapping{
			{
				Name:   "invalid_kind",
				Source: "ensemble.tap.test.invalid",
				Nodes: []graphingest.NodeMapping{
					{
						ID:       "test:entity:1",
						Kind:     "nonexistent_kind",
						Name:     "Invalid",
						Provider: "test",
					},
				},
			},
		},
	}, nil, graphingest.MapperOptions{
		ValidationMode: graphingest.MapperValidationEnforce,
		DeadLetterPath: dlqPath,
	})
	if err != nil {
		t.Fatalf("new mapper with options failed: %v", err)
	}
	s.app.TapEventMapper = mapper

	if _, err := mapper.Apply(s.app.SecurityGraph, events.CloudEvent{
		ID:     "evt-invalid-query-1",
		Type:   "ensemble.tap.test.invalid",
		Time:   time.Date(2026, 3, 9, 22, 30, 0, 0, time.UTC),
		Source: "urn:ensemble:tap",
		Data:   map[string]any{"id": "1"},
	}); err != nil {
		t.Fatalf("mapper apply failed: %v", err)
	}

	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/dead-letter?limit=10&issue_code=unknown_node_kind", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected result object, got %#v", body["result"])
	}
	if total, ok := result["total"].(float64); !ok || total < 1 {
		t.Fatalf("expected dead-letter query total >= 1, got %#v", result["total"])
	}
	records, ok := result["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected at least one dead-letter record, got %#v", result["records"])
	}
}

func TestGraphIngestContractsEndpoint(t *testing.T) {
	s := newTestServer(t)

	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/contracts", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)

	catalogWrapper, ok := body["catalog"].(map[string]any)
	if !ok {
		t.Fatalf("expected catalog object, got %#v", body["catalog"])
	}
	if apiVersion, _ := catalogWrapper["apiVersion"].(string); apiVersion == "" {
		t.Fatalf("expected catalog.apiVersion, got %#v", catalogWrapper["apiVersion"])
	}
	mappings, ok := catalogWrapper["mappings"].([]any)
	if !ok || len(mappings) == 0 {
		t.Fatalf("expected non-empty contract mappings, got %#v", catalogWrapper["mappings"])
	}
	first, ok := mappings[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first mapping object, got %#v", mappings[0])
	}
	if _, ok := first["data_schema"].(map[string]any); !ok {
		t.Fatalf("expected first mapping data_schema object, got %#v", first["data_schema"])
	}
}

func TestGraphIngestHealthEndpointInvalidTailLimit(t *testing.T) {
	s := newTestServer(t)
	w := do(t, s, http.MethodGet, "/api/v1/graph/ingest/health?tail_limit=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tail_limit=0, got %d", w.Code)
	}
}

func TestGraphIntelligenceWeeklyCalibrationEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	now := time.Date(2026, 3, 9, 18, 0, 0, 0, time.UTC)

	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"observed_at":   now.Format(time.RFC3339),
			"valid_from":    now.Format(time.RFC3339),
		},
	})
	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})

	w := do(t, s, http.MethodGet, "/api/v1/platform/intelligence/calibration/weekly?window_days=7&trend_days=14", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if _, ok := body["risk_feedback"].(map[string]any); !ok {
		t.Fatalf("expected risk_feedback object, got %#v", body["risk_feedback"])
	}
	riskFeedback := body["risk_feedback"].(map[string]any)
	if _, ok := riskFeedback["generated_at"].(string); !ok {
		t.Fatalf("expected typed risk_feedback.generated_at, got %#v", riskFeedback["generated_at"])
	}
	if _, ok := body["identity"].(map[string]any); !ok {
		t.Fatalf("expected identity object, got %#v", body["identity"])
	}
	if _, ok := body["ontology"].(map[string]any); !ok {
		t.Fatalf("expected ontology object, got %#v", body["ontology"])
	}
}

func TestGraphQueryEndpoint_NeighborsAndPaths(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "admin-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	neighbors := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:alice&direction=out&limit=10", nil)
	if neighbors.Code != http.StatusOK {
		t.Fatalf("expected 200 neighbors, got %d: %s", neighbors.Code, neighbors.Body.String())
	}
	neighborsBody := decodeJSON(t, neighbors)
	if neighborsBody["mode"] != "neighbors" {
		t.Fatalf("expected neighbors mode, got %#v", neighborsBody["mode"])
	}
	if count, ok := neighborsBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one neighbor, got %#v", neighborsBody["count"])
	}

	paths := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=paths&node_id=user:alice&target_id=db:prod&k=2&max_depth=6", nil)
	if paths.Code != http.StatusOK {
		t.Fatalf("expected 200 paths, got %d: %s", paths.Code, paths.Body.String())
	}
	pathsBody := decodeJSON(t, paths)
	if pathsBody["mode"] != "paths" {
		t.Fatalf("expected paths mode, got %#v", pathsBody["mode"])
	}
	if count, ok := pathsBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path, got %#v", pathsBody["count"])
	}

	if got := neighbors.Header().Get("Deprecation"); got != "true" {
		t.Fatalf("expected deprecation header on legacy graph query endpoint, got %q", got)
	}
	if got := neighbors.Header().Get("Sunset"); got == "" {
		t.Fatal("expected sunset header on legacy graph query endpoint")
	}
}

func TestPlatformGraphQueryEndpoint_PostAlias(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})
	g.AddNode(&graph.Node{ID: "role:admin", Kind: graph.NodeKindRole, Name: "Admin"})
	g.AddNode(&graph.Node{ID: "db:prod", Kind: graph.NodeKindDatabase, Name: "Prod", Risk: graph.RiskCritical})
	g.AddEdge(&graph.Edge{ID: "alice-admin", Source: "user:alice", Target: "role:admin", Kind: graph.EdgeKindCanAssume, Effect: graph.EdgeEffectAllow})
	g.AddEdge(&graph.Edge{ID: "admin-db", Source: "role:admin", Target: "db:prod", Kind: graph.EdgeKindCanRead, Effect: graph.EdgeEffectAllow})

	w := do(t, s, http.MethodPost, "/api/v1/platform/graph/queries", map[string]any{
		"mode":      "paths",
		"node_id":   "user:alice",
		"target_id": "db:prod",
		"k":         2,
		"max_depth": 6,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for platform graph query alias, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	if body["mode"] != "paths" {
		t.Fatalf("expected paths mode, got %#v", body["mode"])
	}
	if count, ok := body["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path, got %#v", body["count"])
	}
}

func TestGraphQueryEndpoint_TemporalScope(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "user:alice",
		Kind: graph.NodeKindUser,
		Name: "Alice",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "role:admin",
		Kind: graph.NodeKindRole,
		Name: "Admin",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-05T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "db:prod",
		Kind: graph.NodeKindDatabase,
		Name: "Prod",
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
		},
		Risk: graph.RiskCritical,
	})
	g.AddEdge(&graph.Edge{
		ID:     "alice-admin",
		Source: "user:alice",
		Target: "role:admin",
		Kind:   graph.EdgeKindCanAssume,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-05T00:00:00Z",
		},
	})
	g.AddEdge(&graph.Edge{
		ID:     "admin-db",
		Source: "role:admin",
		Target: "db:prod",
		Kind:   graph.EdgeKindCanRead,
		Effect: graph.EdgeEffectAllow,
		Properties: map[string]any{
			"observed_at": "2026-03-01T00:00:00Z",
			"valid_from":  "2026-03-01T00:00:00Z",
			"valid_to":    "2026-03-05T00:00:00Z",
		},
	})

	asOfActive := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:alice&direction=out&as_of=2026-03-04T00:00:00Z", nil)
	if asOfActive.Code != http.StatusOK {
		t.Fatalf("expected 200 for as_of active query, got %d: %s", asOfActive.Code, asOfActive.Body.String())
	}
	activeBody := decodeJSON(t, asOfActive)
	if count, ok := activeBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected active neighbors count >=1, got %#v", activeBody["count"])
	}

	asOfExpired := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:alice&direction=out&as_of=2026-03-08T00:00:00Z", nil)
	if asOfExpired.Code != http.StatusOK {
		t.Fatalf("expected 200 for expired as_of query, got %d: %s", asOfExpired.Code, asOfExpired.Body.String())
	}
	expiredBody := decodeJSON(t, asOfExpired)
	if count, ok := expiredBody["count"].(float64); !ok || count != 0 {
		t.Fatalf("expected expired neighbors count 0, got %#v", expiredBody["count"])
	}

	windowed := do(t, s, http.MethodGet, "/api/v1/graph/query?mode=paths&node_id=user:alice&target_id=db:prod&from=2026-03-01T00:00:00Z&to=2026-03-06T00:00:00Z", nil)
	if windowed.Code != http.StatusOK {
		t.Fatalf("expected 200 for windowed query, got %d: %s", windowed.Code, windowed.Body.String())
	}
	windowedBody := decodeJSON(t, windowed)
	if count, ok := windowedBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one path in window, got %#v", windowedBody["count"])
	}
}

func TestGraphQueryEndpoint_InvalidParams(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{ID: "user:alice", Kind: graph.NodeKindUser, Name: "Alice"})

	w := do(t, s, http.MethodGet, "/api/v1/graph/query", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing node_id, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=unsupported&node_id=user:alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported mode, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=paths&node_id=user:alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing target_id in paths mode, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing node, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:alice&as_of=not-a-time", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid as_of, got %d", w.Code)
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/query?mode=neighbors&node_id=user:alice&from=2026-03-01T00:00:00Z", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when from is missing to, got %d", w.Code)
	}
}
