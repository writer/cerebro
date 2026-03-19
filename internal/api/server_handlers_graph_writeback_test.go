package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/webhooks"
)

func TestGraphWriteObservationAndAnnotation(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph
	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})

	observation := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/observations", map[string]any{
		"entity_id":     "service:payments",
		"observation":   "deploy_risk_increase",
		"summary":       "Error rates spiked after deploy",
		"source_system": "composer",
	})
	if observation.Code != http.StatusCreated {
		t.Fatalf("expected 201 for observation, got %d: %s", observation.Code, observation.Body.String())
	}
	observationBody := decodeJSON(t, observation)
	observationID, _ := observationBody["observation_id"].(string)
	if observationID == "" {
		t.Fatalf("expected observation_id, got %+v", observationBody)
	}
	observationNode, ok := s.app.CurrentSecurityGraph().GetNode(observationID)
	if !ok || observationNode == nil {
		t.Fatalf("expected observation node %q to exist", observationID)
	}
	if observationNode.Kind != graph.NodeKindObservation {
		t.Fatalf("expected observation node kind observation, got %q", observationNode.Kind)
	}

	annotation := do(t, s, http.MethodPost, "/api/v1/graph/write/annotation", map[string]any{
		"entity_id":     "service:payments",
		"annotation":    "Rollback candidate if p95 latency continues climbing",
		"tags":          []string{"incident", "latency"},
		"source_system": "analyst",
	})
	if annotation.Code != http.StatusCreated {
		t.Fatalf("expected 201 for annotation, got %d: %s", annotation.Code, annotation.Body.String())
	}
	annotatedNode, ok := s.app.CurrentSecurityGraph().GetNode("service:payments")
	if !ok || annotatedNode == nil {
		t.Fatal("expected annotated node")
	}
	annotations, ok := annotatedNode.Properties["annotations"].([]map[string]any)
	if ok && len(annotations) > 0 {
		return
	}
	if raw, ok := annotatedNode.Properties["annotations"].([]any); !ok || len(raw) == 0 {
		t.Fatalf("expected annotations on entity, got %#v", annotatedNode.Properties["annotations"])
	}
}

func TestGraphWriteDecisionOutcomeAndIdentity(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
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

	resolve := do(t, s, http.MethodPost, "/api/v1/graph/identity/resolve", map[string]any{
		"source_system": "github",
		"external_id":   "alice-handle",
		"email":         "alice@example.com",
		"name":          "Alice",
	})
	if resolve.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity resolve, got %d: %s", resolve.Code, resolve.Body.String())
	}
	resolveBody := decodeJSON(t, resolve)
	aliasID, _ := resolveBody["alias_node_id"].(string)
	if aliasID == "" {
		t.Fatalf("expected alias_node_id from identity resolve, got %+v", resolveBody)
	}

	decision := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/decisions", map[string]any{
		"decision_type": "rollback",
		"status":        "approved",
		"made_by":       "person:alice@example.com",
		"rationale":     "Error budget burn rate exceeded threshold",
		"target_ids":    []string{"service:payments"},
		"source_system": "conductor",
	})
	if decision.Code != http.StatusCreated {
		t.Fatalf("expected 201 for decision, got %d: %s", decision.Code, decision.Body.String())
	}
	decisionBody := decodeJSON(t, decision)
	decisionID, _ := decisionBody["decision_id"].(string)
	if decisionID == "" {
		t.Fatalf("expected decision_id, got %+v", decisionBody)
	}
	if node, ok := s.app.CurrentSecurityGraph().GetNode(decisionID); !ok || node == nil || node.Kind != graph.NodeKindDecision {
		t.Fatalf("expected decision node %q to exist, got %#v", decisionID, node)
	}

	outcome := do(t, s, http.MethodPost, "/api/v1/graph/write/outcome", map[string]any{
		"decision_id":   decisionID,
		"outcome_type":  "deployment_result",
		"verdict":       "positive",
		"impact_score":  0.7,
		"target_ids":    []string{"service:payments"},
		"source_system": "conductor",
	})
	if outcome.Code != http.StatusCreated {
		t.Fatalf("expected 201 for outcome, got %d: %s", outcome.Code, outcome.Body.String())
	}
	outcomeBody := decodeJSON(t, outcome)
	outcomeID, _ := outcomeBody["outcome_id"].(string)
	if outcomeID == "" {
		t.Fatalf("expected outcome_id, got %+v", outcomeBody)
	}
	if node, ok := s.app.CurrentSecurityGraph().GetNode(outcomeID); !ok || node == nil || node.Kind != graph.NodeKindOutcome {
		t.Fatalf("expected outcome node %q to exist, got %#v", outcomeID, node)
	}

	split := do(t, s, http.MethodPost, "/api/v1/graph/identity/split", map[string]any{
		"alias_node_id":     aliasID,
		"canonical_node_id": "person:alice@example.com",
		"reason":            "manual correction",
		"source_system":     "analyst",
	})
	if split.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity split, got %d: %s", split.Code, split.Body.String())
	}
	splitBody := decodeJSON(t, split)
	if removed, ok := splitBody["removed"].(bool); !ok || !removed {
		t.Fatalf("expected removed=true for identity split, got %+v", splitBody)
	}
}

func TestGraphWriteClaim(t *testing.T) {
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
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"observed_at": "2026-03-09T00:00:00Z",
			"valid_from":  "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "evidence:runbook",
		Kind: graph.NodeKindEvidence,
		Name: "Runbook",
		Properties: map[string]any{
			"evidence_type": "document",
			"source_system": "docs",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})

	w := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claims", map[string]any{
		"subject_id":        "service:payments",
		"predicate":         "owner",
		"object_id":         "person:alice@example.com",
		"summary":           "Payments is owned by Alice",
		"evidence_ids":      []string{"evidence:runbook"},
		"source_name":       "CMDB",
		"source_type":       "system",
		"trust_tier":        "authoritative",
		"reliability_score": 0.99,
		"source_system":     "api",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for claim, got %d: %s", w.Code, w.Body.String())
	}
	body := decodeJSON(t, w)
	claimID, _ := body["claim_id"].(string)
	if claimID == "" {
		t.Fatalf("expected claim_id, got %#v", body)
	}
	if node, ok := s.app.CurrentSecurityGraph().GetNode(claimID); !ok || node == nil || node.Kind != graph.NodeKindClaim {
		t.Fatalf("expected claim node %q, got %#v", claimID, node)
	}
	sourceID, _ := body["source_id"].(string)
	if sourceID == "" {
		t.Fatalf("expected source_id, got %#v", body)
	}
	if node, ok := s.app.CurrentSecurityGraph().GetNode(sourceID); !ok || node == nil || node.Kind != graph.NodeKindSource {
		t.Fatalf("expected source node %q, got %#v", sourceID, node)
	}
	if got := w.Header().Get("Deprecation"); got != "" {
		t.Fatalf("did not expect deprecation header on platform claim write endpoint, got %q", got)
	}
}

func TestPlatformClaimAndDecisionEndpoints(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{ID: "service:payments", Kind: graph.NodeKindService, Name: "Payments"})
	g.AddNode(&graph.Node{ID: "person:alice@example.com", Kind: graph.NodeKindPerson, Name: "Alice"})

	claim := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claims", map[string]any{
		"subject_id":    "service:payments",
		"predicate":     "owner",
		"object_id":     "person:alice@example.com",
		"source_system": "api",
	})
	if claim.Code != http.StatusCreated {
		t.Fatalf("expected 201 for platform claim endpoint, got %d: %s", claim.Code, claim.Body.String())
	}
	claimBody := decodeJSON(t, claim)
	if claimBody["claim_id"] == "" {
		t.Fatalf("expected claim_id, got %#v", claimBody)
	}

	decision := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/decisions", map[string]any{
		"decision_type": "owner-confirmation",
		"target_ids":    []string{"service:payments"},
		"source_system": "api",
	})
	if decision.Code != http.StatusCreated {
		t.Fatalf("expected 201 for platform decision endpoint, got %d: %s", decision.Code, decision.Body.String())
	}
	decisionBody := decodeJSON(t, decision)
	if decisionBody["decision_id"] == "" {
		t.Fatalf("expected decision_id, got %#v", decisionBody)
	}
}

func TestGraphIdentityReviewAndCalibrationEndpoints(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "person:alice@example.com",
		Kind: graph.NodeKindPerson,
		Name: "Alice",
		Properties: map[string]any{
			"email": "alice@example.com",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "identity_alias:github:alice",
		Kind: graph.NodeKindIdentityAlias,
		Name: "alice",
		Properties: map[string]any{
			"source_system": "github",
			"external_id":   "alice",
			"email":         "alice@example.com",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})

	review := do(t, s, http.MethodPost, "/api/v1/graph/identity/review", map[string]any{
		"alias_node_id":     "identity_alias:github:alice",
		"canonical_node_id": "person:alice@example.com",
		"verdict":           "accepted",
		"reviewer":          "analyst@company.com",
		"reason":            "exact email",
		"source_system":     "analyst",
	})
	if review.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity review, got %d: %s", review.Code, review.Body.String())
	}
	reviewBody := decodeJSON(t, review)
	if verdict, _ := reviewBody["verdict"].(string); verdict != "accepted" {
		t.Fatalf("expected accepted verdict, got %+v", reviewBody)
	}

	calibration := do(t, s, http.MethodGet, "/api/v1/graph/identity/calibration?include_queue=true&queue_limit=10", nil)
	if calibration.Code != http.StatusOK {
		t.Fatalf("expected 200 for identity calibration, got %d: %s", calibration.Code, calibration.Body.String())
	}
	calibrationBody := decodeJSON(t, calibration)
	if aliases, ok := calibrationBody["alias_nodes"].(float64); !ok || aliases < 1 {
		t.Fatalf("expected alias_nodes >=1, got %#v", calibrationBody["alias_nodes"])
	}
	if reviewed, ok := calibrationBody["reviewed_aliases"].(float64); !ok || reviewed < 1 {
		t.Fatalf("expected reviewed_aliases >=1, got %#v", calibrationBody["reviewed_aliases"])
	}
}

func TestGraphActuateRecommendationEndpoint(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-09T00:00:00Z",
			"valid_from":  "2026-03-09T00:00:00Z",
		},
	})
	g.AddNode(&graph.Node{
		ID:   "decision:rollback",
		Kind: graph.NodeKindDecision,
		Name: "Rollback",
		Properties: map[string]any{
			"decision_type": "rollback",
			"status":        "approved",
		},
	})

	actuation := do(t, s, http.MethodPost, "/api/v1/graph/actuate/recommendation", map[string]any{
		"recommendation_id": "rec-1",
		"insight_type":      "graph_freshness",
		"title":             "Increase scanner cadence",
		"summary":           "Reduce freshness lag on payments",
		"decision_id":       "decision:rollback",
		"target_ids":        []string{"service:payments"},
		"source_system":     "conductor",
		"auto_generated":    true,
	})
	if actuation.Code != http.StatusCreated {
		t.Fatalf("expected 201 for recommendation actuation, got %d: %s", actuation.Code, actuation.Body.String())
	}
	body := decodeJSON(t, actuation)
	actionID, _ := body["action_id"].(string)
	if actionID == "" {
		t.Fatalf("expected action_id, got %#v", body)
	}
	if node, ok := s.app.CurrentSecurityGraph().GetNode(actionID); !ok || node == nil || node.Kind != graph.NodeKindAction {
		t.Fatalf("expected action node %q to exist, got %#v", actionID, node)
	}

	invalid := do(t, s, http.MethodPost, "/api/v1/graph/actuate/recommendation", map[string]any{
		"target_ids": []string{"service:payments"},
	})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid recommendation actuation payload, got %d: %s", invalid.Code, invalid.Body.String())
	}
}

func TestGraphWritebackEmitsPlatformLifecycleEvents(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-09T00:00:00Z",
			"valid_from":  "2026-03-09T00:00:00Z",
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
	g.AddNode(&graph.Node{
		ID:   "evidence:runbook",
		Kind: graph.NodeKindEvidence,
		Name: "Runbook",
		Properties: map[string]any{
			"evidence_type": "document",
			"source_system": "docs",
			"observed_at":   "2026-03-09T00:00:00Z",
			"valid_from":    "2026-03-09T00:00:00Z",
		},
	})

	eventsCh := make(chan webhooks.Event, 8)
	s.app.Webhooks.Subscribe(func(_ context.Context, event webhooks.Event) error {
		eventsCh <- event
		return nil
	})

	claim := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claims", map[string]any{
		"subject_id":    "service:payments",
		"predicate":     "owner",
		"object_id":     "person:alice@example.com",
		"evidence_ids":  []string{"evidence:runbook"},
		"source_system": "api",
	})
	if claim.Code != http.StatusCreated {
		t.Fatalf("expected 201 for claim, got %d: %s", claim.Code, claim.Body.String())
	}
	claimBody := decodeJSON(t, claim)
	event := <-eventsCh
	if event.Type != webhooks.EventPlatformClaimWritten {
		t.Fatalf("expected claim lifecycle event, got %q", event.Type)
	}
	if event.Data["claim_id"] != claimBody["claim_id"] {
		t.Fatalf("expected claim_id %v, got %#v", claimBody["claim_id"], event.Data["claim_id"])
	}
	if event.Data["subject_id"] != "service:payments" {
		t.Fatalf("expected subject_id service:payments, got %#v", event.Data["subject_id"])
	}

	decision := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/decisions", map[string]any{
		"decision_type": "rollback",
		"status":        "approved",
		"made_by":       "person:alice@example.com",
		"target_ids":    []string{"service:payments"},
		"source_system": "conductor",
	})
	if decision.Code != http.StatusCreated {
		t.Fatalf("expected 201 for decision, got %d: %s", decision.Code, decision.Body.String())
	}
	decisionBody := decodeJSON(t, decision)
	event = <-eventsCh
	if event.Type != webhooks.EventPlatformDecisionRecorded {
		t.Fatalf("expected decision lifecycle event, got %q", event.Type)
	}
	if event.Data["decision_id"] != decisionBody["decision_id"] {
		t.Fatalf("expected decision_id %v, got %#v", decisionBody["decision_id"], event.Data["decision_id"])
	}
	if event.Data["status"] != "approved" {
		t.Fatalf("expected approved status, got %#v", event.Data["status"])
	}

	outcome := do(t, s, http.MethodPost, "/api/v1/graph/write/outcome", map[string]any{
		"decision_id":   decisionBody["decision_id"],
		"outcome_type":  "deployment_result",
		"verdict":       "positive",
		"impact_score":  0.7,
		"target_ids":    []string{"service:payments"},
		"source_system": "conductor",
	})
	if outcome.Code != http.StatusCreated {
		t.Fatalf("expected 201 for outcome, got %d: %s", outcome.Code, outcome.Body.String())
	}
	outcomeBody := decodeJSON(t, outcome)
	event = <-eventsCh
	if event.Type != webhooks.EventPlatformOutcomeRecorded {
		t.Fatalf("expected outcome lifecycle event, got %q", event.Type)
	}
	if event.Data["outcome_id"] != outcomeBody["outcome_id"] {
		t.Fatalf("expected outcome_id %v, got %#v", outcomeBody["outcome_id"], event.Data["outcome_id"])
	}

	action := do(t, s, http.MethodPost, "/api/v1/graph/actuate/recommendation", map[string]any{
		"recommendation_id": "rec-1",
		"insight_type":      "graph_freshness",
		"title":             "Increase scanner cadence",
		"summary":           "Reduce freshness lag on payments",
		"decision_id":       decisionBody["decision_id"],
		"target_ids":        []string{"service:payments"},
		"source_system":     "conductor",
		"auto_generated":    true,
	})
	if action.Code != http.StatusCreated {
		t.Fatalf("expected 201 for action, got %d: %s", action.Code, action.Body.String())
	}
	actionBody := decodeJSON(t, action)
	event = <-eventsCh
	if event.Type != webhooks.EventPlatformActionRecorded {
		t.Fatalf("expected action lifecycle event, got %q", event.Type)
	}
	if event.Data["action_id"] != actionBody["action_id"] {
		t.Fatalf("expected action_id %v, got %#v", actionBody["action_id"], event.Data["action_id"])
	}
	if event.Data["auto_generated"] != true {
		t.Fatalf("expected auto_generated=true, got %#v", event.Data["auto_generated"])
	}
}

func TestGraphWritebackValidationFailures(t *testing.T) {
	s := newTestServer(t)
	g := s.app.SecurityGraph

	g.AddNode(&graph.Node{
		ID:   "service:payments",
		Kind: graph.NodeKindService,
		Name: "Payments",
		Properties: map[string]any{
			"service_id":  "payments",
			"observed_at": "2026-03-08T00:00:00Z",
			"valid_from":  "2026-03-08T00:00:00Z",
		},
	})

	observation := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/observations", map[string]any{
		"observation": "deploy_risk_increase",
	})
	if observation.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing entity_id, got %d: %s", observation.Code, observation.Body.String())
	}

	decision := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/decisions", map[string]any{
		"decision_type": "rollback",
		"target_ids":    []string{"service:missing"},
	})
	if decision.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing decision target, got %d: %s", decision.Code, decision.Body.String())
	}

	outcome := do(t, s, http.MethodPost, "/api/v1/graph/write/outcome", map[string]any{
		"decision_id":  "decision:missing",
		"outcome_type": "deployment_result",
		"verdict":      "positive",
	})
	if outcome.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing decision on outcome, got %d: %s", outcome.Code, outcome.Body.String())
	}

	resolve := do(t, s, http.MethodPost, "/api/v1/graph/identity/resolve", map[string]any{
		"external_id": "alice-handle",
	})
	if resolve.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing source_system on identity resolve, got %d: %s", resolve.Code, resolve.Body.String())
	}

	split := do(t, s, http.MethodPost, "/api/v1/graph/identity/split", map[string]any{
		"alias_node_id": "alias:github:alice-handle",
	})
	if split.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing canonical_node_id on identity split, got %d: %s", split.Code, split.Body.String())
	}

	claim := do(t, s, http.MethodPost, "/api/v1/platform/knowledge/claims", map[string]any{
		"subject_id":   "service:missing",
		"predicate":    "owner",
		"object_value": "alice",
	})
	if claim.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing claim subject, got %d: %s", claim.Code, claim.Body.String())
	}
}
