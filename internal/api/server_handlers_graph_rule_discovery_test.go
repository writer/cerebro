package api

import (
	"net/http"
	"testing"
	"time"
)

func TestGraphRuleDiscoveryApprovalFlowEndpoints(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	for i := 0; i < 5; i++ {
		w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected 200 from outcomes POST, got %d: %s", record.Code, record.Body.String())
	}

	run := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/run", map[string]any{
		"window_days":                365,
		"min_detections":             3,
		"max_candidates":             10,
		"include_policies":           true,
		"include_toxic_combinations": true,
	})
	if run.Code != http.StatusOK {
		t.Fatalf("expected 200 from discovery run, got %d: %s", run.Code, run.Body.String())
	}
	runBody := decodeJSON(t, run)
	candidates, ok := runBody["candidates"].([]any)
	if !ok || len(candidates) == 0 {
		t.Fatalf("expected candidates from discovery run, got %+v", runBody["candidates"])
	}

	first, ok := candidates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected candidate object, got %T", candidates[0])
	}
	candidateID, _ := first["id"].(string)
	if candidateID == "" {
		t.Fatalf("expected candidate id, got %+v", first)
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/rule-discovery/candidates?status=pending_approval", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected 200 from candidate list, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected pending candidates, got %+v", listBody)
	}

	approve := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/candidates/"+candidateID+"/decision", map[string]any{
		"approve":  true,
		"reviewer": "security-lead",
		"notes":    "activate for monitoring",
	})
	if approve.Code != http.StatusOK {
		t.Fatalf("expected 200 from candidate approval, got %d: %s", approve.Code, approve.Body.String())
	}
	approveBody := decodeJSON(t, approve)
	candidate, ok := approveBody["candidate"].(map[string]any)
	if !ok {
		t.Fatalf("expected candidate payload after approval, got %+v", approveBody)
	}
	if status, _ := candidate["status"].(string); status != "approved" {
		t.Fatalf("expected approved status, got %+v", candidate["status"])
	}
}

func TestGraphRuleDiscoveryDecision_NotFound(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/candidates/discover:missing/decision", map[string]any{
		"approve": false,
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing candidate, got %d: %s", w.Code, w.Body.String())
	}
}
