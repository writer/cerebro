package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/graph"
)

func buildGraphStoreOrgOnboardingTestGraph() *graph.Graph {
	g := graph.New()
	seedOrgOnboardingGraph(g)
	return g
}

func buildGraphStoreOrgMeetingInsightsTestGraph() *graph.Graph {
	g := graph.New()
	seedOrgMeetingInsightsGraph(g)
	return g
}

func buildGraphStoreOrgInformationFlowTestGraph() *graph.Graph {
	g := graph.New()
	seedOrgInformationFlowGraph(g, time.Now().UTC())
	return g
}

func TestOrgOnboardingPlanUsesGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreOrgOnboardingTestGraph())

	resp := do(t, s, http.MethodGet, "/api/v1/org/onboarding/person:newhire@example.com/plan", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected onboarding plan 200, got %d: %s", resp.Code, resp.Body.String())
	}
	body := decodeJSON(t, resp)
	if body["person_id"] != "person:newhire@example.com" {
		t.Fatalf("expected onboarding response from store-backed handler, got %#v", body)
	}
}

func TestOrgMeetingHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreOrgMeetingInsightsTestGraph())

	insights := do(t, s, http.MethodGet, "/api/v1/org/meeting-insights?team=support", nil)
	if insights.Code != http.StatusOK {
		t.Fatalf("expected meeting insights 200, got %d: %s", insights.Code, insights.Body.String())
	}
	insightsBody := decodeJSON(t, insights)
	meetings, ok := insightsBody["meetings"].([]any)
	if !ok || len(meetings) == 0 {
		t.Fatalf("expected meeting insights from store-backed handler, got %#v", insightsBody)
	}

	analysis := do(t, s, http.MethodGet, "/api/v1/org/meetings/activity:meeting-1/analysis", nil)
	if analysis.Code != http.StatusOK {
		t.Fatalf("expected meeting analysis 200, got %d: %s", analysis.Code, analysis.Body.String())
	}
}

func TestOrgInformationFlowHandlersUseGraphStoreWhenRawGraphUnavailable(t *testing.T) {
	s := newStoreBackedGraphServer(t, buildGraphStoreOrgInformationFlowTestGraph())

	path := do(t, s, http.MethodGet, "/api/v1/org/information-flow?from=team/support&to=team/engineering", nil)
	if path.Code != http.StatusOK {
		t.Fatalf("expected information flow 200, got %d: %s", path.Code, path.Body.String())
	}

	clock := do(t, s, http.MethodGet, "/api/v1/org/clock-speed", nil)
	if clock.Code != http.StatusOK {
		t.Fatalf("expected clock speed 200, got %d: %s", clock.Code, clock.Body.String())
	}

	recommendations := do(t, s, http.MethodGet, "/api/v1/org/recommended-connections?limit=1", nil)
	if recommendations.Code != http.StatusOK {
		t.Fatalf("expected recommended connections 200, got %d: %s", recommendations.Code, recommendations.Body.String())
	}
	body := decodeJSON(t, recommendations)
	if count, ok := body["count"].(float64); !ok || int(count) != 1 {
		t.Fatalf("expected one recommendation from store-backed handler, got %#v", body)
	}
}
