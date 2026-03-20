package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/graph"
)

type stubGraphRuleDiscoveryService struct {
	discoverFunc func(context.Context, graph.RuleDiscoveryRequest) ([]graph.DiscoveredRuleCandidate, error)
	listFunc     func(context.Context, string) ([]graph.DiscoveredRuleCandidate, error)
	decideFunc   func(context.Context, string, graph.RuleDecisionRequest) (*graph.DiscoveredRuleCandidate, error)
}

func (s stubGraphRuleDiscoveryService) Discover(ctx context.Context, req graph.RuleDiscoveryRequest) ([]graph.DiscoveredRuleCandidate, error) {
	if s.discoverFunc != nil {
		return s.discoverFunc(ctx, req)
	}
	return nil, nil
}

func (s stubGraphRuleDiscoveryService) List(ctx context.Context, status string) ([]graph.DiscoveredRuleCandidate, error) {
	if s.listFunc != nil {
		return s.listFunc(ctx, status)
	}
	return nil, nil
}

func (s stubGraphRuleDiscoveryService) Decide(ctx context.Context, candidateID string, req graph.RuleDecisionRequest) (*graph.DiscoveredRuleCandidate, error) {
	if s.decideFunc != nil {
		return s.decideFunc(ctx, candidateID, req)
	}
	return nil, nil
}

func TestGraphRuleDiscoveryHandlersUseServiceInterface(t *testing.T) {
	var (
		discoverCalled bool
		listCalled     bool
		decideCalled   bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		graphRuleDiscovery: stubGraphRuleDiscoveryService{
			discoverFunc: func(_ context.Context, req graph.RuleDiscoveryRequest) ([]graph.DiscoveredRuleCandidate, error) {
				discoverCalled = true
				if req.WindowDays != 30 || req.MinDetections != 4 || req.MaxCandidates != 8 {
					t.Fatalf("unexpected discovery request: %#v", req)
				}
				if req.Profile != "prod" || !req.IncludePolicies || req.IncludeToxicCombinations {
					t.Fatalf("unexpected discovery request flags: %#v", req)
				}
				return []graph.DiscoveredRuleCandidate{{
					ID:         "discover:policy-1",
					Type:       graph.RuleCandidateTypePolicy,
					Status:     graph.RuleCandidateStatusPendingApproval,
					Support:    7,
					Precision:  0.82,
					ProposedAt: time.Unix(1700, 0).UTC(),
					UpdatedAt:  time.Unix(1700, 0).UTC(),
				}}, nil
			},
			listFunc: func(_ context.Context, status string) ([]graph.DiscoveredRuleCandidate, error) {
				listCalled = true
				if status != graph.RuleCandidateStatusApproved {
					t.Fatalf("expected approved status filter, got %q", status)
				}
				return []graph.DiscoveredRuleCandidate{{
					ID:         "discover:policy-2",
					Type:       graph.RuleCandidateTypePolicy,
					Status:     graph.RuleCandidateStatusApproved,
					Activated:  true,
					Support:    5,
					Precision:  0.76,
					ProposedAt: time.Unix(1701, 0).UTC(),
					UpdatedAt:  time.Unix(1702, 0).UTC(),
				}}, nil
			},
			decideFunc: func(_ context.Context, candidateID string, req graph.RuleDecisionRequest) (*graph.DiscoveredRuleCandidate, error) {
				decideCalled = true
				if candidateID != "discover:policy-1" {
					t.Fatalf("unexpected candidate id: %q", candidateID)
				}
				if !req.Approve || req.Reviewer != "security-lead" || req.Notes != "ship it" {
					t.Fatalf("unexpected decision request: %#v", req)
				}
				reviewedAt := time.Unix(1703, 0).UTC()
				return &graph.DiscoveredRuleCandidate{
					ID:          candidateID,
					Type:        graph.RuleCandidateTypePolicy,
					Status:      graph.RuleCandidateStatusApproved,
					Activated:   true,
					ReviewedBy:  req.Reviewer,
					ReviewedAt:  &reviewedAt,
					ReviewNotes: req.Notes,
					ProposedAt:  time.Unix(1700, 0).UTC(),
					UpdatedAt:   reviewedAt,
				}, nil
			},
		},
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	runResp := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/run", map[string]any{
		"window_days":                30,
		"min_detections":             4,
		"max_candidates":             8,
		"profile":                    "prod",
		"include_policies":           true,
		"include_toxic_combinations": false,
	})
	if runResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for discovery run, got %d: %s", runResp.Code, runResp.Body.String())
	}
	if !discoverCalled {
		t.Fatal("expected discovery run handler to use graphRuleDiscovery service")
	}
	runBody := decodeJSON(t, runResp)
	if count, ok := runBody["count"].(float64); !ok || count != 1 {
		t.Fatalf("expected one discovery candidate, got %#v", runBody)
	}

	listResp := do(t, s, http.MethodGet, "/api/v1/graph/rule-discovery/candidates?status=approved", nil)
	if listResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for discovery list, got %d: %s", listResp.Code, listResp.Body.String())
	}
	if !listCalled {
		t.Fatal("expected discovery list handler to use graphRuleDiscovery service")
	}

	decideResp := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/candidates/discover:policy-1/decision", map[string]any{
		"approve":  true,
		"reviewer": "security-lead",
		"notes":    "ship it",
	})
	if decideResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for discovery decision, got %d: %s", decideResp.Code, decideResp.Body.String())
	}
	if !decideCalled {
		t.Fatal("expected discovery decision handler to use graphRuleDiscovery service")
	}
	decideBody := decodeJSON(t, decideResp)
	candidate, ok := decideBody["candidate"].(map[string]any)
	if !ok || candidate["status"] != graph.RuleCandidateStatusApproved {
		t.Fatalf("expected approved candidate payload, got %#v", decideBody)
	}
}

func TestGraphRuleDiscoveryHandlersReturnServiceUnavailableWhenGraphMissing(t *testing.T) {
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
	})
	s.app.SecurityGraph = nil
	t.Cleanup(func() { s.Close() })

	runResp := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/run", map[string]any{})
	if runResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for discovery run without graph, got %d: %s", runResp.Code, runResp.Body.String())
	}

	listResp := do(t, s, http.MethodGet, "/api/v1/graph/rule-discovery/candidates", nil)
	if listResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for discovery list without graph, got %d: %s", listResp.Code, listResp.Body.String())
	}

	decideResp := do(t, s, http.MethodPost, "/api/v1/graph/rule-discovery/candidates/discover:missing/decision", map[string]any{
		"approve": false,
	})
	if decideResp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for discovery decision without graph, got %d: %s", decideResp.Code, decideResp.Body.String())
	}
}
