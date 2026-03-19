package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/graph"
)

type stubOrgAnalysisService struct {
	informationPathFunc      func(context.Context, string, string) (*graph.InformationPath, error)
	clockSpeedFunc           func(context.Context) (graph.ClockSpeed, error)
	recommendConnectionsFunc func(context.Context, int) ([]graph.EdgeRecommendation, error)
	meetingInsightsFunc      func(context.Context, string) (graph.MeetingInsightsReport, error)
	meetingAnalysisFunc      func(context.Context, string) (*graph.MeetingAnalysis, error)
	onboardingPlanFunc       func(context.Context, string) (*graph.OnboardingPlan, error)
}

func (s stubOrgAnalysisService) InformationPath(ctx context.Context, from, to string) (*graph.InformationPath, error) {
	if s.informationPathFunc != nil {
		return s.informationPathFunc(ctx, from, to)
	}
	return nil, nil
}

func (s stubOrgAnalysisService) ClockSpeed(ctx context.Context) (graph.ClockSpeed, error) {
	if s.clockSpeedFunc != nil {
		return s.clockSpeedFunc(ctx)
	}
	return graph.ClockSpeed{}, nil
}

func (s stubOrgAnalysisService) RecommendConnections(ctx context.Context, limit int) ([]graph.EdgeRecommendation, error) {
	if s.recommendConnectionsFunc != nil {
		return s.recommendConnectionsFunc(ctx, limit)
	}
	return nil, nil
}

func (s stubOrgAnalysisService) MeetingInsights(ctx context.Context, teamFilter string) (graph.MeetingInsightsReport, error) {
	if s.meetingInsightsFunc != nil {
		return s.meetingInsightsFunc(ctx, teamFilter)
	}
	return graph.MeetingInsightsReport{}, nil
}

func (s stubOrgAnalysisService) MeetingAnalysis(ctx context.Context, meetingID string) (*graph.MeetingAnalysis, error) {
	if s.meetingAnalysisFunc != nil {
		return s.meetingAnalysisFunc(ctx, meetingID)
	}
	return nil, nil
}

func (s stubOrgAnalysisService) OnboardingPlan(ctx context.Context, personID string) (*graph.OnboardingPlan, error) {
	if s.onboardingPlanFunc != nil {
		return s.onboardingPlanFunc(ctx, personID)
	}
	return nil, nil
}

func TestOrgInformationHandlersUseServiceInterface(t *testing.T) {
	var (
		pathCalled  bool
		clockCalled bool
		recsCalled  bool
	)
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		orgAnalysis: stubOrgAnalysisService{
			informationPathFunc: func(_ context.Context, from, to string) (*graph.InformationPath, error) {
				pathCalled = true
				if from != "team/support" || to != "team/engineering" {
					t.Fatalf("unexpected information-flow params: from=%q to=%q", from, to)
				}
				return &graph.InformationPath{Source: from, Destination: to, Hops: 2}, nil
			},
			clockSpeedFunc: func(_ context.Context) (graph.ClockSpeed, error) {
				clockCalled = true
				return graph.ClockSpeed{
					CustomerIssueToResolver: graph.PathMetrics{SampleSize: 1},
					AverageHops:             1.5,
				}, nil
			},
			recommendConnectionsFunc: func(_ context.Context, limit int) ([]graph.EdgeRecommendation, error) {
				recsCalled = true
				if limit != 50 {
					t.Fatalf("expected clamped limit=50, got %d", limit)
				}
				return []graph.EdgeRecommendation{{
					PersonA: "person:alice@example.com",
					PersonB: "person:bob@example.com",
				}}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	pathResp := do(t, s, http.MethodGet, "/api/v1/org/information-flow?from=team/support&to=team/engineering", nil)
	if pathResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed information flow, got %d: %s", pathResp.Code, pathResp.Body.String())
	}
	if !pathCalled {
		t.Fatal("expected information-flow handler to use org analysis service")
	}

	clockResp := do(t, s, http.MethodGet, "/api/v1/org/clock-speed", nil)
	if clockResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed clock speed, got %d: %s", clockResp.Code, clockResp.Body.String())
	}
	if !clockCalled {
		t.Fatal("expected clock-speed handler to use org analysis service")
	}

	recsResp := do(t, s, http.MethodGet, "/api/v1/org/recommended-connections?limit=999", nil)
	if recsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed recommendations, got %d: %s", recsResp.Code, recsResp.Body.String())
	}
	if !recsCalled {
		t.Fatal("expected recommended-connections handler to use org analysis service")
	}
	body := decodeJSON(t, recsResp)
	if body["count"] != float64(1) {
		t.Fatalf("expected stubbed recommendation count, got %#v", body["count"])
	}
}

func TestOrgMeetingHandlersUseServiceInterface(t *testing.T) {
	var (
		insightsCalled bool
		analysisCalled bool
	)
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		orgAnalysis: stubOrgAnalysisService{
			meetingInsightsFunc: func(_ context.Context, team string) (graph.MeetingInsightsReport, error) {
				insightsCalled = true
				if team != "support" {
					t.Fatalf("expected team filter to reach service, got %q", team)
				}
				return graph.MeetingInsightsReport{
					Meetings: []graph.MeetingInsight{{MeetingID: "activity:meeting-1"}},
				}, nil
			},
			meetingAnalysisFunc: func(_ context.Context, meetingID string) (*graph.MeetingAnalysis, error) {
				analysisCalled = true
				if meetingID != "activity:meeting-1" {
					t.Fatalf("expected meeting id to reach service, got %q", meetingID)
				}
				return &graph.MeetingAnalysis{
					Meeting: graph.MeetingInsight{MeetingID: meetingID},
				}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	insightsResp := do(t, s, http.MethodGet, "/api/v1/org/meeting-insights?team=support", nil)
	if insightsResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed meeting insights, got %d: %s", insightsResp.Code, insightsResp.Body.String())
	}
	if !insightsCalled {
		t.Fatal("expected meeting-insights handler to use org analysis service")
	}

	analysisResp := do(t, s, http.MethodGet, "/api/v1/org/meetings/activity:meeting-1/analysis", nil)
	if analysisResp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed meeting analysis, got %d: %s", analysisResp.Code, analysisResp.Body.String())
	}
	if !analysisCalled {
		t.Fatal("expected meeting analysis handler to use org analysis service")
	}
}

func TestOrgOnboardingHandlerUsesServiceInterface(t *testing.T) {
	var called bool
	generatedAt := time.Date(2026, 3, 19, 16, 40, 0, 0, time.UTC)
	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		orgAnalysis: stubOrgAnalysisService{
			onboardingPlanFunc: func(_ context.Context, personID string) (*graph.OnboardingPlan, error) {
				called = true
				if personID != "person:newhire@example.com" {
					t.Fatalf("expected onboarding person id to reach service, got %q", personID)
				}
				return &graph.OnboardingPlan{
					PersonID:    personID,
					GeneratedAt: generatedAt,
				}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	resp := do(t, s, http.MethodGet, "/api/v1/org/onboarding/person:newhire@example.com/plan", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed onboarding plan, got %d: %s", resp.Code, resp.Body.String())
	}
	if !called {
		t.Fatal("expected onboarding handler to use org analysis service")
	}
	body := decodeJSON(t, resp)
	if body["person_id"] != "person:newhire@example.com" {
		t.Fatalf("expected stubbed onboarding response, got %#v", body)
	}
}
