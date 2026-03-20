package api

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
)

// orgAnalysisService narrows the org-analysis handler family to typed graph
// operations instead of letting handlers reach through the full dependency
// bundle.
type orgAnalysisService interface {
	InformationPath(ctx context.Context, from, to string) (*graph.InformationPath, error)
	ClockSpeed(ctx context.Context) (graph.ClockSpeed, error)
	RecommendConnections(ctx context.Context, limit int) ([]graph.EdgeRecommendation, error)
	MeetingInsights(ctx context.Context, teamFilter string) (graph.MeetingInsightsReport, error)
	MeetingAnalysis(ctx context.Context, meetingID string) (*graph.MeetingAnalysis, error)
	OnboardingPlan(ctx context.Context, personID string) (*graph.OnboardingPlan, error)
}

type serverOrgAnalysisService struct {
	deps *serverDependencies
}

func newOrgAnalysisService(deps *serverDependencies) orgAnalysisService {
	return serverOrgAnalysisService{deps: deps}
}

func (s serverOrgAnalysisService) InformationPath(ctx context.Context, from, to string) (*graph.InformationPath, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return nil, err
	}
	return graph.ShortestInformationPath(g, from, to), nil
}

func (s serverOrgAnalysisService) ClockSpeed(ctx context.Context) (graph.ClockSpeed, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return graph.ClockSpeed{}, err
	}
	return graph.ComputeClockSpeed(g), nil
}

func (s serverOrgAnalysisService) RecommendConnections(ctx context.Context, limit int) ([]graph.EdgeRecommendation, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return nil, err
	}
	return graph.RecommendEdges(g, limit), nil
}

func (s serverOrgAnalysisService) MeetingInsights(ctx context.Context, teamFilter string) (graph.MeetingInsightsReport, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return graph.MeetingInsightsReport{}, err
	}
	return graph.AnalyzeMeetingInsights(g, teamFilter), nil
}

func (s serverOrgAnalysisService) MeetingAnalysis(ctx context.Context, meetingID string) (*graph.MeetingAnalysis, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return nil, err
	}
	return graph.AnalyzeMeetingByID(g, meetingID), nil
}

func (s serverOrgAnalysisService) OnboardingPlan(ctx context.Context, personID string) (*graph.OnboardingPlan, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return nil, err
	}
	return graph.GenerateOnboardingPlan(g, personID), nil
}

func (s serverOrgAnalysisService) tenantGraph(ctx context.Context) (*graph.Graph, error) {
	return currentOrStoredTenantGraphView(ctx, s.deps)
}

var _ orgAnalysisService = serverOrgAnalysisService{}
