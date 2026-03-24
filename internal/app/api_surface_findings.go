package app

import (
	"context"

	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
)

type APISurfaceFindingScanResult struct {
	Endpoints int
	Findings  []policy.Finding
	Errors    []string
}

func (a *App) ScanAPISurfaceFindings(ctx context.Context) APISurfaceFindingScanResult {
	result := APISurfaceFindingScanResult{Findings: make([]policy.Finding, 0)}
	if a == nil {
		return result
	}
	securityGraph, err := a.currentOrStoredSecurityGraphView()
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	if securityGraph == nil {
		return result
	}
	report := graph.AnalyzeAPISurface(securityGraph, graph.APISurfaceReportOptions{
		IncludeInternal: false,
		MaxDepth:        4,
	})
	result.Endpoints = report.Count
	result.Findings = append(result.Findings, apiSurfaceReportToPolicyFindings(report)...)
	return result
}

func apiSurfaceReportToPolicyFindings(report graph.APISurfaceReport) []policy.Finding {
	if len(report.Findings) == 0 {
		return nil
	}
	out := make([]policy.Finding, 0, len(report.Findings))
	index := make(map[string]graph.APISurfaceEndpoint, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		index[endpoint.ID] = endpoint
	}
	for _, finding := range report.Findings {
		endpoint := index[finding.EndpointID]
		resource := map[string]any{
			"id":               endpoint.ID,
			"type":             string(graph.NodeKindAPIEndpoint),
			"url":              endpoint.URL,
			"method":           endpoint.Method,
			"host":             endpoint.Host,
			"path":             endpoint.Path,
			"provider":         endpoint.Provider,
			"provider_service": endpoint.ProviderService,
			"public":           endpoint.Public,
			"auth_type":        endpoint.AuthType,
			"cors_permissive":  endpoint.CORSPermissive,
		}
		out = append(out, policy.Finding{
			ID:           finding.ID,
			PolicyID:     "graph-api-" + finding.Category,
			PolicyName:   finding.Title,
			Severity:     finding.Severity,
			Resource:     resource,
			Description:  finding.Message,
			Title:        finding.Title,
			ResourceType: string(graph.NodeKindAPIEndpoint),
			ResourceID:   endpoint.ID,
			ResourceName: endpoint.URL,
			RiskCategories: []string{
				policy.RiskExternalAttackSurface,
			},
		})
	}
	return out
}
