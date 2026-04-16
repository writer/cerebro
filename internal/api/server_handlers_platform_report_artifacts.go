package api

import (
	"context"
	"time"

	reports "github.com/writer/cerebro/internal/graph/reports"
)

func (s *Server) buildPlatformReportArtifacts(ctx context.Context, run *reports.ReportRun, runID string, definition reports.ReportDefinition, result map[string]any, materializeResult bool, completedAt time.Time) ([]reports.ReportSectionResult, []reports.ReportSectionEmission, *reports.ReportSnapshot, error) {
	options := s.platformReportSectionBuildOptions(ctx, run)
	sections := reports.BuildReportSectionResultsWithOptions(definition, result, options)
	sectionEmissions := reports.BuildReportSectionEmissionsFromResults(sections, result, completedAt)
	var snapshot *reports.ReportSnapshot
	if materializeResult {
		var err error
		snapshot, err = reports.BuildReportSnapshot(runID, definition, result, true, completedAt)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return sections, sectionEmissions, snapshot, nil
}

func (s *Server) platformReportSectionBuildOptions(ctx context.Context, run *reports.ReportRun) *reports.ReportSectionBuildOptions {
	if run == nil {
		return nil
	}
	g, err := s.currentPlatformSecurityGraphView(ctx)
	if err != nil {
		g = nil
	}
	options := &reports.ReportSectionBuildOptions{
		Graph:            g,
		TimeSlice:        run.TimeSlice,
		CacheStatus:      run.CacheStatus,
		CacheSourceRunID: run.CacheSourceRunID,
	}
	if attempt := reports.LatestReportRunAttempt(run); attempt != nil {
		options.RetryBackoffMS = attempt.RetryBackoffMS
	}
	return options
}
