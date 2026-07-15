package bootstrap

import (
	"errors"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecoverage"
	"github.com/writer/cerebro/internal/sourcehttp/responseview"
)

type grcProgramReadinessResponse struct {
	grcprogram.Readiness
	SourceSummaries    []sourceRuntimeHealthSummary `json:"source_summaries,omitempty"`
	CoverageBlindSpots []sourcecoverage.Record      `json:"coverage_blind_spots,omitempty"`
	CoverageSummaries  []sourcecoverage.Summary     `json:"coverage_summaries,omitempty"`
}

func (a *App) handleGRCProgramReadiness(w http.ResponseWriter, r *http.Request) {
	view, err := responseview.FromRequest(r)
	if err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	coverageScope, err := responseview.CoverageScopeFromRequest(r, view)
	if err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	runtimes, err := a.grcListRuntimes(r, scope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	result, err := a.buildGRCControlEvidencePacketWithScope(r, scope, runtimes)
	if err != nil {
		writeGRCControlPacketError(w, err)
		return
	}
	generatedAt := time.Now().UTC()
	sourceSummaries, err := a.grcSourceRuntimeHealthSummaries(r.Context(), runtimes, generatedAt)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	coverage, err := a.sourceCoverageRecordsScoped(r.Context(), runtimes, ports.SourceRuntimeFilter{
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		TenantID:   scope.TenantID,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	}, generatedAt, coverageScope)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	coverageBlindSpots := sourcecoverage.BlindSpots(coverage)
	readiness := grcprogram.Build(grcprogram.BuildInput{
		Result:             result,
		Query:              r.URL.Query(),
		TenantID:           scope.TenantID,
		Connectors:         grcProgramConnectors(grcConnectorItems(runtimes)),
		CoverageBlindSpots: len(coverageBlindSpots),
		CoverageRecords:    coverage,
		GeneratedAt:        generatedAt,
	})
	serializedCoverageBlindSpots := coverageBlindSpots
	if view == responseview.Summary {
		serializedCoverageBlindSpots = nil
		readiness.ProductAreas = responseview.CompactProductAreas(readiness.ProductAreas)
	}
	writeJSON(w, http.StatusOK, grcProgramReadinessResponse{
		Readiness:          readiness,
		SourceSummaries:    sourceSummaries,
		CoverageBlindSpots: serializedCoverageBlindSpots,
		CoverageSummaries:  sourcecoverage.Summaries(coverage),
	})
}

func grcProgramConnectors(connectors []grcConnector) []grcprogram.Connector {
	items := make([]grcprogram.Connector, 0, len(connectors))
	for _, connector := range connectors {
		items = append(items, grcprogram.Connector(connector))
	}
	return items
}
