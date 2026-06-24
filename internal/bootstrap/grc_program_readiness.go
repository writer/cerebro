package bootstrap

import (
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

type grcProgramReadinessResponse struct {
	grcprogram.Readiness
	SourceSummaries    []sourceRuntimeHealthSummary `json:"source_summaries,omitempty"`
	CoverageBlindSpots []sourcecoverage.Record      `json:"coverage_blind_spots,omitempty"`
	CoverageSummaries  []sourcecoverage.Summary     `json:"coverage_summaries,omitempty"`
}

func (a *App) handleGRCProgramReadiness(w http.ResponseWriter, r *http.Request) {
	result, err := a.buildGRCControlEvidencePacket(r)
	if err != nil {
		writeGRCControlPacketError(w, err)
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
	generatedAt := time.Now().UTC()
	sourceSummaries, err := a.grcSourceRuntimeHealthSummaries(r.Context(), runtimes, generatedAt)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	coverage := a.sourceCoverageRecords(runtimes, ports.SourceRuntimeFilter{
		RuntimeID:  scope.RuntimeID,
		RuntimeIDs: scope.RuntimeIDs,
		TenantID:   scope.TenantID,
		SourceID:   scope.SourceID,
		Limit:      scope.Limit,
	}, generatedAt)
	coverageBlindSpots := sourcecoverage.BlindSpots(coverage)
	readiness := grcprogram.Build(grcprogram.BuildInput{
		Result:             result,
		Query:              r.URL.Query(),
		TenantID:           scope.TenantID,
		Connectors:         grcProgramConnectors(grcConnectorItems(runtimes)),
		CoverageBlindSpots: len(coverageBlindSpots),
		GeneratedAt:        generatedAt,
	})
	writeJSON(w, http.StatusOK, grcProgramReadinessResponse{
		Readiness:          readiness,
		SourceSummaries:    sourceSummaries,
		CoverageBlindSpots: coverageBlindSpots,
		CoverageSummaries:  sourcecoverage.Summaries(coverage),
	})
}

func grcProgramConnectors(connectors []grcConnector) []grcprogram.Connector {
	items := make([]grcprogram.Connector, 0, len(connectors))
	for _, connector := range connectors {
		items = append(items, grcprogram.Connector{
			RuntimeID:           connector.RuntimeID,
			SourceID:            connector.SourceID,
			TenantID:            connector.TenantID,
			Status:              connector.Status,
			Freshness:           connector.Freshness,
			SyncLagSeconds:      connector.SyncLagSeconds,
			CheckpointWatermark: connector.CheckpointWatermark,
			WatermarkLagSeconds: connector.WatermarkLagSeconds,
			WatermarkFreshness:  connector.WatermarkFreshness,
			LastSyncedAt:        connector.LastSyncedAt,
		})
	}
	return items
}
