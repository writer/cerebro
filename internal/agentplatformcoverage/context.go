package agentplatformcoverage

import (
	"context"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/agentplatform"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

func FromRuntimeStore(ctx context.Context, registry *sourcecdk.Registry, lister ports.SourceRuntimeListStore, tenantID string, generatedAt time.Time, status func(*cerebrov1.SourceRuntime) string, limit int) *agentplatform.AgentCoverageContext {
	tenantID = strings.TrimSpace(tenantID)
	if lister == nil || tenantID == "" {
		return nil
	}
	runtimes, err := lister.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{TenantID: tenantID, Limit: 500})
	if err != nil {
		return nil
	}
	return FromRuntimes(registry, runtimes, tenantID, generatedAt, status, limit)
}

func FromRuntimes(registry *sourcecdk.Registry, runtimes []*cerebrov1.SourceRuntime, tenantID string, generatedAt time.Time, status func(*cerebrov1.SourceRuntime) string, limit int) *agentplatform.AgentCoverageContext {
	if registry == nil || strings.TrimSpace(tenantID) == "" {
		return nil
	}
	contracts := sourcecoverage.ContractsFromRegistry(registry)
	if len(contracts) == 0 {
		return nil
	}
	observations := sourcecoverage.ObservationsFromRuntimes(runtimes, status)
	records := sourcecoverage.Evaluate(contracts, observations, sourcecoverage.Options{TenantID: strings.TrimSpace(tenantID)})
	return FromReport(sourcecoverage.BuildReport(records, sourcecoverage.Options{TenantID: strings.TrimSpace(tenantID)}, generatedAt), limit)
}

func FromReport(report sourcecoverage.Report, limit int) *agentplatform.AgentCoverageContext {
	if report.Version == "" && report.Totals.Dimensions == 0 && len(report.BlindSpots) == 0 {
		return nil
	}
	if limit <= 0 {
		limit = 5
	}
	blindSpots := report.BlindSpots
	if len(blindSpots) > limit {
		blindSpots = blindSpots[:limit]
	}
	context := &agentplatform.AgentCoverageContext{
		Version:             report.Version,
		TenantID:            report.TenantID,
		SourceID:            report.SourceID,
		GeneratedAt:         report.GeneratedAt,
		TotalDimensions:     report.Totals.Dimensions,
		HighValueDimensions: report.Totals.HighValueDimensions,
		BlindSpotCount:      report.Totals.BlindSpots,
		UnconfiguredCount:   report.Totals.Unconfigured,
		StaleCount:          report.Totals.Stale,
		FailedCount:         report.Totals.Failed,
		UnsupportedCount:    report.Totals.Unsupported,
		PartialCount:        report.Totals.Partial,
		TopBlindSpots:       make([]agentplatform.AgentCoverageBlindSpot, 0, len(blindSpots)),
	}
	for _, record := range blindSpots {
		context.TopBlindSpots = append(context.TopBlindSpots, agentplatform.AgentCoverageBlindSpot{
			SourceID:      record.SourceID,
			DimensionID:   record.DimensionID,
			DimensionType: record.DimensionType,
			Title:         record.Title,
			State:         record.State,
			SupportLevel:  record.SupportLevel,
			RuntimeID:     record.RuntimeID,
			Family:        record.Family,
			Warning:       record.Warning,
			Notes:         append([]string(nil), record.Notes...),
		})
	}
	return context
}
