package app

import (
	"context"
	"time"

	appscan "github.com/writer/cerebro/internal/app/scan"
	"github.com/writer/cerebro/internal/graph"
)

type ScanTuning = appscan.Tuning

type scheduledGraphAnalysisSummary struct {
	graphToxicCount         int
	graphPaths              int
	orgTopologyFindingCount int
	orgTopologyErrorCount   int
	apiSurfaceFindingCount  int
	apiSurfaceErrorCount    int
}

func (a *App) ScanTuning() ScanTuning {
	if runtime := a.scanRuntime(); runtime != nil {
		return runtime.ScanTuning()
	}
	return ScanTuning{}
}

func (a *App) ScanColumnsForTable(ctx context.Context, table string) []string {
	if runtime := a.scanRuntime(); runtime != nil {
		return runtime.ScanColumnsForTable(ctx, table)
	}
	return nil
}

func (a *App) initScheduler(ctx context.Context) {
	if runtime := a.scanRuntime(); runtime != nil {
		runtime.InitScheduler(ctx)
	}
}

func (a *App) runRetentionCleanup(ctx context.Context) error {
	if runtime := a.scanRuntime(); runtime != nil {
		return runtime.RunRetentionCleanup(ctx)
	}
	return nil
}

func (a *App) currentOrStoredScheduledScanGraphView(ctx context.Context, tuning ScanTuning) *graph.Graph {
	if runtime := a.scanRuntime(); runtime != nil {
		return runtime.CurrentOrStoredScheduledScanGraphView(ctx, tuning)
	}
	return nil
}

func (a *App) runScheduledGraphAnalyses(ctx context.Context, tuning ScanTuning, sqlToxicRiskSets map[string][]map[string]bool) scheduledGraphAnalysisSummary {
	if runtime := a.scanRuntime(); runtime != nil {
		summary := runtime.RunScheduledGraphAnalyses(ctx, tuning, sqlToxicRiskSets)
		return scheduledGraphAnalysisSummary{
			graphToxicCount:         summary.GraphToxicCount,
			graphPaths:              summary.GraphPaths,
			orgTopologyFindingCount: summary.OrgTopologyFindingCount,
			orgTopologyErrorCount:   summary.OrgTopologyErrorCount,
			apiSurfaceFindingCount:  summary.APISurfaceFindingCount,
			apiSurfaceErrorCount:    summary.APISurfaceErrorCount,
		}
	}
	return scheduledGraphAnalysisSummary{}
}

func (a *App) sendSecurityDigest(ctx context.Context) error {
	if runtime := a.scanRuntime(); runtime != nil {
		return runtime.SendSecurityDigest(ctx)
	}
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	return appscan.ParseDuration(s)
}

func splitTables(s string) []string {
	return appscan.SplitTables(s)
}
