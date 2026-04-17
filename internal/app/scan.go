package app

import (
	"context"
	"log/slog"
	"time"

	appscan "github.com/writer/cerebro/internal/app/scan"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/graph/builders"
	"github.com/writer/cerebro/internal/notifications"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
	"github.com/writer/cerebro/internal/warehouse"
	"github.com/writer/cerebro/internal/webhooks"
)

func (a *App) ScanRuntime() *appscan.Runtime {
	return a.scanRuntime()
}

func (a *App) scanRuntime() *appscan.Runtime {
	if a == nil {
		return nil
	}
	if a.Scan == nil {
		a.Scan = a.newScanRuntime()
	}
	return a.Scan
}

func (a *App) newScanRuntime() *appscan.Runtime {
	if a == nil {
		return nil
	}
	return appscan.NewRuntime(appscan.Dependencies{
		Logger: func() *slog.Logger {
			if a == nil {
				return nil
			}
			return a.Logger
		},
		Config: func() *appscan.Config {
			return a.scanConfig()
		},
		SchedulerGetter: func() *scheduler.Scheduler {
			if a == nil {
				return nil
			}
			return a.Scheduler
		},
		SchedulerSetter: func(s *scheduler.Scheduler) {
			if a != nil {
				a.Scheduler = s
			}
		},
		Warehouse: func() warehouse.DataWarehouse {
			if a == nil {
				return nil
			}
			return a.Warehouse
		},
		Policy: func() *policy.Engine {
			if a == nil {
				return nil
			}
			return a.Policy
		},
		Findings: func() findings.FindingStore {
			if a == nil {
				return nil
			}
			return a.Findings
		},
		Scanner: func() *scanner.Scanner {
			if a == nil {
				return nil
			}
			return a.Scanner
		},
		Notifications: func() *notifications.Manager {
			if a == nil {
				return nil
			}
			return a.Notifications
		},
		Webhooks: func() *webhooks.Service {
			if a == nil {
				return nil
			}
			return a.Webhooks
		},
		SecurityGraphBuilder: func() *builders.Builder {
			if a == nil {
				return nil
			}
			return a.SecurityGraphBuilder
		},
		RetentionRepo: func() appscan.RetentionCleaner {
			if a == nil {
				return nil
			}
			return a.RetentionRepo
		},
		ScanWatermarks: func() *scanner.WatermarkStore {
			if a == nil {
				return nil
			}
			return a.ScanWatermarks
		},
		AvailableTables: func() []string {
			if a == nil || len(a.AvailableTables) == 0 {
				return nil
			}
			return append([]string(nil), a.AvailableTables...)
		},
		SetAvailableTables: func(tables []string) {
			if a == nil {
				return
			}
			a.AvailableTables = append([]string(nil), tables...)
		},
		GraphRebuildInterval: a.scanGraphRebuildInterval,
		CurrentLiveSecurityGraph: func() *graph.Graph {
			if a == nil {
				return nil
			}
			return a.currentLiveSecurityGraph()
		},
		WaitForGraph:                     a.WaitForGraph,
		CurrentOrStoredSecurityGraphView: a.currentOrStoredSecurityGraphView,
		ApplySecurityGraphChanges:        a.ApplySecurityGraphChanges,
		UpsertFindingAndRemediate:        a.upsertFindingAndRemediate,
		ScanAndPersistDSPMFindings:       a.scanAndPersistDSPMFindings,
		ScanQueryPolicies: func(ctx context.Context) appscan.QueryPolicyScanResult {
			result := a.ScanQueryPolicies(ctx)
			return appscan.QueryPolicyScanResult{
				Policies: result.Policies,
				Findings: append([]policy.Finding(nil), result.Findings...),
				Errors:   append([]string(nil), result.Errors...),
			}
		},
		ScanOrgTopologyPolicies: func(ctx context.Context) appscan.OrgTopologyPolicyScanResult {
			result := a.ScanOrgTopologyPolicies(ctx)
			return appscan.OrgTopologyPolicyScanResult{
				Assets:   result.Assets,
				Findings: append([]policy.Finding(nil), result.Findings...),
				Errors:   append([]string(nil), result.Errors...),
			}
		},
		ScanAPISurfaceFindings: func(ctx context.Context) appscan.APISurfaceFindingScanResult {
			result := a.ScanAPISurfaceFindings(ctx)
			return appscan.APISurfaceFindingScanResult{
				Endpoints: result.Endpoints,
				Findings:  append([]policy.Finding(nil), result.Findings...),
				Errors:    append([]string(nil), result.Errors...),
			}
		},
	})
}

func (a *App) scanConfig() *appscan.Config {
	if a == nil || a.Config == nil {
		return nil
	}
	return &appscan.Config{
		ScanInterval:              a.Config.ScanInterval,
		ScanTables:                a.Config.ScanTables,
		SecurityDigestInterval:    a.Config.SecurityDigestInterval,
		RetentionJobInterval:      a.Config.RetentionJobInterval,
		AuditRetentionDays:        a.Config.AuditRetentionDays,
		SessionRetentionDays:      a.Config.SessionRetentionDays,
		GraphRetentionDays:        a.Config.GraphRetentionDays,
		AccessReviewRetentionDays: a.Config.AccessReviewRetentionDays,
		ScanTableTimeout:          a.Config.ScanTableTimeout,
		ScanMaxConcurrent:         a.Config.ScanMaxConcurrent,
		ScanMinConcurrent:         a.Config.ScanMinConcurrent,
		ScanAdaptiveConcurrency:   a.Config.ScanAdaptiveConcurrency,
		ScanRetryAttempts:         a.Config.ScanRetryAttempts,
		ScanRetryBackoff:          a.Config.ScanRetryBackoff,
		ScanRetryMaxBackoff:       a.Config.ScanRetryMaxBackoff,
	}
}

func (a *App) scanGraphRebuildInterval() time.Duration {
	interval := time.Hour
	if envInterval := getEnv("GRAPH_REBUILD_INTERVAL", ""); envInterval != "" {
		if parsed, err := time.ParseDuration(envInterval); err == nil {
			interval = parsed
		}
	}
	return interval
}
