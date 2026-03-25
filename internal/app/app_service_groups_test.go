package app

import (
	"context"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/postgres"
	"github.com/writer/cerebro/internal/providers"
	"github.com/writer/cerebro/internal/scanner"
	"github.com/writer/cerebro/internal/scheduler"
)

type noopRetentionCleaner struct{}

func (noopRetentionCleaner) CleanupAuditLogs(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (noopRetentionCleaner) CleanupAgentData(context.Context, time.Time) (int64, int64, error) {
	return 0, 0, nil
}
func (noopRetentionCleaner) CleanupGraphData(context.Context, time.Time) (int64, int64, int64, error) {
	return 0, 0, 0, nil
}
func (noopRetentionCleaner) CleanupAccessReviewData(context.Context, time.Time) (int64, int64, error) {
	return 0, 0, nil
}

func TestAppServiceGroupAccessors(t *testing.T) {
	store := findings.NewStore()
	watermarks := scanner.NewWatermarkStore(nil)
	policyEngine := &policy.Engine{}
	providersRegistry := &providers.Registry{}
	schedulerSvc := &scheduler.Scheduler{}
	rbac := auth.NewRBAC()
	securityGraph := graph.New()
	findingsRepo := &postgres.FindingRepository{}
	riskEngineStateRepo := &postgres.RiskEngineStateRepository{}
	pgStore := &findings.PostgresStore{}
	retention := noopRetentionCleaner{}

	application := &App{
		Policy:              policyEngine,
		Findings:            store,
		ScanWatermarks:      watermarks,
		Providers:           providersRegistry,
		Scheduler:           schedulerSvc,
		RBAC:                rbac,
		SecurityGraph:       securityGraph,
		FindingsRepo:        findingsRepo,
		RiskEngineStateRepo: riskEngineStateRepo,
		PostgresFindings:    pgStore,
		RetentionRepo:       retention,
	}

	core := application.CoreServices()
	if core.Policy != policyEngine {
		t.Fatal("core services should expose policy engine")
	}
	if core.Findings != store {
		t.Fatal("core services should expose findings store")
	}
	if core.ScanWatermark != watermarks {
		t.Fatal("core services should expose scan watermark store")
	}

	feature := application.FeatureServices()
	if feature.Providers != providersRegistry {
		t.Fatal("feature services should expose providers registry")
	}
	if feature.Scheduler != schedulerSvc {
		t.Fatal("feature services should expose scheduler")
	}

	security := application.SecurityServices()
	if security.RBAC != rbac {
		t.Fatal("security services should expose RBAC")
	}
	if security.SecurityGraph != securityGraph {
		t.Fatal("security services should expose graph")
	}

	storage := application.StorageServices()
	if storage.FindingsRepo != findingsRepo {
		t.Fatal("storage services should expose findings repository")
	}
	if storage.RiskEngineStateRepo != riskEngineStateRepo {
		t.Fatal("storage services should expose risk engine state repository")
	}
	if storage.PostgresFindings != pgStore {
		t.Fatal("storage services should expose Postgres findings store")
	}
	if storage.RetentionRepo != retention {
		t.Fatal("storage services should expose retention cleaner")
	}
}
