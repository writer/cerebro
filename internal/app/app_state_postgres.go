package app

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/agents"
	appsubstate "github.com/writer/cerebro/internal/app/appstate"
	staterepo "github.com/writer/cerebro/internal/appstate"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/snowflake"
)

const appStateRiskEngineGraphID = "security-graph"

func (a *App) appStateMigrationSnowflake() *snowflake.Client {
	if a == nil {
		return nil
	}
	if a.LegacySnowflake != nil {
		return a.LegacySnowflake
	}
	return a.Snowflake
}

func (a *App) appStateDatabaseURL() string {
	if a == nil || a.Config == nil {
		return ""
	}
	return appsubstate.DatabaseURL(a.Config.JobDatabaseURL, a.Config.WarehouseBackend, a.Config.WarehousePostgresDSN)
}

func (a *App) appStateRuntime() *appsubstate.Runtime {
	if a == nil {
		return nil
	}
	if a.AppState == nil {
		a.AppState = appsubstate.NewRuntime()
	}
	return a.AppState
}

func (a *App) appStateDB() *sql.DB {
	if a == nil || a.AppState == nil {
		return nil
	}
	return a.AppState.DB()
}

func (a *App) setAppStateDB(db *sql.DB) {
	if a == nil {
		return
	}
	a.appStateRuntime().SetDB(db)
}

func (a *App) initAppStateDB(ctx context.Context) error {
	dsn := a.appStateDatabaseURL()
	runtime := a.appStateRuntime()
	if runtime == nil {
		return fmt.Errorf("appstate runtime is nil")
	}
	if dsn == "" {
		return nil
	}
	return runtime.Init(ctx, dsn,
		func(ctx context.Context, db *sql.DB) error { return findings.NewPostgresStore(db).EnsureSchema(ctx) },
		func(ctx context.Context, db *sql.DB) error {
			return agents.NewPostgresSessionStore(db).EnsureSchema(ctx)
		},
		func(ctx context.Context, db *sql.DB) error { return staterepo.NewAuditRepository(db).EnsureSchema(ctx) },
		func(ctx context.Context, db *sql.DB) error {
			return staterepo.NewPolicyHistoryRepository(db).EnsureSchema(ctx)
		},
		func(ctx context.Context, db *sql.DB) error {
			return staterepo.NewRiskEngineStateRepository(db).EnsureSchema(ctx)
		},
	)
}

func (a *App) migrateAppState(ctx context.Context) error {
	if a == nil || a.appStateDB() == nil || a.appStateMigrationSnowflake() == nil {
		return nil
	}
	if err := a.migrateFindings(ctx); err != nil {
		return err
	}
	if err := a.migrateAgentSessions(ctx); err != nil {
		return err
	}
	if err := a.migrateAuditLogs(ctx); err != nil {
		return err
	}
	if err := a.migratePolicyHistory(ctx); err != nil {
		return err
	}
	if err := a.migrateRiskEngineState(ctx); err != nil {
		return err
	}
	return nil
}

func (a *App) migrateFindings(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	store, ok := a.Findings.(*findings.PostgresStore)
	if !ok || source == nil {
		return nil
	}
	records, err := snowflake.NewFindingRepository(source).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("migrate findings from snowflake: %w", err)
	}
	return store.ImportRecords(ctx, records)
}

func (a *App) migrateAgentSessions(ctx context.Context) error {
	sourceClient := a.appStateMigrationSnowflake()
	if a.appStateDB() == nil || sourceClient == nil {
		return nil
	}
	source, err := agents.NewSnowflakeSessionStore(sourceClient)
	if err != nil {
		return fmt.Errorf("initialize snowflake session store: %w", err)
	}
	sessions, err := source.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list snowflake agent sessions: %w", err)
	}
	destination := agents.NewPostgresSessionStore(a.appStateDB())
	if err := destination.ImportMissing(ctx, sessions); err != nil {
		return fmt.Errorf("persist postgres agent sessions: %w", err)
	}
	return nil
}

func (a *App) migrateAuditLogs(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	if a.AuditRepo == nil || source == nil {
		return nil
	}
	entries, err := snowflake.NewAuditRepository(source).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("list snowflake audit logs: %w", err)
	}
	for _, entry := range entries {
		if err := a.AuditRepo.Log(ctx, entry); err != nil {
			return fmt.Errorf("persist audit log %s: %w", entry.ID, err)
		}
	}
	return nil
}

func (a *App) migratePolicyHistory(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	if a.PolicyHistoryRepo == nil || source == nil {
		return nil
	}
	records, err := snowflake.NewPolicyHistoryRepository(source).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("list snowflake policy history: %w", err)
	}
	for _, record := range records {
		if err := a.PolicyHistoryRepo.Upsert(ctx, record); err != nil {
			return fmt.Errorf("persist policy history %s@%d: %w", record.PolicyID, record.Version, err)
		}
	}
	return nil
}

func (a *App) migrateRiskEngineState(ctx context.Context) error {
	source := a.appStateMigrationSnowflake()
	if a.RiskEngineStateRepo == nil || source == nil {
		return nil
	}
	existing, err := a.RiskEngineStateRepo.LoadSnapshot(ctx, appStateRiskEngineGraphID)
	if err != nil {
		return fmt.Errorf("load postgres risk engine state: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	payload, err := snowflake.NewRiskEngineStateRepository(source).LoadSnapshot(ctx, appStateRiskEngineGraphID)
	if err != nil {
		return fmt.Errorf("load snowflake risk engine state: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if err := a.RiskEngineStateRepo.SaveSnapshot(ctx, appStateRiskEngineGraphID, payload); err != nil {
		return fmt.Errorf("persist postgres risk engine state: %w", err)
	}
	return nil
}

func isMissingSnowflakeTableErr(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "does not exist") ||
		strings.Contains(message, "unknown table") ||
		strings.Contains(message, "not exist")
}
