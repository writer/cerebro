package app

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/cerebro/internal/agents"
	"github.com/writer/cerebro/internal/appstate"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/snowflake"
)

const appStateRiskEngineGraphID = "security-graph"

func (a *App) appStateDatabaseURL() string {
	if a == nil || a.Config == nil {
		return ""
	}
	if dsn := strings.TrimSpace(a.Config.JobDatabaseURL); dsn != "" {
		return dsn
	}
	if strings.EqualFold(strings.TrimSpace(a.Config.WarehouseBackend), "postgres") {
		return strings.TrimSpace(a.Config.WarehousePostgresDSN)
	}
	return ""
}

func (a *App) initAppStateDB(ctx context.Context) error {
	dsn := a.appStateDatabaseURL()
	if dsn == "" {
		return nil
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open app-state database: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return fmt.Errorf("ping app-state database: %w", err)
	}

	ensure := []func(context.Context) error{
		findings.NewPostgresStore(db).EnsureSchema,
		agents.NewPostgresSessionStore(db).EnsureSchema,
		appstate.NewAuditRepository(db).EnsureSchema,
		appstate.NewPolicyHistoryRepository(db).EnsureSchema,
		appstate.NewRiskEngineStateRepository(db).EnsureSchema,
	}
	for _, ensureFn := range ensure {
		if err := ensureFn(ctx); err != nil {
			_ = db.Close()
			return err
		}
	}

	a.appStateDB = db
	return nil
}

func (a *App) migrateAppState(ctx context.Context) error {
	if a == nil || a.appStateDB == nil || a.Snowflake == nil {
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
	store, ok := a.Findings.(*findings.PostgresStore)
	if !ok || a.Snowflake == nil {
		return nil
	}
	records, err := snowflake.NewFindingRepository(a.Snowflake).ListAll(ctx)
	if err != nil {
		if isMissingSnowflakeTableErr(err) {
			return nil
		}
		return fmt.Errorf("migrate findings from snowflake: %w", err)
	}
	return store.ImportRecords(ctx, records)
}

func (a *App) migrateAgentSessions(ctx context.Context) error {
	if a.appStateDB == nil || a.Snowflake == nil {
		return nil
	}
	source, err := agents.NewSnowflakeSessionStore(a.Snowflake)
	if err != nil {
		return fmt.Errorf("initialize snowflake session store: %w", err)
	}
	sessions, err := source.ListAll(ctx)
	if err != nil {
		return fmt.Errorf("list snowflake agent sessions: %w", err)
	}
	destination := agents.NewPostgresSessionStore(a.appStateDB)
	for _, session := range sessions {
		if err := destination.Save(ctx, session); err != nil {
			return fmt.Errorf("persist postgres agent session %s: %w", session.ID, err)
		}
	}
	return nil
}

func (a *App) migrateAuditLogs(ctx context.Context) error {
	if a.AuditRepo == nil || a.Snowflake == nil {
		return nil
	}
	entries, err := snowflake.NewAuditRepository(a.Snowflake).ListAll(ctx)
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
	if a.PolicyHistoryRepo == nil || a.Snowflake == nil {
		return nil
	}
	records, err := snowflake.NewPolicyHistoryRepository(a.Snowflake).ListAll(ctx)
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
	if a.RiskEngineStateRepo == nil || a.Snowflake == nil {
		return nil
	}
	existing, err := a.RiskEngineStateRepo.LoadSnapshot(ctx, appStateRiskEngineGraphID)
	if err != nil {
		return fmt.Errorf("load postgres risk engine state: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	payload, err := snowflake.NewRiskEngineStateRepository(a.Snowflake).LoadSnapshot(ctx, appStateRiskEngineGraphID)
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
