package app

import (
	"context"
	"strings"
)

func (a *App) initLegacySnowflakeForAppState(ctx context.Context) error {
	if runtime := a.bootRuntime(); runtime != nil {
		return runtime.InitLegacySnowflakeForAppState(ctx)
	}
	return nil
}

func (a *App) requiresLegacySnowflakeSource(ctx context.Context) (bool, error) {
	migrationRequired, err := a.requiresLegacySnowflakeMigrationSource(ctx)
	if err != nil || migrationRequired {
		return migrationRequired, err
	}
	return a.requiresLegacySnowflakeRetentionSource(ctx)
}

func (a *App) requiresLegacySnowflakeMigrationSource(ctx context.Context) (bool, error) {
	if a == nil || a.appStateDB() == nil {
		return false, nil
	}
	completed, err := a.appStateMigrationComplete(ctx, legacySnowflakeAppStateMigrationName)
	if err != nil {
		return false, err
	}
	if completed || a.Snowflake != nil {
		return false, nil
	}
	started, err := a.appStateMigrationComplete(ctx, legacySnowflakeAppStateStartedName)
	if err != nil {
		return false, err
	}
	if started || hasSnowflakeCredentials(a.Config) {
		return true, nil
	}
	return a.hasExistingWarehouseTables(ctx)
}

func (a *App) requiresLegacySnowflakeRetentionSource(ctx context.Context) (bool, error) {
	if a == nil || a.appStateDB() == nil || a.Snowflake != nil || !legacySnowflakeRetentionEnabled(a.Config) {
		return false, nil
	}
	return a.appStateMigrationComplete(ctx, legacySnowflakeAppStateMigrationName)
}

func (a *App) hasExistingWarehouseTables(ctx context.Context) (bool, error) {
	if a == nil || a.Warehouse == nil {
		return false, nil
	}
	tables, err := a.Warehouse.ListAvailableTables(ctx)
	if err != nil {
		return false, err
	}
	for _, table := range tables {
		if !isAppStateWarehouseTable(table) {
			return true, nil
		}
	}
	return false, nil
}

func legacySnowflakeRetentionEnabled(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	return maxRetentionDays(cfg.GraphRetentionDays) > 0 || maxRetentionDays(cfg.AccessReviewRetentionDays) > 0
}

func maxRetentionDays(days int) int {
	if days < 0 {
		return 0
	}
	return days
}

func isAppStateWarehouseTable(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case
		"cerebro_findings",
		"cerebro_agent_sessions",
		"cerebro_audit_log",
		"cerebro_policy_history",
		"cerebro_risk_engine_state",
		"cerebro_app_state_migrations":
		return true
	default:
		return false
	}
}
