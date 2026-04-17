package app

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

func TestInitLegacySnowflakeForAppStateFailsWhenMigrationNeedsSource(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return nil, errors.New("boom")
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend:    "postgres",
			SnowflakeAccount:    "acct",
			SnowflakeUser:       "user",
			SnowflakePrivateKey: "key",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.setAppStateDB(db)

	err = a.initLegacySnowflakeForAppState(context.Background())
	if err == nil {
		t.Fatal("expected legacy snowflake initialization failure to be fatal when app-state migration depends on it")
		return
	}
	if !strings.Contains(err.Error(), "legacy snowflake initialization failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateWarnsWhenMigrationDoesNotNeedSource(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return nil, errors.New("boom")
	}

	a := &App{
		Config: &Config{
			WarehouseBackend:    "postgres",
			SnowflakeAccount:    "acct",
			SnowflakeUser:       "user",
			SnowflakePrivateKey: "key",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := a.initLegacySnowflakeForAppState(context.Background()); err != nil {
		t.Fatalf("expected legacy snowflake init failure to stay non-fatal when app-state migration does not depend on it, got %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateSkipsSourceAfterMigrationCompletes(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return nil, errors.New("boom")
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend:    "postgres",
			SnowflakeAccount:    "acct",
			SnowflakeUser:       "user",
			SnowflakePrivateKey: "key",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.setAppStateDB(db)
	if err := ensureAppStateMigrationStateSchema(context.Background(), db); err != nil {
		t.Fatalf("ensure app-state migration state schema: %v", err)
	}
	if err := a.markAppStateMigrationComplete(context.Background(), legacySnowflakeAppStateMigrationName); err != nil {
		t.Fatalf("markAppStateMigrationComplete() error = %v", err)
	}

	if err := a.initLegacySnowflakeForAppState(context.Background()); err != nil {
		t.Fatalf("expected legacy snowflake init failure to stay non-fatal after migration completion, got %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateAllowsFreshPostgresWithoutSnowflakeSource(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend: "postgres",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.setAppStateDB(db)

	if err := a.initLegacySnowflakeForAppState(context.Background()); err != nil {
		t.Fatalf("expected fresh postgres app-state startup without snowflake source to stay non-fatal, got %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateIgnoresAppStateTablesWhenCheckingWarehouseData(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend: "postgres",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{ListAvailableFunc: func(context.Context) ([]string, error) {
			return []string{"cerebro_findings", "cerebro_agent_sessions"}, nil
		}},
	}
	a.setAppStateDB(db)

	if err := a.initLegacySnowflakeForAppState(context.Background()); err != nil {
		t.Fatalf("expected app-state tables to be ignored when checking for warehouse data, got %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateFailsWhenWarehouseAlreadyHasDataWithoutSource(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend: "postgres",
		},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warehouse: &warehouse.MemoryWarehouse{ListAvailableFunc: func(context.Context) ([]string, error) { return []string{"aws_s3_buckets"}, nil }},
	}
	a.setAppStateDB(db)

	err = a.initLegacySnowflakeForAppState(context.Background())
	if err == nil {
		t.Fatal("expected startup to fail when warehouse data exists but the legacy migration source is unavailable")
		return
	}
	if !strings.Contains(err.Error(), "legacy snowflake source is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateFailsWhenMigrationPreviouslyStartedWithoutSource(t *testing.T) {
	originalNewSnowflakeClient := newSnowflakeClient
	originalPingSnowflake := pingSnowflake
	t.Cleanup(func() {
		newSnowflakeClient = originalNewSnowflakeClient
		pingSnowflake = originalPingSnowflake
	})

	newSnowflakeClient = func(snowflake.ClientConfig) (*snowflake.Client, error) {
		return nil, errors.New("boom")
	}

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend: "postgres",
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.setAppStateDB(db)
	if err := ensureAppStateMigrationStateSchema(context.Background(), db); err != nil {
		t.Fatalf("ensure app-state migration state schema: %v", err)
	}
	if err := a.markAppStateMigrationComplete(context.Background(), legacySnowflakeAppStateStartedName); err != nil {
		t.Fatalf("markAppStateMigrationComplete(started) error = %v", err)
	}

	err = a.initLegacySnowflakeForAppState(context.Background())
	if err == nil {
		t.Fatal("expected startup to fail when legacy app-state migration previously started but the source is unavailable")
		return
	}
	if !strings.Contains(err.Error(), "legacy snowflake source is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitLegacySnowflakeForAppStateRequiresLegacySourceForRetentionAfterMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	a := &App{
		Config: &Config{
			WarehouseBackend:          "postgres",
			GraphRetentionDays:        7,
			AccessReviewRetentionDays: 0,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a.setAppStateDB(db)

	ctx := context.Background()
	if err := a.markAppStateMigrationComplete(ctx, legacySnowflakeAppStateMigrationName); err != nil {
		t.Fatalf("mark migration complete: %v", err)
	}

	err = a.initLegacySnowflakeForAppState(ctx)
	if err == nil {
		t.Fatal("expected startup to fail while legacy retention still requires Snowflake")
		return
	}
	if !strings.Contains(err.Error(), "legacy snowflake source is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitPhase2bInitializesRemediationBeforeAgents(t *testing.T) {
	for i := 0; i < 100; i++ {
		a := &App{
			Config: &Config{},
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		a.initRuntime()

		if err := a.initPhase2b(context.Background()); err != nil {
			t.Fatalf("initPhase2b() error = %v", err)
		}
		if a.RemediationExecutor == nil {
			t.Fatal("expected remediation executor to be initialized")
		}
		if a.Agents == nil {
			t.Fatal("expected agents to be initialized")
		}
	}
}
