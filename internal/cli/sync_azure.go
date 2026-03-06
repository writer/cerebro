package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	nativesync "github.com/evalops/cerebro/internal/sync"
)

func runAzureSync(ctx context.Context, start time.Time) error {
	if syncAzureSubscription != "" {
		Info("Starting Azure sync for subscription: %s", syncAzureSubscription)
	} else {
		Info("Starting Azure sync (auto-discovering subscriptions)...")
	}
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering Azure tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	opts := []nativesync.AzureEngineOption{}
	if syncAzureSubscription != "" {
		opts = append(opts, nativesync.WithAzureSubscription(syncAzureSubscription))
	}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithAzureConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(tableFilter))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return fmt.Errorf("create azure sync engine: %w", err)
	}

	if syncValidate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "Azure (validate)")
	}

	results, err := syncer.SyncAll(ctx)
	if err := handleSyncRunResults(results, start, "Azure", err); err != nil {
		return err
	}

	if syncScanAfter {
		Info("Triggering policy scan...")
		if err := runPostSyncScan(ctx, tableFilter); err != nil {
			Warning("Post-sync scan failed: %v", err)
		}
	}

	return nil
}
