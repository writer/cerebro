package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	apiclient "github.com/writer/cerebro/internal/client"
	nativesync "github.com/writer/cerebro/internal/sync"
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

	mode, err := loadCLIExecutionMode()
	if err != nil {
		return err
	}

	if mode != cliExecutionModeDirect {
		apiClient, err := newCLIAPIClient()
		if err != nil {
			if mode == cliExecutionModeAPI {
				return err
			}
			Warning("API client configuration invalid; using direct mode: %v", err)
		} else {
			resp, err := apiClient.RunAzureSync(ctx, apiclient.AzureSyncRequest{
				Subscription: syncAzureSubscription,
				Concurrency:  syncConcurrency,
				Tables:       tableFilter,
				Validate:     syncValidate,
			})
			if err == nil {
				provider := "Azure"
				if syncValidate || (resp != nil && resp.Validate) {
					provider = "Azure (validate)"
				}
				var results []nativesync.SyncResult
				if resp != nil {
					results = resp.Results
				}
				if err := printSyncResults(results, start, provider); err != nil {
					return err
				}
				if syncScanAfter && !syncValidate {
					Info("Triggering policy scan...")
					if err := runPostSyncScan(ctx, tableFilter); err != nil {
						Warning("Post-sync scan failed: %v", err)
					}
				}
				return nil
			}
			if mode == cliExecutionModeAPI || !shouldFallbackToDirect(mode, err) {
				return fmt.Errorf("azure sync via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runAzureSyncDirectFn(ctx, start, tableFilter)
}

var runAzureSyncDirectFn = runAzureSyncDirect

func runAzureSyncDirect(ctx context.Context, start time.Time, tableFilter []string) error {
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
