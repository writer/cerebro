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
	explicitSubscriptions, managementGroupID, err := resolveAzureSyncScope()
	if err != nil {
		return err
	}
	switch {
	case managementGroupID != "":
		Info("Starting Azure sync for management group: %s", managementGroupID)
	case len(explicitSubscriptions) == 1:
		Info("Starting Azure sync for subscription: %s", explicitSubscriptions[0])
	case len(explicitSubscriptions) > 1:
		Info("Starting Azure sync for %d Azure subscriptions", len(explicitSubscriptions))
	default:
		Info("Starting Azure sync (auto-discovering all enabled subscriptions)...")
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
				Subscription:            strings.TrimSpace(syncAzureSubscription),
				Subscriptions:           explicitSubscriptions,
				ManagementGroup:         managementGroupID,
				Concurrency:             syncConcurrency,
				SubscriptionConcurrency: syncAzureSubConcurrency,
				Tables:                  tableFilter,
				Validate:                syncValidate,
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
	explicitSubscriptions, managementGroupID, err := resolveAzureSyncScope()
	if err != nil {
		return err
	}
	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

	opts := []nativesync.AzureEngineOption{}
	switch len(explicitSubscriptions) {
	case 1:
		opts = append(opts, nativesync.WithAzureSubscription(explicitSubscriptions[0]))
	case 0:
		// let the engine enumerate enabled subscriptions if no explicit scope is set
	default:
		opts = append(opts, nativesync.WithAzureSubscriptions(explicitSubscriptions))
	}
	if managementGroupID != "" {
		opts = append(opts, nativesync.WithAzureManagementGroup(managementGroupID))
	}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithAzureConcurrency(syncConcurrency))
	}
	if syncAzureSubConcurrency > 0 {
		opts = append(opts, nativesync.WithAzureSubscriptionConcurrency(syncAzureSubConcurrency))
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

func resolveAzureSyncScope() ([]string, string, error) {
	subscriptions := append(parseCommaSeparatedValues(syncAzureSubscriptions), strings.TrimSpace(syncAzureSubscription))
	subscriptions = uniqueNonEmpty(subscriptions)
	managementGroupID := strings.TrimSpace(syncAzureMgmtGroup)
	if managementGroupID != "" && len(subscriptions) > 0 {
		return nil, "", fmt.Errorf("--azure-management-group cannot be combined with --azure-subscription or --azure-subscriptions")
	}
	return subscriptions, managementGroupID, nil
}
