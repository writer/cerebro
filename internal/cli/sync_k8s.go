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

func runK8sSync(ctx context.Context, start time.Time) error {
	Info("Starting Kubernetes sync...")
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering Kubernetes tables: %s", strings.Join(tableFilter, ", "))
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
			resp, err := apiClient.RunK8sSync(ctx, apiclient.K8sSyncRequest{
				Kubeconfig:  syncK8sKubeconfig,
				Context:     syncK8sContext,
				Namespace:   syncK8sNamespace,
				Concurrency: syncConcurrency,
				Tables:      tableFilter,
				Validate:    syncValidate,
			})
			if err == nil {
				provider := "Kubernetes"
				if syncValidate || (resp != nil && resp.Validate) {
					provider = "Kubernetes (validate)"
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
				return fmt.Errorf("kubernetes sync via api failed: %w", err)
			}
			Warning("API unavailable; using direct mode: %v", err)
		}
	}

	return runK8sSyncDirectFn(ctx, start, tableFilter)
}

var runK8sSyncDirectFn = runK8sSyncDirect

func runK8sSyncDirect(ctx context.Context, start time.Time, tableFilter []string) error {
	store, err := openSyncWarehouseFn(ctx)
	if err != nil {
		return fmt.Errorf("open warehouse: %w", err)
	}
	defer func() { _ = closeSyncWarehouse(store) }()

	opts := []nativesync.K8sEngineOption{}
	if syncK8sKubeconfig != "" {
		opts = append(opts, nativesync.WithK8sKubeconfig(syncK8sKubeconfig))
	}
	if syncK8sContext != "" {
		opts = append(opts, nativesync.WithK8sContext(syncK8sContext))
	}
	if syncK8sNamespace != "" {
		opts = append(opts, nativesync.WithK8sNamespace(syncK8sNamespace))
	}
	if syncConcurrency > 0 {
		opts = append(opts, nativesync.WithK8sConcurrency(syncConcurrency))
	}
	if len(tableFilter) > 0 {
		opts = append(opts, nativesync.WithK8sTableFilter(tableFilter))
	}

	syncer := nativesync.NewK8sSyncEngine(store, slog.Default(), opts...)
	if syncValidate {
		results, err := syncer.ValidateTables(ctx)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		return printSyncResults(results, start, "Kubernetes (validate)")
	}

	results, err := syncer.SyncAll(ctx)
	if err := handleSyncRunResults(results, start, "Kubernetes", err); err != nil {
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
