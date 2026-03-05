package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	nativesync "github.com/writer/cerebro/internal/sync"
)

func runK8sSync(ctx context.Context, start time.Time) error {
	Info("Starting Kubernetes sync...")
	tableFilter := parseTableFilter(syncTable)
	if len(tableFilter) > 0 {
		Info("Filtering Kubernetes tables: %s", strings.Join(tableFilter, ", "))
	}

	client, err := createSnowflakeClient()
	if err != nil {
		return fmt.Errorf("create snowflake client: %w", err)
	}
	defer func() { _ = client.Close() }()

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

	syncer := nativesync.NewK8sSyncEngine(client, slog.Default(), opts...)
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
