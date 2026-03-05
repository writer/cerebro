package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
)

func executeAzureSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	spec := parseScheduledSyncSpec(schedule.Table)
	subscriptionID := spec.AzureSubscription
	if subscriptionID == "" {
		subscriptionID = firstNonEmptyEnv("CEREBRO_AZURE_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID")
	}

	if subscriptionID != "" {
		Info("[%s] Executing Azure sync for subscription %s...", schedule.Name, subscriptionID)
	} else {
		Info("[%s] Executing Azure sync (auto-discovering subscription)...", schedule.Name)
	}
	if len(spec.TableFilter) > 0 {
		Info("[%s] Filtering Azure tables: %s", schedule.Name, strings.Join(spec.TableFilter, ", "))
	}

	opts := []nativesync.AzureEngineOption{}
	if subscriptionID != "" {
		opts = append(opts, nativesync.WithAzureSubscription(subscriptionID))
	}
	if len(spec.TableFilter) > 0 {
		opts = append(opts, nativesync.WithAzureTableFilter(spec.TableFilter))
	}

	syncer, err := nativesync.NewAzureSyncEngine(client, slog.Default(), opts...)
	if err != nil {
		return fmt.Errorf("create Azure sync engine: %w", err)
	}
	_, err = syncer.SyncAll(ctx)
	return err
}
