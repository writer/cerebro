package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/writer/cerebro/internal/snowflake"
	nativesync "github.com/writer/cerebro/internal/sync"
)

func executeAzureSync(ctx context.Context, client *snowflake.Client, schedule *SyncSchedule) error {
	client, closeClient, err := ensureSnowflakeClientForDirectScheduledSync(client, "azure")
	if err != nil {
		return err
	}
	defer closeClient()

	spec := parseScheduledSyncSpec(schedule.Table)
	subscriptions := uniqueNonEmpty(append(append([]string{}, spec.AzureSubscriptions...), spec.AzureSubscription))
	if len(subscriptions) == 0 {
		subscriptions = uniqueNonEmpty(parseCommaSeparatedValues(firstNonEmptyEnv("CEREBRO_AZURE_SUBSCRIPTIONS", "AZURE_SUBSCRIPTIONS")))
	}
	if len(subscriptions) == 0 {
		if subscriptionID := firstNonEmptyEnv("CEREBRO_AZURE_SUBSCRIPTION_ID", "AZURE_SUBSCRIPTION_ID"); subscriptionID != "" {
			subscriptions = []string{subscriptionID}
		}
	}
	managementGroupID := strings.TrimSpace(spec.AzureManagementGroup)
	if managementGroupID == "" {
		managementGroupID = firstNonEmptyEnv("CEREBRO_AZURE_MANAGEMENT_GROUP", "AZURE_MANAGEMENT_GROUP")
	}
	if managementGroupID != "" && len(subscriptions) > 0 {
		return fmt.Errorf("azure_management_group cannot be combined with subscription/subscriptions directives")
	}

	subscriptionConcurrency, err := parseAzureSubscriptionConcurrency(spec.AzureSubscriptionConcurrency)
	if err != nil {
		return err
	}

	switch {
	case managementGroupID != "":
		Info("[%s] Executing Azure sync for management group %s...", schedule.Name, managementGroupID)
	case len(subscriptions) == 1:
		Info("[%s] Executing Azure sync for subscription %s...", schedule.Name, subscriptions[0])
	case len(subscriptions) > 1:
		Info("[%s] Executing Azure sync for %d subscriptions...", schedule.Name, len(subscriptions))
	default:
		Info("[%s] Executing Azure sync (auto-discovering enabled subscriptions)...", schedule.Name)
	}
	if len(spec.TableFilter) > 0 {
		Info("[%s] Filtering Azure tables: %s", schedule.Name, strings.Join(spec.TableFilter, ", "))
	}

	opts := []nativesync.AzureEngineOption{}
	switch len(subscriptions) {
	case 1:
		opts = append(opts, nativesync.WithAzureSubscription(subscriptions[0]))
	case 0:
		// allow tenant-wide discovery
	default:
		opts = append(opts, nativesync.WithAzureSubscriptions(subscriptions))
	}
	if managementGroupID != "" {
		opts = append(opts, nativesync.WithAzureManagementGroup(managementGroupID))
	}
	if subscriptionConcurrency > 0 {
		opts = append(opts, nativesync.WithAzureSubscriptionConcurrency(subscriptionConcurrency))
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

func parseAzureSubscriptionConcurrency(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("azure_subscription_concurrency must be an integer: %w", err)
	}
	if value < 1 || value > 256 {
		return 0, fmt.Errorf("azure_subscription_concurrency must be between 1 and 256")
	}
	return value, nil
}
