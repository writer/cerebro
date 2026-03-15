package sync

import "context"

func (e *AzureSyncEngine) fetchWithRetry(ctx context.Context, table AzureTableSpec, subscriptionID string) ([]map[string]interface{}, error) {
	logFields := []any{"table", table.Name, "subscription", subscriptionID}
	return retryFetch(
		ctx,
		e.rateLimiter,
		e.retryOptions,
		e.logger,
		"retrying azure fetch",
		logFields,
		classifyAzureError,
		nil,
		func() ([]map[string]interface{}, error) {
			return table.Fetch(ctx, e.credential, subscriptionID)
		},
	)
}
