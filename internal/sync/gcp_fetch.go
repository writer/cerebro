package sync

import "context"

func (e *GCPSyncEngine) fetchWithRetry(ctx context.Context, table GCPTableSpec) ([]map[string]interface{}, error) {
	logFields := []any{"table", table.Name, "project", e.projectID}
	return retryFetch(
		ctx,
		e.rateLimiter,
		e.retryOptions,
		e.logger,
		"retrying gcp fetch",
		logFields,
		classifyGCPError,
		nil,
		func() ([]map[string]interface{}, error) {
			return table.Fetch(ctx, e.projectID)
		},
	)
}
