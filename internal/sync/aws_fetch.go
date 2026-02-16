package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func (e *SyncEngine) fetchWithRetry(ctx context.Context, table TableSpec, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	logFields := []any{"table", table.Name, "region", region}
	return retryFetch(
		ctx,
		e.rateLimiter,
		e.retryOptions,
		e.logger,
		"retrying aws fetch",
		logFields,
		classifyAWSError,
		awsRetryDelayForClass,
		func() ([]map[string]interface{}, error) {
			return table.Fetch(ctx, cfg, region)
		},
	)
}
