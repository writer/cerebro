package sync

import (
	"context"

	"github.com/evalops/cerebro/internal/snowflake"
	"github.com/evalops/cerebro/internal/snowflake/tableops"
)

const insertBatchSize = tableops.DefaultInsertBatchSize

func mergeRowsBatch(ctx context.Context, sf *snowflake.Client, table string, rows []map[string]interface{}) error {
	return tableops.MergeVariantRowsBatch(ctx, sf, table, rows, nil, insertBatchSize)
}
