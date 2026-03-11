package sync

import (
	"context"

	"github.com/evalops/cerebro/internal/snowflake/tableops"
	"github.com/evalops/cerebro/internal/warehouse"
)

const insertBatchSize = tableops.DefaultInsertBatchSize

func mergeRowsBatch(ctx context.Context, sf warehouse.SyncWarehouse, table string, rows []map[string]interface{}) error {
	return tableops.MergeVariantRowsBatch(ctx, sf, table, rows, nil, insertBatchSize)
}
