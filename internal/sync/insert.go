package sync

import (
	"context"

	"github.com/writer/cerebro/internal/snowflake/tableops"
	"github.com/writer/cerebro/internal/warehouse"
)

const insertBatchSize = tableops.DefaultInsertBatchSize

func mergeRowsBatch(ctx context.Context, sf warehouse.SyncWarehouse, table string, rows []map[string]interface{}) error {
	return tableops.MergeVariantRowsBatch(ctx, sf, table, rows, nil, insertBatchSize)
}
