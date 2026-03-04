package sync

import (
	"context"

	"github.com/writerinternal/cerebro/internal/snowflake"
	"github.com/writerinternal/cerebro/internal/snowflake/tableops"
)

const insertBatchSize = tableops.DefaultInsertBatchSize

func insertRowsBatch(ctx context.Context, sf *snowflake.Client, table string, rows []map[string]interface{}) error {
	return tableops.InsertVariantRowsBatch(ctx, sf, table, rows, nil, insertBatchSize)
}
