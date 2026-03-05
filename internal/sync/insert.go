package sync

import (
	"context"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/snowflake/tableops"
)

const insertBatchSize = tableops.DefaultInsertBatchSize

func insertRowsBatch(ctx context.Context, sf *snowflake.Client, table string, rows []map[string]interface{}) error {
	return tableops.InsertVariantRowsBatch(ctx, sf, table, rows, nil, insertBatchSize)
}
