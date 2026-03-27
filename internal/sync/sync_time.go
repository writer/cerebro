package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/snowflake"
	"github.com/writer/cerebro/internal/warehouse"
)

var queryLatestTableSyncTime = func(ctx context.Context, sf warehouse.SyncWarehouse, table string, region string, hasRegion bool) (time.Time, error) {
	query := fmt.Sprintf("SELECT MAX(_CQ_SYNC_TIME) AS SYNC_TIME FROM %s", table)
	args := []interface{}{}
	if hasRegion {
		query += " WHERE REGION = " + warehouse.Placeholder(sf, 1)
		args = append(args, region)
	}

	result, err := sf.Query(ctx, query, args...)
	if err != nil {
		return time.Time{}, err
	}
	if len(result.Rows) == 0 {
		return time.Time{}, nil
	}

	syncValue := queryRow(result.Rows[0], "sync_time")
	if syncValue == nil {
		return time.Time{}, nil
	}

	switch value := syncValue.(type) {
	case time.Time:
		return value, nil
	case *time.Time:
		if value == nil {
			return time.Time{}, nil
		}
		return *value, nil
	case string:
		if value == "" {
			return time.Time{}, nil
		}

		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			parsed, err = time.Parse(time.RFC3339, value)
		}
		if err != nil {
			return time.Time{}, err
		}
		return parsed, nil
	default:
		return time.Time{}, nil
	}
}

type forceFullBackfillContextKey struct{}

func withForceFullBackfill(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, forceFullBackfillContextKey{}, true)
}

func shouldForceFullBackfill(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	value, ok := ctx.Value(forceFullBackfillContextKey{}).(bool)
	return ok && value
}

func (e *SyncEngine) latestTableSyncTime(ctx context.Context, table string, region string, hasRegion bool) (time.Time, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return time.Time{}, err
	}

	return queryLatestTableSyncTime(ctx, e.sf, table, region, hasRegion)
}

func (e *SyncEngine) incrementalStartTime(ctx context.Context, table string, region string, hasRegion bool, lookback time.Duration) (time.Time, bool) {
	if shouldForceFullBackfill(ctx) {
		return time.Time{}, false
	}

	lastSync, err := e.latestTableSyncTime(ctx, table, region, hasRegion)
	if err != nil {
		e.logger.Debug("failed to load incremental sync watermark", "table", table, "region", region, "error", err)
		return time.Time{}, false
	}
	return deriveIncrementalStart(lastSync, lookback)
}

func deriveIncrementalStart(lastSync time.Time, lookback time.Duration) (time.Time, bool) {
	if lastSync.IsZero() {
		return time.Time{}, false
	}
	start := lastSync.UTC()
	if lookback > 0 {
		start = start.Add(-lookback)
	}
	return start, true
}
