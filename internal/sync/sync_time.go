package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

func (e *SyncEngine) latestTableSyncTime(ctx context.Context, table string, region string, hasRegion bool) (time.Time, error) {
	if err := snowflake.ValidateTableName(table); err != nil {
		return time.Time{}, err
	}

	query := fmt.Sprintf("SELECT MAX(_CQ_SYNC_TIME) AS SYNC_TIME FROM %s", table)
	args := []interface{}{}
	if hasRegion {
		query += " WHERE REGION = ?"
		args = append(args, region)
	}

	result, err := e.sf.Query(ctx, query, args...)
	if err != nil {
		return time.Time{}, err
	}
	if len(result.Rows) == 0 {
		return time.Time{}, nil
	}

	syncValue := result.Rows[0]["SYNC_TIME"]
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
