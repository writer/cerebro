package sync

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/writer/cerebro/internal/warehouse"
)

const (
	permissionUsageStateTable  = "cerebro_permission_usage_state"
	permissionUsageStateSchema = `
		CREATE TABLE IF NOT EXISTS cerebro_permission_usage_state (
			state_key VARCHAR PRIMARY KEY,
			last_cursor_time TIMESTAMP_NTZ,
			last_cursor_id VARCHAR,
			updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
		)
	`
	permissionUsageCursorOverlap = 5 * time.Minute
)

type permissionUsageCursor struct {
	Time time.Time
	ID   string
}

func (e *SyncEngine) loadPermissionUsageCursor(ctx context.Context, key string) (permissionUsageCursor, error) {
	return loadPermissionUsageCursor(ctx, e.sf, key)
}

func (e *SyncEngine) savePermissionUsageCursor(ctx context.Context, key string, cursor permissionUsageCursor) error {
	return savePermissionUsageCursor(ctx, e.sf, key, cursor)
}

func (e *GCPSyncEngine) loadPermissionUsageCursor(ctx context.Context, key string) (permissionUsageCursor, error) {
	return loadPermissionUsageCursor(ctx, e.sf, key)
}

func (e *GCPSyncEngine) savePermissionUsageCursor(ctx context.Context, key string, cursor permissionUsageCursor) error {
	return savePermissionUsageCursor(ctx, e.sf, key, cursor)
}

func loadPermissionUsageCursor(ctx context.Context, sf warehouse.SyncWarehouse, key string) (permissionUsageCursor, error) {
	if sf == nil || sf.DB() == nil || key == "" {
		return permissionUsageCursor{}, nil
	}
	if err := ensurePermissionUsageStateTable(ctx, sf); err != nil {
		return permissionUsageCursor{}, err
	}

	row := sf.DB().QueryRowContext(ctx,
		"SELECT last_cursor_time, last_cursor_id FROM "+permissionUsageStateTable+" WHERE state_key = ?",
		key,
	)

	var t sql.NullTime
	var id sql.NullString
	if err := row.Scan(&t, &id); err != nil {
		if err == sql.ErrNoRows {
			return permissionUsageCursor{}, nil
		}
		return permissionUsageCursor{}, fmt.Errorf("read permission usage cursor %q: %w", key, err)
	}

	cursor := permissionUsageCursor{}
	if t.Valid {
		cursor.Time = t.Time.UTC()
	}
	if id.Valid {
		cursor.ID = id.String
	}
	return cursor, nil
}

func savePermissionUsageCursor(ctx context.Context, sf warehouse.SyncWarehouse, key string, cursor permissionUsageCursor) error {
	if sf == nil || sf.DB() == nil || key == "" || cursor.Time.IsZero() {
		return nil
	}
	if err := ensurePermissionUsageStateTable(ctx, sf); err != nil {
		return err
	}

	_, err := sf.DB().ExecContext(ctx, `
		MERGE INTO `+permissionUsageStateTable+` t
		USING (SELECT ? AS state_key, ? AS last_cursor_time, ? AS last_cursor_id) s
		ON t.state_key = s.state_key
		WHEN MATCHED THEN UPDATE SET
			last_cursor_time = CASE
				WHEN t.last_cursor_time IS NULL THEN s.last_cursor_time
				WHEN s.last_cursor_time > t.last_cursor_time THEN s.last_cursor_time
				ELSE t.last_cursor_time
			END,
			last_cursor_id = CASE
				WHEN t.last_cursor_time IS NULL THEN s.last_cursor_id
				WHEN s.last_cursor_time > t.last_cursor_time THEN s.last_cursor_id
				WHEN s.last_cursor_time = t.last_cursor_time AND COALESCE(s.last_cursor_id, '') > COALESCE(t.last_cursor_id, '') THEN s.last_cursor_id
				ELSE t.last_cursor_id
			END,
			updated_at = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (state_key, last_cursor_time, last_cursor_id, updated_at)
		VALUES (s.state_key, s.last_cursor_time, s.last_cursor_id, CURRENT_TIMESTAMP())
	`, key, cursor.Time.UTC(), cursor.ID)
	if err != nil {
		return fmt.Errorf("upsert permission usage cursor %q: %w", key, err)
	}
	return nil
}

func ensurePermissionUsageStateTable(ctx context.Context, sf warehouse.SyncWarehouse) error {
	if sf == nil || sf.DB() == nil {
		return nil
	}
	if _, err := sf.DB().ExecContext(ctx, permissionUsageStateSchema); err != nil {
		return fmt.Errorf("ensure permission usage state table: %w", err)
	}
	if _, err := sf.DB().ExecContext(ctx, `ALTER TABLE `+permissionUsageStateTable+` ADD COLUMN IF NOT EXISTS last_cursor_id VARCHAR`); err != nil {
		return fmt.Errorf("ensure permission usage state cursor id column: %w", err)
	}
	return nil
}

func permissionUsageWindowStart(now time.Time, lookbackDays int, cursor permissionUsageCursor) time.Time {
	if lookbackDays <= 0 {
		lookbackDays = defaultPermissionUsageLookbackDays
	}
	lookbackStart := now.UTC().Add(-time.Duration(lookbackDays) * 24 * time.Hour)
	if cursor.Time.IsZero() {
		return lookbackStart
	}
	if cursor.Time.Before(lookbackStart) {
		return lookbackStart
	}
	start := cursor.Time.Add(-permissionUsageCursorOverlap)
	if start.Before(lookbackStart) {
		return lookbackStart
	}
	return start
}

func cursorAfter(current, candidate permissionUsageCursor) permissionUsageCursor {
	if candidate.Time.IsZero() {
		return current
	}
	if current.Time.IsZero() {
		return candidate
	}
	if candidate.Time.After(current.Time) {
		return candidate
	}
	if candidate.Time.Equal(current.Time) && candidate.ID > current.ID {
		return candidate
	}
	return current
}
