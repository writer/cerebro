package sync

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/warehouse"
)

const (
	permissionUsageStateTable    = "cerebro_permission_usage_state"
	permissionUsageCursorOverlap = 5 * time.Minute
)

type permissionUsageCursor struct {
	Time time.Time
	ID   string
}

type permissionUsageCurrentState struct {
	LastUsed    time.Time
	UnusedSince time.Time
	Status      string
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
	if sf == nil || key == "" {
		return permissionUsageCursor{}, nil
	}
	if err := ensurePermissionUsageStateTable(ctx, sf); err != nil {
		return permissionUsageCursor{}, err
	}

	result, err := sf.Query(ctx,
		"SELECT last_cursor_time, last_cursor_id FROM "+permissionUsageStateTable+" WHERE state_key = "+warehouse.Placeholder(sf, 1),
		key,
	)
	if err != nil {
		return permissionUsageCursor{}, fmt.Errorf("read permission usage cursor %q: %w", key, err)
	}
	if len(result.Rows) == 0 {
		return permissionUsageCursor{}, nil
	}

	cursor := permissionUsageCursor{}
	if ts, ok := parseAnyTime(queryRow(result.Rows[0], "last_cursor_time")); ok {
		cursor.Time = ts.UTC()
	}
	cursor.ID = strings.TrimSpace(queryRowString(result.Rows[0], "last_cursor_id"))
	return cursor, nil
}

func savePermissionUsageCursor(ctx context.Context, sf warehouse.SyncWarehouse, key string, cursor permissionUsageCursor) error {
	if sf == nil || key == "" || cursor.Time.IsZero() {
		return nil
	}
	if err := ensurePermissionUsageStateTable(ctx, sf); err != nil {
		return err
	}

	var (
		query string
		args  []interface{}
	)
	if warehouse.Dialect(sf) == warehouse.SQLDialectSnowflake {
		query = `
			MERGE INTO ` + permissionUsageStateTable + ` t
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
		`
		args = []interface{}{key, cursor.Time.UTC(), cursor.ID}
	} else {
		query = fmt.Sprintf(`
			INSERT INTO %[1]s (state_key, last_cursor_time, last_cursor_id, updated_at)
			VALUES (%[2]s)
			ON CONFLICT (state_key) DO UPDATE SET
				last_cursor_time = CASE
					WHEN %[1]s.last_cursor_time IS NULL THEN EXCLUDED.last_cursor_time
					WHEN EXCLUDED.last_cursor_time > %[1]s.last_cursor_time THEN EXCLUDED.last_cursor_time
					ELSE %[1]s.last_cursor_time
				END,
				last_cursor_id = CASE
					WHEN %[1]s.last_cursor_time IS NULL THEN EXCLUDED.last_cursor_id
					WHEN EXCLUDED.last_cursor_time > %[1]s.last_cursor_time THEN EXCLUDED.last_cursor_id
					WHEN EXCLUDED.last_cursor_time = %[1]s.last_cursor_time AND COALESCE(EXCLUDED.last_cursor_id, '') > COALESCE(%[1]s.last_cursor_id, '') THEN EXCLUDED.last_cursor_id
					ELSE %[1]s.last_cursor_id
				END,
				updated_at = CURRENT_TIMESTAMP()
		`, permissionUsageStateTable, strings.Join(warehouse.Placeholders(sf, 1, 4), ", "))
		args = []interface{}{key, cursor.Time.UTC(), cursor.ID, time.Now().UTC()}
	}

	_, err := sf.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("upsert permission usage cursor %q: %w", key, err)
	}
	return nil
}

func ensurePermissionUsageStateTable(ctx context.Context, sf warehouse.SyncWarehouse) error {
	if sf == nil {
		return nil
	}
	schemaSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			state_key VARCHAR PRIMARY KEY,
			last_cursor_time %s,
			last_cursor_id VARCHAR,
			updated_at %s DEFAULT CURRENT_TIMESTAMP()
		)
	`, permissionUsageStateTable, warehouse.LocalTimestampColumnType(sf), warehouse.LocalTimestampColumnType(sf))
	if _, err := sf.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("ensure permission usage state table: %w", err)
	}
	if _, err := sf.Exec(ctx, `ALTER TABLE `+permissionUsageStateTable+` ADD COLUMN IF NOT EXISTS last_cursor_id VARCHAR`); err != nil {
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

func derivePermissionUsageCurrentState(observedAt, windowStart, lastUsed time.Time, previous permissionUsageCurrentState, status string) permissionUsageCurrentState {
	state := permissionUsageCurrentState{
		Status:   strings.ToLower(strings.TrimSpace(status)),
		LastUsed: lastUsed.UTC(),
	}

	switch state.Status {
	case "used":
		return state
	case "unused":
		if !lastUsed.IsZero() {
			state.UnusedSince = lastUsed.UTC()
			return state
		}
		if !previous.UnusedSince.IsZero() && strings.EqualFold(previous.Status, "unused") {
			state.UnusedSince = previous.UnusedSince.UTC()
			return state
		}
		if !windowStart.IsZero() {
			state.UnusedSince = windowStart.UTC()
			return state
		}
		if !observedAt.IsZero() {
			state.UnusedSince = observedAt.UTC()
		}
	}

	return state
}

func permissionUsageDaysUnused(observedAt time.Time, state permissionUsageCurrentState, fallback int) int {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	if !state.LastUsed.IsZero() {
		return max(0, int(observedAt.Sub(state.LastUsed.UTC()).Hours()/24))
	}
	if !state.UnusedSince.IsZero() {
		return max(0, int(observedAt.Sub(state.UnusedSince.UTC()).Hours()/24))
	}
	return fallback
}

func permissionUsageShouldRecommendRemoval(status string, daysUnused, threshold int, authoritative bool) bool {
	if !authoritative {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(status), "unused") {
		return false
	}
	if threshold <= 0 {
		threshold = defaultPermissionRemovalThresholdDays
	}
	return daysUnused >= threshold
}
