package snowflake

import (
	"context"
	"fmt"
	"time"
)

// RetentionRepository deletes stale data from Snowflake app tables.
type RetentionRepository struct {
	client *Client
	schema string
}

func NewRetentionRepository(client *Client) *RetentionRepository {
	return &RetentionRepository{
		client: client,
		schema: fmt.Sprintf("%s.%s", client.Database(), client.AppSchema()),
	}
}

func (r *RetentionRepository) CleanupAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	return r.deleteBefore(ctx, "audit_log", "timestamp", olderThan)
}

func (r *RetentionRepository) CleanupAgentData(ctx context.Context, olderThan time.Time) (sessionsDeleted, messagesDeleted int64, err error) {
	messagesDeleted, err = r.deleteBefore(ctx, "agent_messages", "created_at", olderThan)
	if err != nil {
		return 0, 0, err
	}
	sessionsDeleted, err = r.deleteBefore(ctx, "agent_sessions", "updated_at", olderThan)
	if err != nil {
		return 0, 0, err
	}
	return sessionsDeleted, messagesDeleted, nil
}

func (r *RetentionRepository) CleanupGraphData(ctx context.Context, olderThan time.Time) (pathsDeleted, edgesDeleted, nodesDeleted int64, err error) {
	pathsDeleted, err = r.deleteBefore(ctx, "attack_paths", "analyzed_at", olderThan)
	if err != nil {
		return 0, 0, 0, err
	}
	edgesDeleted, err = r.deleteBefore(ctx, "attack_path_edges", "created_at", olderThan)
	if err != nil {
		return 0, 0, 0, err
	}
	nodesDeleted, err = r.deleteBefore(ctx, "attack_path_nodes", "updated_at", olderThan)
	if err != nil {
		return 0, 0, 0, err
	}
	return pathsDeleted, edgesDeleted, nodesDeleted, nil
}

func (r *RetentionRepository) CleanupAccessReviewData(ctx context.Context, olderThan time.Time) (reviewsDeleted, itemsDeleted int64, err error) {
	itemsDeleted, err = r.deleteBefore(ctx, "review_items", "created_at", olderThan)
	if err != nil {
		return 0, 0, err
	}
	reviewsDeleted, err = r.deleteBefore(ctx, "access_reviews", "created_at", olderThan)
	if err != nil {
		return 0, 0, err
	}
	return reviewsDeleted, itemsDeleted, nil
}

func (r *RetentionRepository) deleteBefore(ctx context.Context, table, timeColumn string, olderThan time.Time) (int64, error) {
	if r == nil || r.client == nil {
		return 0, fmt.Errorf("retention repository is not initialized")
	}
	if olderThan.IsZero() {
		return 0, fmt.Errorf("retention cutoff is required")
	}

	tableRef, err := SafeQualifiedTableRef(r.schema, table)
	if err != nil {
		return 0, fmt.Errorf("invalid table reference for %s: %w", table, err)
	}

	// #nosec G201 -- tableRef is validated via SafeQualifiedTableRef, timeColumn is constant.
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s < ?`, tableRef, timeColumn)
	result, err := r.client.db.ExecContext(ctx, query, olderThan.UTC())
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return affected, nil
}
