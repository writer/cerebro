package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/complianceremediation"
)

type complianceWorkItemCursor struct {
	UpdatedAt time.Time `json:"updated_at"`
	ID        string    `json:"id"`
}

// ListWorkItems exposes a bounded tenant-scoped page from the Postgres work
// projection. The cursor is opaque to callers and uses projection update time
// plus stable item identity for deterministic keyset pagination.
func (s *Store) ListWorkItems(ctx context.Context, tenantID string, filter complianceremediation.WorkItemListFilter) (complianceremediation.WorkItemPage, error) {
	if err := s.ensureComplianceReviewTables(ctx); err != nil {
		return complianceremediation.WorkItemPage{}, err
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return complianceremediation.WorkItemPage{}, fmt.Errorf("%w: tenant_id is required", complianceremediation.ErrInvalidRequest)
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 50
	}
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	if filter.State != "" {
		args = append(args, string(filter.State))
		where = append(where, fmt.Sprintf("body_json->>'state' = $%d", len(args)))
	}
	if ownerID := strings.TrimSpace(filter.OwnerID); ownerID != "" {
		args = append(args, ownerID)
		where = append(where, fmt.Sprintf("body_json->>'owner_id' = $%d", len(args)))
	}
	if cursorValue := strings.TrimSpace(filter.Cursor); cursorValue != "" {
		cursor, err := decodeComplianceWorkItemCursor(cursorValue)
		if err != nil {
			return complianceremediation.WorkItemPage{}, err
		}
		args = append(args, cursor.UpdatedAt.UTC(), cursor.ID)
		where = append(where, fmt.Sprintf("(updated_at < $%d OR (updated_at = $%d AND id > $%d))", len(args)-1, len(args)-1, len(args)))
	}
	args = append(args, int64(limit)+1)
	query := fmt.Sprintf(`
SELECT id, updated_at, body_json
FROM compliance_work_items
WHERE %s
ORDER BY updated_at DESC, id ASC
LIMIT $%d`, strings.Join(where, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return complianceremediation.WorkItemPage{}, fmt.Errorf("list compliance work items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type rowValue struct {
		id        string
		updatedAt time.Time
		item      complianceassessment.WorkItem
	}
	values := make([]rowValue, 0, limit+1)
	for rows.Next() {
		var value rowValue
		var body []byte
		if err := rows.Scan(&value.id, &value.updatedAt, &body); err != nil {
			return complianceremediation.WorkItemPage{}, fmt.Errorf("scan compliance work item: %w", err)
		}
		if err := json.Unmarshal(body, &value.item); err != nil {
			return complianceremediation.WorkItemPage{}, fmt.Errorf("decode compliance work item: %w", err)
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return complianceremediation.WorkItemPage{}, fmt.Errorf("iterate compliance work items: %w", err)
	}
	page := complianceremediation.WorkItemPage{Items: make([]complianceassessment.WorkItem, 0, min(len(values), int(limit)))}
	for index, value := range values {
		if index >= int(limit) {
			break
		}
		page.Items = append(page.Items, value.item)
	}
	if len(values) > int(limit) && len(page.Items) != 0 {
		last := values[int(limit)-1]
		page.NextCursor, err = encodeComplianceWorkItemCursor(complianceWorkItemCursor{UpdatedAt: last.updatedAt, ID: last.id})
		if err != nil {
			return complianceremediation.WorkItemPage{}, err
		}
	}
	return page, nil
}

func encodeComplianceWorkItemCursor(cursor complianceWorkItemCursor) (string, error) {
	cursor.ID = strings.TrimSpace(cursor.ID)
	cursor.UpdatedAt = cursor.UpdatedAt.UTC()
	if cursor.ID == "" || cursor.UpdatedAt.IsZero() {
		return "", fmt.Errorf("%w: work item cursor is incomplete", complianceremediation.ErrInvalidRequest)
	}
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode compliance work item cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeComplianceWorkItemCursor(value string) (complianceWorkItemCursor, error) {
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return complianceWorkItemCursor{}, fmt.Errorf("%w: work item cursor is malformed", complianceremediation.ErrInvalidRequest)
	}
	var cursor complianceWorkItemCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return complianceWorkItemCursor{}, fmt.Errorf("%w: work item cursor is malformed", complianceremediation.ErrInvalidRequest)
	}
	cursor.ID = strings.TrimSpace(cursor.ID)
	cursor.UpdatedAt = cursor.UpdatedAt.UTC()
	if cursor.ID == "" || cursor.UpdatedAt.IsZero() {
		return complianceWorkItemCursor{}, fmt.Errorf("%w: work item cursor is incomplete", complianceremediation.ErrInvalidRequest)
	}
	return cursor, nil
}

var _ complianceremediation.WorkItemLister = (*Store)(nil)
