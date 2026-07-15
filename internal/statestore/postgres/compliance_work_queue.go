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
	if limit > 200 {
		return complianceremediation.WorkItemPage{}, fmt.Errorf("%w: limit must be at most 200", complianceremediation.ErrInvalidRequest)
	}
	state := string(filter.State)
	ownerID := strings.TrimSpace(filter.OwnerID)
	var cursorUpdatedAt any
	cursorID := ""
	if cursorValue := strings.TrimSpace(filter.Cursor); cursorValue != "" {
		cursor, err := decodeComplianceWorkItemCursor(cursorValue)
		if err != nil {
			return complianceremediation.WorkItemPage{}, err
		}
		cursorUpdatedAt = cursor.UpdatedAt.UTC()
		cursorID = cursor.ID
	}
	const query = `
SELECT id, updated_at, body_json
FROM compliance_work_items
WHERE tenant_id = $1
  AND ($2 = '' OR body_json->>'state' = $2)
  AND ($3 = '' OR body_json->>'owner_id' = $3)
  AND ($4::timestamptz IS NULL OR (updated_at < $4 OR (updated_at = $4 AND id > $5)))
ORDER BY updated_at DESC, id ASC
LIMIT $6`
	rows, err := s.db.QueryContext(ctx, query, tenantID, state, ownerID, cursorUpdatedAt, cursorID, int64(limit)+1)
	if err != nil {
		return complianceremediation.WorkItemPage{}, fmt.Errorf("list compliance work items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	type rowValue struct {
		id        string
		updatedAt time.Time
		item      complianceassessment.WorkItem
	}
	values := []rowValue{}
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
	page := complianceremediation.WorkItemPage{Items: []complianceassessment.WorkItem{}}
	var lastIncluded rowValue
	var included uint32
	for _, value := range values {
		if included == limit {
			break
		}
		page.Items = append(page.Items, value.item)
		lastIncluded = value
		included++
	}
	if len(values) > len(page.Items) && len(page.Items) != 0 {
		page.NextCursor, err = encodeComplianceWorkItemCursor(complianceWorkItemCursor{UpdatedAt: lastIncluded.updatedAt, ID: lastIncluded.id})
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
