package appstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/writer/cerebro/internal/snowflake"
)

const (
	auditTable           = "cerebro_audit_log"
	policyHistoryTable   = "cerebro_policy_history"
	riskEngineStateTable = "cerebro_risk_engine_state"
	sessionTable         = "cerebro_agent_sessions"
)

type AuditRepository struct {
	db          *sql.DB
	rewriteSQL  func(string) string
	schemaMu    sync.Mutex
	schemaReady bool
}

func NewAuditRepository(db *sql.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) EnsureSchema(ctx context.Context) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("audit repository is not initialized")
	}

	r.schemaMu.Lock()
	defer r.schemaMu.Unlock()
	if r.schemaReady {
		return nil
	}

	_, err := r.db.ExecContext(ctx, r.q(`
CREATE TABLE IF NOT EXISTS `+auditTable+` (
	id TEXT PRIMARY KEY,
	created_at TIMESTAMP NOT NULL,
	action TEXT NOT NULL,
	actor_id TEXT,
	actor_type TEXT,
	resource_type TEXT,
	resource_id TEXT,
	details TEXT NOT NULL DEFAULT '{}',
	ip_address TEXT,
	user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_`+auditTable+`_resource ON `+auditTable+` (resource_type, resource_id, created_at);
CREATE INDEX IF NOT EXISTS idx_`+auditTable+`_created_at ON `+auditTable+` (created_at);
`))
	if err == nil {
		r.schemaReady = true
	}
	return err
}

func (r *AuditRepository) Log(ctx context.Context, entry *snowflake.AuditEntry) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("audit repository is not initialized")
	}
	if entry == nil {
		return fmt.Errorf("audit entry is required")
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(entry.ID) == "" {
		entry.ID = uuid.NewString()
	}

	detailsJSON, err := marshalJSONText(entry.Details, "{}")
	if err != nil {
		return err
	}

	createdAt := entry.Timestamp.UTC()
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
		entry.Timestamp = createdAt
	}

	_, err = r.db.ExecContext(ctx, r.q(`
INSERT INTO `+auditTable+` (
	id, created_at, action, actor_id, actor_type, resource_type, resource_id, details, ip_address, user_agent
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO UPDATE SET
	created_at = EXCLUDED.created_at,
	action = EXCLUDED.action,
	actor_id = EXCLUDED.actor_id,
	actor_type = EXCLUDED.actor_type,
	resource_type = EXCLUDED.resource_type,
	resource_id = EXCLUDED.resource_id,
	details = EXCLUDED.details,
	ip_address = EXCLUDED.ip_address,
	user_agent = EXCLUDED.user_agent
`),
		entry.ID,
		createdAt,
		entry.Action,
		entry.ActorID,
		entry.ActorType,
		entry.ResourceType,
		entry.ResourceID,
		detailsJSON,
		entry.IPAddress,
		entry.UserAgent,
	)
	return err
}

func (r *AuditRepository) List(ctx context.Context, resourceType, resourceID string, limit int) ([]*snowflake.AuditEntry, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("audit repository is not initialized")
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
SELECT id, created_at, action, actor_id, actor_type, resource_type, resource_id, details, ip_address, user_agent
FROM ` + auditTable + `
WHERE 1=1`
	args := make([]any, 0, 3)
	if trimmed := strings.TrimSpace(resourceType); trimmed != "" {
		args = append(args, trimmed)
		query += fmt.Sprintf(" AND resource_type = %s", placeholder(len(args)))
	}
	if trimmed := strings.TrimSpace(resourceID); trimmed != "" {
		args = append(args, trimmed)
		query += fmt.Sprintf(" AND resource_id = %s", placeholder(len(args)))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %s", placeholder(len(args)))

	rows, err := r.db.QueryContext(ctx, r.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	entries := make([]*snowflake.AuditEntry, 0, limit)
	for rows.Next() {
		entry := &snowflake.AuditEntry{}
		var detailsRaw string
		if err := rows.Scan(
			&entry.ID,
			&entry.Timestamp,
			&entry.Action,
			&entry.ActorID,
			&entry.ActorType,
			&entry.ResourceType,
			&entry.ResourceID,
			&detailsRaw,
			&entry.IPAddress,
			&entry.UserAgent,
		); err != nil {
			return nil, err
		}
		if strings.TrimSpace(detailsRaw) != "" {
			if err := json.Unmarshal([]byte(detailsRaw), &entry.Details); err != nil {
				return nil, err
			}
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (r *AuditRepository) q(query string) string {
	if r != nil && r.rewriteSQL != nil {
		return r.rewriteSQL(query)
	}
	return query
}

type PolicyHistoryRepository struct {
	db          *sql.DB
	rewriteSQL  func(string) string
	schemaMu    sync.Mutex
	schemaReady bool
}

func NewPolicyHistoryRepository(db *sql.DB) *PolicyHistoryRepository {
	return &PolicyHistoryRepository{db: db}
}

func (r *PolicyHistoryRepository) EnsureSchema(ctx context.Context) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("policy history repository is not initialized")
	}

	r.schemaMu.Lock()
	defer r.schemaMu.Unlock()
	if r.schemaReady {
		return nil
	}

	_, err := r.db.ExecContext(ctx, r.q(`
CREATE TABLE IF NOT EXISTS `+policyHistoryTable+` (
	policy_id TEXT NOT NULL,
	version INTEGER NOT NULL,
	content TEXT NOT NULL DEFAULT '{}',
	change_type TEXT,
	pinned_version INTEGER,
	effective_from TIMESTAMP NOT NULL,
	effective_to TIMESTAMP,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (policy_id, version)
);
CREATE INDEX IF NOT EXISTS idx_`+policyHistoryTable+`_policy ON `+policyHistoryTable+` (policy_id, version DESC);
`))
	if err == nil {
		r.schemaReady = true
	}
	return err
}

func (r *PolicyHistoryRepository) Upsert(ctx context.Context, record *snowflake.PolicyHistoryRecord) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("policy history repository is not initialized")
	}
	if record == nil {
		return fmt.Errorf("policy history record is required")
	}
	if strings.TrimSpace(record.PolicyID) == "" {
		return fmt.Errorf("policy id is required")
	}
	if record.Version <= 0 {
		return fmt.Errorf("policy version must be positive")
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return err
	}

	content := string(record.Content)
	if strings.TrimSpace(content) == "" {
		content = "{}"
	}
	effectiveFrom := record.EffectiveFrom.UTC()
	if effectiveFrom.IsZero() {
		effectiveFrom = time.Now().UTC()
	}

	var pinnedVersion any
	if record.PinnedVersion != nil {
		pinnedVersion = *record.PinnedVersion
	}
	var effectiveTo any
	if record.EffectiveTo != nil {
		effectiveTo = record.EffectiveTo.UTC()
	}

	_, err := r.db.ExecContext(ctx, r.q(`
INSERT INTO `+policyHistoryTable+` (
	policy_id, version, content, change_type, pinned_version, effective_from, effective_to
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (policy_id, version) DO UPDATE SET
	content = EXCLUDED.content,
	change_type = EXCLUDED.change_type,
	pinned_version = EXCLUDED.pinned_version,
	effective_from = EXCLUDED.effective_from,
	effective_to = EXCLUDED.effective_to
`),
		record.PolicyID,
		record.Version,
		content,
		record.ChangeType,
		pinnedVersion,
		effectiveFrom,
		effectiveTo,
	)
	return err
}

func (r *PolicyHistoryRepository) List(ctx context.Context, policyID string, limit int) ([]*snowflake.PolicyHistoryRecord, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("policy history repository is not initialized")
	}
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("policy id is required")
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	rows, err := r.db.QueryContext(ctx, r.q(`
SELECT policy_id, version, content, change_type, pinned_version, effective_from, effective_to
FROM `+policyHistoryTable+`
WHERE policy_id = $1
ORDER BY version DESC
LIMIT $2
`), policyID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	records := make([]*snowflake.PolicyHistoryRecord, 0, limit)
	for rows.Next() {
		record := &snowflake.PolicyHistoryRecord{}
		var content string
		var changeType sql.NullString
		var pinned sql.NullInt64
		var effectiveTo sql.NullTime
		if err := rows.Scan(
			&record.PolicyID,
			&record.Version,
			&content,
			&changeType,
			&pinned,
			&record.EffectiveFrom,
			&effectiveTo,
		); err != nil {
			return nil, err
		}
		record.Content = json.RawMessage(content)
		if changeType.Valid {
			record.ChangeType = changeType.String
		}
		if pinned.Valid {
			pinnedValue := int(pinned.Int64)
			record.PinnedVersion = &pinnedValue
		}
		if effectiveTo.Valid {
			ts := effectiveTo.Time.UTC()
			record.EffectiveTo = &ts
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (r *PolicyHistoryRepository) q(query string) string {
	if r != nil && r.rewriteSQL != nil {
		return r.rewriteSQL(query)
	}
	return query
}

type RiskEngineStateRepository struct {
	db          *sql.DB
	rewriteSQL  func(string) string
	schemaMu    sync.Mutex
	schemaReady bool
}

func NewRiskEngineStateRepository(db *sql.DB) *RiskEngineStateRepository {
	return &RiskEngineStateRepository{db: db}
}

func (r *RiskEngineStateRepository) EnsureSchema(ctx context.Context) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("risk engine state repository is not initialized")
	}

	r.schemaMu.Lock()
	defer r.schemaMu.Unlock()
	if r.schemaReady {
		return nil
	}

	_, err := r.db.ExecContext(ctx, r.q(`
CREATE TABLE IF NOT EXISTS `+riskEngineStateTable+` (
	graph_id TEXT PRIMARY KEY,
	snapshot TEXT NOT NULL DEFAULT '{}',
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`))
	if err == nil {
		r.schemaReady = true
	}
	return err
}

func (r *RiskEngineStateRepository) SaveSnapshot(ctx context.Context, graphID string, snapshot []byte) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("risk engine state repository is not initialized")
	}
	graphID = strings.TrimSpace(graphID)
	if graphID == "" {
		return fmt.Errorf("graph id is required")
	}
	if len(snapshot) == 0 {
		snapshot = []byte("{}")
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return err
	}

	_, err := r.db.ExecContext(ctx, r.q(`
INSERT INTO `+riskEngineStateTable+` (graph_id, snapshot, updated_at)
VALUES ($1, $2, $3)
ON CONFLICT (graph_id) DO UPDATE SET
	snapshot = EXCLUDED.snapshot,
	updated_at = EXCLUDED.updated_at
`), graphID, string(snapshot), time.Now().UTC())
	return err
}

func (r *RiskEngineStateRepository) LoadSnapshot(ctx context.Context, graphID string) ([]byte, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("risk engine state repository is not initialized")
	}
	graphID = strings.TrimSpace(graphID)
	if graphID == "" {
		return nil, fmt.Errorf("graph id is required")
	}
	if err := r.EnsureSchema(ctx); err != nil {
		return nil, err
	}

	var payload string
	err := r.db.QueryRowContext(ctx, r.q(`
SELECT snapshot FROM `+riskEngineStateTable+`
WHERE graph_id = $1
`), graphID).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload) == "" || strings.TrimSpace(payload) == "null" {
		return nil, nil
	}
	return []byte(payload), nil
}

func (r *RiskEngineStateRepository) q(query string) string {
	if r != nil && r.rewriteSQL != nil {
		return r.rewriteSQL(query)
	}
	return query
}

type RetentionRepository struct {
	db *sql.DB
}

func NewRetentionRepository(db *sql.DB) *RetentionRepository {
	return &RetentionRepository{db: db}
}

func (r *RetentionRepository) CleanupAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	return r.deleteBefore(ctx, auditTable, "created_at", olderThan)
}

func (r *RetentionRepository) CleanupAgentData(ctx context.Context, olderThan time.Time) (sessionsDeleted, messagesDeleted int64, err error) {
	sessionsDeleted, err = r.deleteBefore(ctx, sessionTable, "updated_at", olderThan)
	if err != nil {
		return 0, 0, err
	}
	return sessionsDeleted, 0, nil
}

func (r *RetentionRepository) CleanupGraphData(context.Context, time.Time) (int64, int64, int64, error) {
	return 0, 0, 0, nil
}

func (r *RetentionRepository) CleanupAccessReviewData(context.Context, time.Time) (int64, int64, error) {
	return 0, 0, nil
}

func (r *RetentionRepository) deleteBefore(ctx context.Context, table, timeColumn string, olderThan time.Time) (int64, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("retention repository is not initialized")
	}
	if olderThan.IsZero() {
		return 0, fmt.Errorf("retention cutoff is required")
	}
	result, err := r.db.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s < $1`, table, timeColumn), olderThan.UTC())
	if err != nil {
		return 0, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return rowsAffected, nil
}

func marshalJSONText(value any, fallback string) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	if trimmed := strings.TrimSpace(string(encoded)); trimmed != "" && trimmed != "null" {
		return trimmed, nil
	}
	return fallback, nil
}

func placeholder(idx int) string {
	return fmt.Sprintf("$%d", idx)
}
