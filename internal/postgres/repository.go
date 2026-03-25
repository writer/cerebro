package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FindingRepository handles finding persistence in Postgres.
type FindingRepository struct {
	client *PostgresClient
	schema string
}

// NewFindingRepository creates a new FindingRepository.
func NewFindingRepository(client *PostgresClient) *FindingRepository {
	return &FindingRepository{
		client: client,
		schema: client.AppSchema(),
	}
}

// FindingRecord represents a finding row.
type FindingRecord struct {
	ID           string                 `json:"id"`
	PolicyID     string                 `json:"policy_id"`
	PolicyName   string                 `json:"policy_name"`
	Severity     string                 `json:"severity"`
	Status       string                 `json:"status"`
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"`
	ResourceData map[string]interface{} `json:"resource_data"`
	Description  string                 `json:"description"`
	Remediation  string                 `json:"remediation,omitempty"`
	Metadata     json.RawMessage        `json:"metadata,omitempty"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	ResolvedAt   *time.Time             `json:"resolved_at"`
}

// Upsert inserts or updates a finding using INSERT ON CONFLICT.
func (r *FindingRepository) Upsert(ctx context.Context, f *FindingRecord) error {
	resourceJSON, _ := json.Marshal(f.ResourceData)

	findingsTable, err := SafeQualifiedTableRef(r.schema, "findings")
	if err != nil {
		return fmt.Errorf("invalid findings table reference: %w", err)
	}

	metadata := f.Metadata
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		INSERT INTO ` + findingsTable + ` (
			id, policy_id, policy_name, severity, status,
			resource_id, resource_type, resource_data, description,
			remediation, metadata, first_seen, last_seen
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			status = $5,
			resource_data = $8::jsonb,
			description = $9,
			remediation = $10,
			metadata = $11::jsonb,
			_updated_at = CURRENT_TIMESTAMP
	`

	_, err = r.client.db.ExecContext(ctx, query,
		f.ID, f.PolicyID, f.PolicyName, f.Severity, strings.ToUpper(f.Status),
		f.ResourceID, f.ResourceType, string(resourceJSON), f.Description,
		f.Remediation, string(metadata),
	)
	return err
}

// Get retrieves a finding by ID.
func (r *FindingRepository) Get(ctx context.Context, id string) (*FindingRecord, error) {
	findingsTable, err := SafeQualifiedTableRef(r.schema, "findings")
	if err != nil {
		return nil, fmt.Errorf("invalid findings table reference: %w", err)
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, resource_data, description,
			   remediation, metadata, first_seen, last_seen, resolved_at
		FROM ` + findingsTable + ` WHERE id = $1
	`

	row := r.client.db.QueryRowContext(ctx, query, id)

	var f FindingRecord
	var resourceData []byte
	var metadataData []byte
	var remediation sql.NullString
	err = row.Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status,
		&f.ResourceID, &f.ResourceType, &resourceData, &f.Description,
		&remediation, &metadataData, &f.FirstSeen, &f.LastSeen, &f.ResolvedAt)
	if err != nil {
		return nil, err
	}
	if remediation.Valid {
		f.Remediation = remediation.String
	}
	if len(metadataData) > 0 {
		f.Metadata = metadataData
	}

	_ = json.Unmarshal(resourceData, &f.ResourceData)
	return &f, nil
}

// List retrieves findings matching the given filter.
func (r *FindingRepository) List(ctx context.Context, filter FindingFilter) ([]*FindingRecord, error) {
	findingsTable, err := SafeQualifiedTableRef(r.schema, "findings")
	if err != nil {
		return nil, fmt.Errorf("invalid findings table reference: %w", err)
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, description, first_seen, last_seen
		FROM ` + findingsTable + ` WHERE 1=1
	`

	var args []interface{}
	argIdx := 1
	if filter.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, filter.Severity)
		argIdx++
	}
	if filter.Status != "" {
		query += fmt.Sprintf(" AND UPPER(status) = $%d", argIdx)
		args = append(args, strings.ToUpper(filter.Status))
		argIdx++
	}
	if filter.PolicyID != "" {
		query += fmt.Sprintf(" AND policy_id = $%d", argIdx)
		args = append(args, filter.PolicyID)
	}

	query += " ORDER BY last_seen DESC LIMIT 1000"

	rows, err := r.client.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	findings := make([]*FindingRecord, 0, 100)
	for rows.Next() {
		var f FindingRecord
		if err := rows.Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status,
			&f.ResourceID, &f.ResourceType, &f.Description, &f.FirstSeen, &f.LastSeen); err != nil {
			continue
		}
		findings = append(findings, &f)
	}
	return findings, nil
}

// UpdateStatus updates the status of a finding.
func (r *FindingRepository) UpdateStatus(ctx context.Context, id, status string) error {
	normalized := strings.ToUpper(status)
	findingsTable, err := SafeQualifiedTableRef(r.schema, "findings")
	if err != nil {
		return fmt.Errorf("invalid findings table reference: %w", err)
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		UPDATE ` + findingsTable + `
		SET status = $1, _updated_at = CURRENT_TIMESTAMP
		WHERE id = $2
	`

	if normalized == "RESOLVED" {
		// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
		query = `
			UPDATE ` + findingsTable + `
			SET status = $1, resolved_at = CURRENT_TIMESTAMP, _updated_at = CURRENT_TIMESTAMP
			WHERE id = $2
		`
	}

	_, err = r.client.db.ExecContext(ctx, query, normalized, id)
	return err
}

// Stats returns aggregate statistics for findings.
func (r *FindingRepository) Stats(ctx context.Context) (map[string]interface{}, error) {
	findingsTable, err := SafeQualifiedTableRef(r.schema, "findings")
	if err != nil {
		return nil, fmt.Errorf("invalid findings table reference: %w", err)
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN UPPER(status) = 'OPEN' THEN 1 END) as open,
			COUNT(CASE WHEN UPPER(status) = 'RESOLVED' THEN 1 END) as resolved,
			COUNT(CASE WHEN UPPER(status) = 'SUPPRESSED' THEN 1 END) as suppressed,
			COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
			COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
			COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
			COUNT(CASE WHEN severity = 'low' THEN 1 END) as low
		FROM ` + findingsTable + `
	`

	row := r.client.db.QueryRowContext(ctx, query)

	var total, open, resolved, suppressed, critical, high, medium, low int
	if err := row.Scan(&total, &open, &resolved, &suppressed, &critical, &high, &medium, &low); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total":       total,
		"by_status":   map[string]int{"OPEN": open, "RESOLVED": resolved, "SUPPRESSED": suppressed},
		"by_severity": map[string]int{"critical": critical, "high": high, "medium": medium, "low": low},
	}, nil
}

// FindingFilter specifies criteria for listing findings.
type FindingFilter struct {
	Severity string
	Status   string
	PolicyID string
}

// TicketRepository handles ticket persistence in Postgres.
type TicketRepository struct {
	client *PostgresClient
	schema string
}

// NewTicketRepository creates a new TicketRepository.
func NewTicketRepository(client *PostgresClient) *TicketRepository {
	return &TicketRepository{
		client: client,
		schema: client.AppSchema(),
	}
}

// TicketRecord represents a ticket row.
type TicketRecord struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"external_id"`
	Provider    string    `json:"provider"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"`
	Status      string    `json:"status"`
	Type        string    `json:"type"`
	ExternalURL string    `json:"external_url"`
	FindingIDs  []string  `json:"finding_ids"`
	CreatedAt   time.Time `json:"created_at"`
}

// Create inserts a new ticket.
func (r *TicketRepository) Create(ctx context.Context, t *TicketRecord) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}

	findingsJSON, _ := json.Marshal(t.FindingIDs)
	ticketsTable, err := SafeQualifiedTableRef(r.schema, "tickets")
	if err != nil {
		return fmt.Errorf("invalid tickets table reference: %w", err)
	}

	// #nosec G202 -- ticketsTable is validated via SafeQualifiedTableRef.
	query := `
		INSERT INTO ` + ticketsTable + ` (
			id, external_id, provider, title, description,
			priority, status, type, external_url, finding_ids
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
	`

	_, err = r.client.db.ExecContext(ctx, query,
		t.ID, t.ExternalID, t.Provider, t.Title, t.Description,
		t.Priority, t.Status, t.Type, t.ExternalURL, string(findingsJSON),
	)
	return err
}

// AuditRepository handles audit log persistence in Postgres.
type AuditRepository struct {
	client *PostgresClient
	schema string
}

// NewAuditRepository creates a new AuditRepository.
func NewAuditRepository(client *PostgresClient) *AuditRepository {
	return &AuditRepository{
		client: client,
		schema: client.AppSchema(),
	}
}

// AuditEntry represents an audit log row.
type AuditEntry struct {
	ID           string                 `json:"id"`
	Action       string                 `json:"action"`
	ActorID      string                 `json:"actor_id"`
	ActorType    string                 `json:"actor_type"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Details      map[string]interface{} `json:"details"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
}

// Log inserts an audit entry.
func (r *AuditRepository) Log(ctx context.Context, entry *AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	detailsJSON, _ := json.Marshal(entry.Details)
	auditTable, err := SafeQualifiedTableRef(r.schema, "audit_log")
	if err != nil {
		return fmt.Errorf("invalid audit_log table reference: %w", err)
	}

	// #nosec G202 -- auditTable is validated via SafeQualifiedTableRef.
	query := `
		INSERT INTO ` + auditTable + ` (
			id, action, actor_id, actor_type, resource_type,
			resource_id, details, ip_address, user_agent
		) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
	`

	_, err = r.client.db.ExecContext(ctx, query,
		entry.ID, entry.Action, entry.ActorID, entry.ActorType, entry.ResourceType,
		entry.ResourceID, string(detailsJSON), entry.IPAddress, entry.UserAgent,
	)
	return err
}

// List retrieves audit entries matching the given criteria.
func (r *AuditRepository) List(ctx context.Context, resourceType, resourceID string, limit int) ([]*AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	auditTable, err := SafeQualifiedTableRef(r.schema, "audit_log")
	if err != nil {
		return nil, fmt.Errorf("invalid audit_log table reference: %w", err)
	}

	// #nosec G202 -- auditTable is validated via SafeQualifiedTableRef.
	query := `
		SELECT id, action, actor_id, actor_type, resource_type, resource_id, ip_address, timestamp
		FROM ` + auditTable + `
		WHERE 1=1
	`

	var args []interface{}
	argIdx := 1
	if resourceType != "" {
		query += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, resourceType)
		argIdx++
	}
	if resourceID != "" {
		query += fmt.Sprintf(" AND resource_id = $%d", argIdx)
		args = append(args, resourceID)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d", argIdx)
	args = append(args, limit)

	rows, err := r.client.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	entries := make([]*AuditEntry, 0, limit)
	for rows.Next() {
		var e AuditEntry
		var ts time.Time
		if err := rows.Scan(&e.ID, &e.Action, &e.ActorID, &e.ActorType,
			&e.ResourceType, &e.ResourceID, &e.IPAddress, &ts); err != nil {
			continue
		}
		_ = ts // timestamp available for future use
		entries = append(entries, &e)
	}
	return entries, nil
}

// PolicyHistoryRepository handles policy version history in Postgres.
type PolicyHistoryRepository struct {
	client *PostgresClient
	schema string
}

// NewPolicyHistoryRepository creates a new PolicyHistoryRepository.
func NewPolicyHistoryRepository(client *PostgresClient) *PolicyHistoryRepository {
	return &PolicyHistoryRepository{
		client: client,
		schema: client.AppSchema(),
	}
}

// PolicyHistoryRecord represents a policy version history row.
type PolicyHistoryRecord struct {
	PolicyID      string          `json:"policy_id"`
	Version       int             `json:"version"`
	Content       json.RawMessage `json:"content"`
	ChangeType    string          `json:"change_type,omitempty"`
	PinnedVersion *int            `json:"pinned_version,omitempty"`
	EffectiveFrom time.Time       `json:"effective_from"`
	EffectiveTo   *time.Time      `json:"effective_to,omitempty"`
}

// Upsert inserts or updates a policy history record using INSERT ON CONFLICT.
func (r *PolicyHistoryRepository) Upsert(ctx context.Context, record *PolicyHistoryRecord) error {
	if record == nil {
		return fmt.Errorf("policy history record is required")
	}
	if strings.TrimSpace(record.PolicyID) == "" {
		return fmt.Errorf("policy id is required")
	}
	if record.Version <= 0 {
		return fmt.Errorf("policy version must be positive")
	}

	policyHistoryTable, err := SafeQualifiedTableRef(r.schema, "policy_history")
	if err != nil {
		return fmt.Errorf("invalid policy_history table reference: %w", err)
	}

	content := record.Content
	if len(content) == 0 {
		content = []byte("{}")
	}

	effectiveFrom := record.EffectiveFrom.UTC()
	if effectiveFrom.IsZero() {
		effectiveFrom = time.Now().UTC()
	}

	var effectiveTo interface{}
	if record.EffectiveTo != nil {
		effectiveTo = record.EffectiveTo.UTC()
	}

	var pinnedVersion interface{}
	if record.PinnedVersion != nil {
		pinnedVersion = *record.PinnedVersion
	}

	// #nosec G202 -- policyHistoryTable is validated via SafeQualifiedTableRef.
	query := `
		INSERT INTO ` + policyHistoryTable + ` (
			policy_id, version, content, change_type, pinned_version, effective_from, effective_to
		) VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)
		ON CONFLICT (policy_id, version) DO UPDATE SET
			content = $3::jsonb,
			change_type = $4,
			pinned_version = $5,
			effective_from = $6,
			effective_to = $7
	`

	_, err = r.client.db.ExecContext(ctx, query,
		record.PolicyID, record.Version,
		string(content), record.ChangeType, pinnedVersion, effectiveFrom, effectiveTo,
	)
	return err
}

// List retrieves policy history records for a policy.
func (r *PolicyHistoryRepository) List(ctx context.Context, policyID string, limit int) ([]*PolicyHistoryRecord, error) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		return nil, fmt.Errorf("policy id is required")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	policyHistoryTable, err := SafeQualifiedTableRef(r.schema, "policy_history")
	if err != nil {
		return nil, fmt.Errorf("invalid policy_history table reference: %w", err)
	}

	// #nosec G202 -- policyHistoryTable is validated via SafeQualifiedTableRef.
	query := `
		SELECT policy_id, version, content, change_type, pinned_version, effective_from, effective_to
		FROM ` + policyHistoryTable + `
		WHERE policy_id = $1
		ORDER BY version DESC
		LIMIT $2
	`

	rows, err := r.client.db.QueryContext(ctx, query, policyID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	result := make([]*PolicyHistoryRecord, 0, limit)
	for rows.Next() {
		record := &PolicyHistoryRecord{}
		var content []byte
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
		record.Content = content
		if changeType.Valid {
			record.ChangeType = changeType.String
		}
		if pinned.Valid {
			pinnedVal := int(pinned.Int64)
			record.PinnedVersion = &pinnedVal
		}
		if effectiveTo.Valid {
			ts := effectiveTo.Time
			record.EffectiveTo = &ts
		}
		result = append(result, record)
	}

	return result, rows.Err()
}

// RiskEngineStateRepository persists durable graph risk-engine snapshots in Postgres.
type RiskEngineStateRepository struct {
	client *PostgresClient
	schema string
}

// NewRiskEngineStateRepository creates a new RiskEngineStateRepository.
func NewRiskEngineStateRepository(client *PostgresClient) *RiskEngineStateRepository {
	return &RiskEngineStateRepository{
		client: client,
		schema: client.AppSchema(),
	}
}

// SaveSnapshot persists a risk engine snapshot using INSERT ON CONFLICT.
func (r *RiskEngineStateRepository) SaveSnapshot(ctx context.Context, graphID string, snapshot []byte) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("risk engine state repository is not initialized")
	}
	graphID = strings.TrimSpace(graphID)
	if graphID == "" {
		return fmt.Errorf("graph id is required")
	}
	if len(snapshot) == 0 {
		snapshot = []byte("{}")
	}

	tableRef, err := r.tableRef()
	if err != nil {
		return err
	}
	if err := r.ensureTable(ctx, tableRef); err != nil {
		return err
	}

	// #nosec G202 -- tableRef is validated through SafeQualifiedTableRef.
	query := `
		INSERT INTO ` + tableRef + ` (graph_id, snapshot, updated_at)
		VALUES ($1, $2::jsonb, CURRENT_TIMESTAMP)
		ON CONFLICT (graph_id) DO UPDATE SET
			snapshot = $2::jsonb,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err = r.client.db.ExecContext(ctx, query, graphID, string(snapshot))
	return err
}

// LoadSnapshot retrieves the risk engine snapshot for a graph.
func (r *RiskEngineStateRepository) LoadSnapshot(ctx context.Context, graphID string) ([]byte, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("risk engine state repository is not initialized")
	}
	graphID = strings.TrimSpace(graphID)
	if graphID == "" {
		return nil, fmt.Errorf("graph id is required")
	}

	tableRef, err := r.tableRef()
	if err != nil {
		return nil, err
	}
	if err := r.ensureTable(ctx, tableRef); err != nil {
		return nil, err
	}

	// #nosec G202 -- tableRef is validated through SafeQualifiedTableRef.
	query := `SELECT snapshot FROM ` + tableRef + ` WHERE graph_id = $1`
	row := r.client.db.QueryRowContext(ctx, query, graphID)
	var raw interface{}
	if err := row.Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	normalized := normalizeJSONB(raw)
	if len(normalized) == 0 || string(normalized) == "null" {
		return nil, nil
	}
	return normalized, nil
}

func (r *RiskEngineStateRepository) tableRef() (string, error) {
	ref, err := SafeQualifiedTableRef(r.schema, "risk_engine_state")
	if err != nil {
		return "", fmt.Errorf("invalid risk_engine_state table reference: %w", err)
	}
	return ref, nil
}

func (r *RiskEngineStateRepository) ensureTable(ctx context.Context, tableRef string) error {
	// #nosec G202 -- tableRef is validated through SafeQualifiedTableRef.
	query := `
		CREATE TABLE IF NOT EXISTS ` + tableRef + ` (
			graph_id VARCHAR(128) PRIMARY KEY,
			snapshot JSONB,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`
	_, err := r.client.db.ExecContext(ctx, query)
	return err
}

func normalizeJSONB(raw interface{}) []byte {
	switch v := raw.(type) {
	case nil:
		return nil
	case []byte:
		trimmed := strings.TrimSpace(string(v))
		if trimmed == "" {
			return nil
		}
		return []byte(trimmed)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return nil
		}
		return []byte(trimmed)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return encoded
	}
}

// RetentionRepository deletes stale data from Postgres app tables.
type RetentionRepository struct {
	client *PostgresClient
	schema string
}

// NewRetentionRepository creates a new RetentionRepository.
func NewRetentionRepository(client *PostgresClient) *RetentionRepository {
	return &RetentionRepository{
		client: client,
		schema: client.AppSchema(),
	}
}

// CleanupAuditLogs deletes audit log entries older than the given time.
func (r *RetentionRepository) CleanupAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	return r.deleteBefore(ctx, "audit_log", "timestamp", olderThan)
}

// CleanupAgentData deletes agent sessions and messages older than the given time.
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

// CleanupGraphData deletes graph data older than the given time.
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

// CleanupAccessReviewData deletes access review data older than the given time.
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
	query := fmt.Sprintf(`DELETE FROM %s WHERE %s < $1`, tableRef, timeColumn)
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
