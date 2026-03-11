package snowflake

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// FindingRepository handles finding persistence
type FindingRepository struct {
	client *Client
	schema string
}

func NewFindingRepository(client *Client) *FindingRepository {
	return &FindingRepository{
		client: client,
		schema: fmt.Sprintf("%s.%s", client.Database(), client.AppSchema()),
	}
}

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

func (r *FindingRepository) Upsert(ctx context.Context, f *FindingRecord) error {
	resourceJSON, _ := json.Marshal(f.ResourceData)

	// Using parameterized query with schema prefix.
	// #nosec G202 -- schema is internal trusted configuration, values remain parameterized
	query := `
		MERGE INTO ` + r.schema + `.findings t
		USING (SELECT ? as id) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			last_seen = CURRENT_TIMESTAMP(),
			status = ?,
			resource_data = PARSE_JSON(?),
			description = ?,
			remediation = ?,
			metadata = PARSE_JSON(?),
			_updated_at = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (
			id, policy_id, policy_name, severity, status,
			resource_id, resource_type, resource_data, description,
			remediation, metadata, first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?, ?, PARSE_JSON(?), CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())
	`

	metadata := f.Metadata
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}

	_, err := r.client.db.ExecContext(ctx, query,
		f.ID,
		strings.ToUpper(f.Status),
		string(resourceJSON),
		f.Description,
		f.Remediation,
		string(metadata),
		f.ID, f.PolicyID, f.PolicyName, f.Severity, strings.ToUpper(f.Status),
		f.ResourceID, f.ResourceType, string(resourceJSON), f.Description,
		f.Remediation,
		string(metadata),
	)
	return err
}

func (r *FindingRepository) Get(ctx context.Context, id string) (*FindingRecord, error) {
	// #nosec G202 -- schema is internal trusted configuration, id is parameterized
	query := `
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, resource_data, description,
			   remediation, metadata, first_seen, last_seen, resolved_at
		FROM ` + r.schema + `.findings WHERE id = ?
	`

	row := r.client.db.QueryRowContext(ctx, query, id)

	var f FindingRecord
	var resourceData []byte
	var metadataData []byte
	var remediation sql.NullString
	err := row.Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status,
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

func (r *FindingRepository) List(ctx context.Context, filter FindingFilter) ([]*FindingRecord, error) {
	// #nosec G202 -- schema is internal trusted configuration, filters remain parameterized
	query := `
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, description, first_seen, last_seen
		FROM ` + r.schema + `.findings WHERE 1=1
	`

	var args []interface{}
	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND UPPER(status) = ?"
		args = append(args, strings.ToUpper(filter.Status))
	}
	if filter.PolicyID != "" {
		query += " AND policy_id = ?"
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

func (r *FindingRepository) UpdateStatus(ctx context.Context, id, status string) error {
	normalized := strings.ToUpper(status)
	findingsTable, err := SafeQualifiedTableRef(r.schema, "findings")
	if err != nil {
		return fmt.Errorf("invalid findings table reference: %w", err)
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		UPDATE ` + findingsTable + `
		SET status = ?, _updated_at = CURRENT_TIMESTAMP()
		WHERE id = ?
	`

	if normalized == "RESOLVED" {
		// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
		query = `
			UPDATE ` + findingsTable + `
			SET status = ?, resolved_at = CURRENT_TIMESTAMP(), _updated_at = CURRENT_TIMESTAMP()
			WHERE id = ?
		`
	}

	_, err = r.client.db.ExecContext(ctx, query, normalized, id)
	return err
}

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

type FindingFilter struct {
	Severity string
	Status   string
	PolicyID string
}

// TicketRepository handles ticket persistence
type TicketRepository struct {
	client *Client
	schema string
}

func NewTicketRepository(client *Client) *TicketRepository {
	return &TicketRepository{
		client: client,
		schema: fmt.Sprintf("%s.%s", client.Database(), client.AppSchema()),
	}
}

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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?))
	`

	_, err = r.client.db.ExecContext(ctx, query,
		t.ID, t.ExternalID, t.Provider, t.Title, t.Description,
		t.Priority, t.Status, t.Type, t.ExternalURL, string(findingsJSON),
	)
	return err
}

// AuditRepository handles audit log persistence
type AuditRepository struct {
	client *Client
	schema string
}

func NewAuditRepository(client *Client) *AuditRepository {
	return &AuditRepository{
		client: client,
		schema: fmt.Sprintf("%s.%s", client.Database(), client.AppSchema()),
	}
}

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
		) VALUES (?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?, ?)
	`

	_, err = r.client.db.ExecContext(ctx, query,
		entry.ID, entry.Action, entry.ActorID, entry.ActorType, entry.ResourceType,
		entry.ResourceID, string(detailsJSON), entry.IPAddress, entry.UserAgent,
	)
	return err
}

func (r *AuditRepository) List(ctx context.Context, resourceType, resourceID string, limit int) ([]*AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// #nosec G202 -- schema is internal trusted configuration, filters remain parameterized
	query := `
		SELECT id, action, actor_id, actor_type, resource_type, resource_id, ip_address, timestamp
		FROM ` + r.schema + `.audit_log
		WHERE 1=1
	`

	var args []interface{}
	if resourceType != "" {
		query += " AND resource_type = ?"
		args = append(args, resourceType)
	}
	if resourceID != "" {
		query += " AND resource_id = ?"
		args = append(args, resourceID)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
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

// PolicyHistoryRepository handles policy version history persistence.
type PolicyHistoryRepository struct {
	client *Client
	schema string
}

func NewPolicyHistoryRepository(client *Client) *PolicyHistoryRepository {
	return &PolicyHistoryRepository{
		client: client,
		schema: fmt.Sprintf("%s.%s", client.Database(), client.AppSchema()),
	}
}

type PolicyHistoryRecord struct {
	PolicyID      string          `json:"policy_id"`
	Version       int             `json:"version"`
	Content       json.RawMessage `json:"content"`
	ChangeType    string          `json:"change_type,omitempty"`
	PinnedVersion *int            `json:"pinned_version,omitempty"`
	EffectiveFrom time.Time       `json:"effective_from"`
	EffectiveTo   *time.Time      `json:"effective_to,omitempty"`
}

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
		MERGE INTO ` + policyHistoryTable + ` t
		USING (SELECT ? AS policy_id, ? AS version) s
		ON t.policy_id = s.policy_id AND t.version = s.version
		WHEN MATCHED THEN UPDATE SET
			content = PARSE_JSON(?),
			change_type = ?,
			pinned_version = ?,
			effective_from = ?,
			effective_to = ?
		WHEN NOT MATCHED THEN INSERT (
			policy_id, version, content, change_type, pinned_version, effective_from, effective_to
		) VALUES (?, ?, PARSE_JSON(?), ?, ?, ?, ?)
	`

	_, err = r.client.db.ExecContext(ctx, query,
		record.PolicyID, record.Version,
		string(content), record.ChangeType, pinnedVersion, effectiveFrom, effectiveTo,
		record.PolicyID, record.Version, string(content), record.ChangeType, pinnedVersion, effectiveFrom, effectiveTo,
	)
	return err
}

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
		WHERE policy_id = ?
		ORDER BY version DESC
		LIMIT ?
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
