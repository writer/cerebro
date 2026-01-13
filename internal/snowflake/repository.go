package snowflake

import (
	"context"
	"encoding/json"
	"fmt"
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
		schema: fmt.Sprintf("%s.%s", client.database, SchemaName),
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
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
	ResolvedAt   *time.Time             `json:"resolved_at"`
}

func (r *FindingRepository) Upsert(ctx context.Context, f *FindingRecord) error {
	resourceJSON, _ := json.Marshal(f.ResourceData)

	query := fmt.Sprintf(`
		MERGE INTO %s.findings t
		USING (SELECT ? as id) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			last_seen = CURRENT_TIMESTAMP(),
			status = ?,
			resource_data = PARSE_JSON(?),
			_updated_at = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (
			id, policy_id, policy_name, severity, status,
			resource_id, resource_type, resource_data, description,
			first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())
	`, r.schema)

	_, err := r.client.db.ExecContext(ctx, query,
		f.ID,
		f.Status,
		string(resourceJSON),
		f.ID, f.PolicyID, f.PolicyName, f.Severity, f.Status,
		f.ResourceID, f.ResourceType, string(resourceJSON), f.Description,
	)
	return err
}

func (r *FindingRepository) Get(ctx context.Context, id string) (*FindingRecord, error) {
	query := fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, resource_data, description,
			   first_seen, last_seen, resolved_at
		FROM %s.findings WHERE id = ?
	`, r.schema)

	row := r.client.db.QueryRowContext(ctx, query, id)

	var f FindingRecord
	var resourceData []byte
	err := row.Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status,
		&f.ResourceID, &f.ResourceType, &resourceData, &f.Description,
		&f.FirstSeen, &f.LastSeen, &f.ResolvedAt)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(resourceData, &f.ResourceData)
	return &f, nil
}

func (r *FindingRepository) List(ctx context.Context, filter FindingFilter) ([]*FindingRecord, error) {
	query := fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, description, first_seen, last_seen
		FROM %s.findings WHERE 1=1
	`, r.schema)

	var args []interface{}
	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND status = ?"
		args = append(args, filter.Status)
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
	defer rows.Close()

	var findings []*FindingRecord
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
	query := fmt.Sprintf(`
		UPDATE %s.findings 
		SET status = ?, _updated_at = CURRENT_TIMESTAMP()
		WHERE id = ?
	`, r.schema)

	if status == "resolved" {
		query = fmt.Sprintf(`
			UPDATE %s.findings 
			SET status = ?, resolved_at = CURRENT_TIMESTAMP(), _updated_at = CURRENT_TIMESTAMP()
			WHERE id = ?
		`, r.schema)
	}

	_, err := r.client.db.ExecContext(ctx, query, status, id)
	return err
}

func (r *FindingRepository) Stats(ctx context.Context) (map[string]interface{}, error) {
	query := fmt.Sprintf(`
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN status = 'open' THEN 1 END) as open,
			COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved,
			COUNT(CASE WHEN status = 'suppressed' THEN 1 END) as suppressed,
			COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
			COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
			COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
			COUNT(CASE WHEN severity = 'low' THEN 1 END) as low
		FROM %s.findings
	`, r.schema)

	row := r.client.db.QueryRowContext(ctx, query)

	var total, open, resolved, suppressed, critical, high, medium, low int
	if err := row.Scan(&total, &open, &resolved, &suppressed, &critical, &high, &medium, &low); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total":      total,
		"by_status":  map[string]int{"open": open, "resolved": resolved, "suppressed": suppressed},
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
		schema: fmt.Sprintf("%s.%s", client.database, SchemaName),
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

	query := fmt.Sprintf(`
		INSERT INTO %s.tickets (
			id, external_id, provider, title, description,
			priority, status, type, external_url, finding_ids
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?))
	`, r.schema)

	_, err := r.client.db.ExecContext(ctx, query,
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
		schema: fmt.Sprintf("%s.%s", client.database, SchemaName),
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

	query := fmt.Sprintf(`
		INSERT INTO %s.audit_log (
			id, action, actor_id, actor_type, resource_type,
			resource_id, details, ip_address, user_agent
		) VALUES (?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?, ?)
	`, r.schema)

	_, err := r.client.db.ExecContext(ctx, query,
		entry.ID, entry.Action, entry.ActorID, entry.ActorType, entry.ResourceType,
		entry.ResourceID, string(detailsJSON), entry.IPAddress, entry.UserAgent,
	)
	return err
}

func (r *AuditRepository) List(ctx context.Context, resourceType, resourceID string, limit int) ([]*AuditEntry, error) {
	if limit == 0 {
		limit = 100
	}

	query := fmt.Sprintf(`
		SELECT id, action, actor_id, actor_type, resource_type, resource_id, ip_address, timestamp
		FROM %s.audit_log
		WHERE 1=1
	`, r.schema)

	var args []interface{}
	if resourceType != "" {
		query += " AND resource_type = ?"
		args = append(args, resourceType)
	}
	if resourceID != "" {
		query += " AND resource_id = ?"
		args = append(args, resourceID)
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)

	rows, err := r.client.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts time.Time
		if err := rows.Scan(&e.ID, &e.Action, &e.ActorID, &e.ActorType,
			&e.ResourceType, &e.ResourceID, &e.IPAddress, &ts); err != nil {
			continue
		}
		entries = append(entries, &e)
	}
	return entries, nil
}
