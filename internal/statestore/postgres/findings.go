package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

var ensureFindingStatements = []string{
	`CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  tenant_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  resource_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  event_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  observed_policy_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  control_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  policy_id TEXT NOT NULL DEFAULT '',
  policy_name TEXT NOT NULL DEFAULT '',
  check_id TEXT NOT NULL DEFAULT '',
  check_name TEXT NOT NULL DEFAULT '',
  assignee TEXT NOT NULL DEFAULT '',
  status_reason TEXT NOT NULL DEFAULT '',
  status_updated_at TIMESTAMPTZ,
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS observed_policy_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS control_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS policy_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS check_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS check_name TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_reason TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE findings ADD COLUMN IF NOT EXISTS status_updated_at TIMESTAMPTZ`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_rule_idx ON findings (runtime_id, rule_id)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_policy_idx ON findings (runtime_id, policy_id)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_check_idx ON findings (runtime_id, check_id)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_status_idx ON findings (runtime_id, status)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_severity_idx ON findings (runtime_id, severity)`,
	`CREATE INDEX IF NOT EXISTS findings_resource_urns_gin_idx ON findings USING GIN (resource_urns_json)`,
	`CREATE INDEX IF NOT EXISTS findings_event_ids_gin_idx ON findings USING GIN (event_ids_json)`,
	`CREATE INDEX IF NOT EXISTS findings_observed_policy_ids_gin_idx ON findings USING GIN (observed_policy_ids_json)`,
	`CREATE INDEX IF NOT EXISTS findings_control_refs_gin_idx ON findings USING GIN (control_refs_json)`,
}

// UpsertFinding persists one normalized finding in the current-state store.
func (s *Store) UpsertFinding(ctx context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	id := strings.TrimSpace(finding.ID)
	if id == "" {
		return nil, errors.New("finding id is required")
	}
	fingerprint := strings.TrimSpace(finding.Fingerprint)
	if fingerprint == "" {
		return nil, errors.New("finding fingerprint is required")
	}
	tenantID := strings.TrimSpace(finding.TenantID)
	if tenantID == "" {
		return nil, errors.New("finding tenant id is required")
	}
	runtimeID := strings.TrimSpace(finding.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("finding runtime id is required")
	}
	ruleID := strings.TrimSpace(finding.RuleID)
	if ruleID == "" {
		return nil, errors.New("finding rule id is required")
	}
	title := strings.TrimSpace(finding.Title)
	if title == "" {
		return nil, errors.New("finding title is required")
	}
	severity := strings.TrimSpace(finding.Severity)
	if severity == "" {
		return nil, errors.New("finding severity is required")
	}
	status := strings.TrimSpace(finding.Status)
	if status == "" {
		return nil, errors.New("finding status is required")
	}
	summary := strings.TrimSpace(finding.Summary)
	if summary == "" {
		return nil, errors.New("finding summary is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	resourceURNsJSON, err := findingStringsJSON(finding.ResourceURNs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding resource urns: %w", err)
	}
	eventIDsJSON, err := findingStringsJSON(finding.EventIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding event ids: %w", err)
	}
	observedPolicyIDsJSON, err := findingStringsJSON(finding.ObservedPolicyIDs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding observed policy ids: %w", err)
	}
	controlRefsJSON, err := findingControlRefsJSON(finding.ControlRefs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding control refs: %w", err)
	}
	attributesJSON, err := findingAttributesJSON(finding.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding attributes: %w", err)
	}
	policyID := strings.TrimSpace(finding.PolicyID)
	policyName := strings.TrimSpace(finding.PolicyName)
	checkID := strings.TrimSpace(finding.CheckID)
	checkName := strings.TrimSpace(finding.CheckName)
	assignee := strings.TrimSpace(finding.Assignee)
	statusReason := strings.TrimSpace(finding.StatusReason)
	var statusUpdatedAt any
	if !finding.StatusUpdatedAt.IsZero() {
		statusUpdatedAt = finding.StatusUpdatedAt.UTC()
	}
	firstObservedAt := finding.FirstObservedAt.UTC()
	lastObservedAt := finding.LastObservedAt.UTC()
	if firstObservedAt.IsZero() {
		firstObservedAt = lastObservedAt
	}
	if lastObservedAt.IsZero() {
		lastObservedAt = firstObservedAt
	}
	var stored findingRow
	if err := s.db.QueryRowContext(ctx, `
INSERT INTO findings (
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json, event_ids_json, observed_policy_ids_json, control_refs_json, attributes_json,
  policy_id, policy_name, check_id, check_name, assignee, status_reason, status_updated_at,
  first_observed_at, last_observed_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb, $15, $16, $17, $18, $19, $20, $21, $22, $23)
ON CONFLICT (id)
DO UPDATE SET
  fingerprint = EXCLUDED.fingerprint,
  tenant_id = EXCLUDED.tenant_id,
  runtime_id = EXCLUDED.runtime_id,
  rule_id = EXCLUDED.rule_id,
  title = EXCLUDED.title,
  severity = EXCLUDED.severity,
  status = CASE
    WHEN findings.status IN ('resolved', 'suppressed') AND EXCLUDED.status = 'open' THEN findings.status
    ELSE EXCLUDED.status
  END,
  summary = EXCLUDED.summary,
  resource_urns_json = EXCLUDED.resource_urns_json,
  event_ids_json = EXCLUDED.event_ids_json,
  observed_policy_ids_json = EXCLUDED.observed_policy_ids_json,
  control_refs_json = EXCLUDED.control_refs_json,
  attributes_json = EXCLUDED.attributes_json,
  policy_id = EXCLUDED.policy_id,
  policy_name = EXCLUDED.policy_name,
  check_id = EXCLUDED.check_id,
  check_name = EXCLUDED.check_name,
  assignee = CASE
    WHEN findings.assignee <> '' AND EXCLUDED.assignee = '' THEN findings.assignee
    ELSE EXCLUDED.assignee
  END,
  status_reason = CASE
    WHEN findings.status IN ('resolved', 'suppressed') AND EXCLUDED.status = 'open' THEN findings.status_reason
    ELSE EXCLUDED.status_reason
  END,
  status_updated_at = CASE
    WHEN findings.status IN ('resolved', 'suppressed') AND EXCLUDED.status = 'open' THEN findings.status_updated_at
    ELSE EXCLUDED.status_updated_at
  END,
  first_observed_at = LEAST(findings.first_observed_at, EXCLUDED.first_observed_at),
  last_observed_at = GREATEST(findings.last_observed_at, EXCLUDED.last_observed_at),
  updated_at = NOW()
RETURNING
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, observed_policy_ids_json::text, control_refs_json::text,
  policy_id, policy_name, check_id, check_name, attributes_json::text, assignee, status_reason, status_updated_at,
  first_observed_at, last_observed_at`,
		id,
		fingerprint,
		tenantID,
		runtimeID,
		ruleID,
		title,
		severity,
		status,
		summary,
		resourceURNsJSON,
		eventIDsJSON,
		observedPolicyIDsJSON,
		controlRefsJSON,
		attributesJSON,
		policyID,
		policyName,
		checkID,
		checkName,
		assignee,
		statusReason,
		statusUpdatedAt,
		firstObservedAt,
		lastObservedAt,
	).Scan(
		&stored.ID,
		&stored.Fingerprint,
		&stored.TenantID,
		&stored.RuntimeID,
		&stored.RuleID,
		&stored.Title,
		&stored.Severity,
		&stored.Status,
		&stored.Summary,
		&stored.ResourceURNsJSON,
		&stored.EventIDsJSON,
		&stored.ObservedPolicyIDsJSON,
		&stored.ControlRefsJSON,
		&stored.PolicyID,
		&stored.PolicyName,
		&stored.CheckID,
		&stored.CheckName,
		&stored.AttributesJSON,
		&stored.Assignee,
		&stored.StatusReason,
		&stored.StatusUpdatedAt,
		&stored.FirstObservedAt,
		&stored.LastObservedAt,
	); err != nil {
		return nil, fmt.Errorf("upsert finding %q: %w", id, err)
	}
	return stored.record()
}

// ListFindings loads persisted findings for one runtime.
func (s *Store) ListFindings(ctx context.Context, request ports.ListFindingsRequest) (_ []*ports.FindingRecord, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query findings for runtime %q: %w", strings.TrimSpace(request.RuntimeID), err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close findings rows: %w", closeErr)
		}
	}()

	findings := []*ports.FindingRecord{}
	for rows.Next() {
		var row findingRow
		if err := rows.Scan(
			&row.ID,
			&row.Fingerprint,
			&row.TenantID,
			&row.RuntimeID,
			&row.RuleID,
			&row.Title,
			&row.Severity,
			&row.Status,
			&row.Summary,
			&row.ResourceURNsJSON,
			&row.EventIDsJSON,
			&row.ObservedPolicyIDsJSON,
			&row.ControlRefsJSON,
			&row.PolicyID,
			&row.PolicyName,
			&row.CheckID,
			&row.CheckName,
			&row.AttributesJSON,
			&row.Assignee,
			&row.StatusReason,
			&row.StatusUpdatedAt,
			&row.FirstObservedAt,
			&row.LastObservedAt,
		); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		record, err := row.record()
		if err != nil {
			return nil, err
		}
		findings = append(findings, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate findings rows: %w", err)
	}
	return findings, nil
}

// GetFinding loads one persisted finding by durable identifier.
func (s *Store) GetFinding(ctx context.Context, id string) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(id)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	var row findingRow
	if err := s.db.QueryRowContext(ctx, `
SELECT
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, observed_policy_ids_json::text, control_refs_json::text,
  policy_id, policy_name, check_id, check_name, attributes_json::text, assignee, status_reason, status_updated_at,
  first_observed_at, last_observed_at
FROM findings
WHERE id = $1`,
		findingID,
	).Scan(
		&row.ID,
		&row.Fingerprint,
		&row.TenantID,
		&row.RuntimeID,
		&row.RuleID,
		&row.Title,
		&row.Severity,
		&row.Status,
		&row.Summary,
		&row.ResourceURNsJSON,
		&row.EventIDsJSON,
		&row.ObservedPolicyIDsJSON,
		&row.ControlRefsJSON,
		&row.PolicyID,
		&row.PolicyName,
		&row.CheckID,
		&row.CheckName,
		&row.AttributesJSON,
		&row.Assignee,
		&row.StatusReason,
		&row.StatusUpdatedAt,
		&row.FirstObservedAt,
		&row.LastObservedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("query finding %q: %w", findingID, err)
	}
	return row.record()
}

// UpdateFindingStatus mutates one persisted finding lifecycle status.
func (s *Store) UpdateFindingStatus(ctx context.Context, request ports.FindingStatusUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	status := strings.TrimSpace(request.Status)
	if status == "" {
		return nil, errors.New("finding status is required")
	}
	statusReason := strings.TrimSpace(request.Reason)
	updatedAt := request.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}
	var row findingRow
	if err := s.db.QueryRowContext(ctx, `
UPDATE findings
SET status = $2, status_reason = $3, status_updated_at = $4, updated_at = NOW()
WHERE id = $1
RETURNING
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, observed_policy_ids_json::text, control_refs_json::text,
  policy_id, policy_name, check_id, check_name, attributes_json::text, assignee, status_reason, status_updated_at,
  first_observed_at, last_observed_at`,
		findingID,
		status,
		statusReason,
		updatedAt,
	).Scan(
		&row.ID,
		&row.Fingerprint,
		&row.TenantID,
		&row.RuntimeID,
		&row.RuleID,
		&row.Title,
		&row.Severity,
		&row.Status,
		&row.Summary,
		&row.ResourceURNsJSON,
		&row.EventIDsJSON,
		&row.ObservedPolicyIDsJSON,
		&row.ControlRefsJSON,
		&row.PolicyID,
		&row.PolicyName,
		&row.CheckID,
		&row.CheckName,
		&row.AttributesJSON,
		&row.Assignee,
		&row.StatusReason,
		&row.StatusUpdatedAt,
		&row.FirstObservedAt,
		&row.LastObservedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("update finding %q status: %w", findingID, err)
	}
	return row.record()
}

// UpdateFindingAssignee updates or clears one persisted finding assignee.
func (s *Store) UpdateFindingAssignee(ctx context.Context, request ports.FindingAssigneeUpdate) (*ports.FindingRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	findingID := strings.TrimSpace(request.FindingID)
	if findingID == "" {
		return nil, errors.New("finding id is required")
	}
	var row findingRow
	if err := s.db.QueryRowContext(ctx, `
UPDATE findings
SET assignee = $2, updated_at = NOW()
WHERE id = $1
RETURNING
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, observed_policy_ids_json::text, control_refs_json::text,
  policy_id, policy_name, check_id, check_name, attributes_json::text, assignee, status_reason, status_updated_at,
  first_observed_at, last_observed_at`,
		findingID,
		strings.TrimSpace(request.Assignee),
	).Scan(
		&row.ID,
		&row.Fingerprint,
		&row.TenantID,
		&row.RuntimeID,
		&row.RuleID,
		&row.Title,
		&row.Severity,
		&row.Status,
		&row.Summary,
		&row.ResourceURNsJSON,
		&row.EventIDsJSON,
		&row.ObservedPolicyIDsJSON,
		&row.ControlRefsJSON,
		&row.PolicyID,
		&row.PolicyName,
		&row.CheckID,
		&row.CheckName,
		&row.AttributesJSON,
		&row.Assignee,
		&row.StatusReason,
		&row.StatusUpdatedAt,
		&row.FirstObservedAt,
		&row.LastObservedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ports.ErrFindingNotFound
		}
		return nil, fmt.Errorf("update finding %q assignee: %w", findingID, err)
	}
	return row.record()
}

func findingListQuery(request ports.ListFindingsRequest) (string, []any, error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return "", nil, errors.New("finding runtime id is required")
	}
	clauses := []string{"runtime_id = $1"}
	args := []any{runtimeID}
	addFindingFilter(&clauses, &args, "id", request.FindingID)
	addFindingFilter(&clauses, &args, "rule_id", request.RuleID)
	addFindingFilter(&clauses, &args, "severity", request.Severity)
	addFindingFilter(&clauses, &args, "status", request.Status)
	addFindingFilter(&clauses, &args, "policy_id", request.PolicyID)
	if err := addFindingArrayContainsFilter(&clauses, &args, "resource_urns_json", request.ResourceURN); err != nil {
		return "", nil, err
	}
	if err := addFindingArrayContainsFilter(&clauses, &args, "event_ids_json", request.EventID); err != nil {
		return "", nil, err
	}
	query := `
SELECT
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, observed_policy_ids_json::text, control_refs_json::text,
  policy_id, policy_name, check_id, check_name, attributes_json::text, assignee, status_reason, status_updated_at,
  first_observed_at, last_observed_at
FROM findings
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY last_observed_at DESC, id`
	if request.Limit != 0 {
		args = append(args, int64(request.Limit))
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return query, args, nil
}

func (s *Store) ensureFindingTables(ctx context.Context) error {
	for _, statement := range ensureFindingStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure findings tables: %w", err)
		}
	}
	return nil
}

func findingStringsJSON(values []string) (string, error) {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingAttributesJSON(attributes map[string]string) (string, error) {
	if len(attributes) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func findingControlRefsJSON(values []ports.FindingControlRef) (string, error) {
	normalized := make([]ports.FindingControlRef, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		frameworkName := strings.TrimSpace(value.FrameworkName)
		controlID := strings.TrimSpace(value.ControlID)
		if frameworkName == "" || controlID == "" {
			continue
		}
		key := frameworkName + "|" + controlID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, ports.FindingControlRef{
			FrameworkName: frameworkName,
			ControlID:     controlID,
		})
	}
	if len(normalized) == 0 {
		return `[]`, nil
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func addFindingFilter(clauses *[]string, args *[]any, column string, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return
	}
	*args = append(*args, trimmed)
	*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
}

func addFindingArrayContainsFilter(clauses *[]string, args *[]any, column string, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	payload, err := findingStringsJSON([]string{trimmed})
	if err != nil {
		return fmt.Errorf("marshal %s filter: %w", column, err)
	}
	*args = append(*args, payload)
	*clauses = append(*clauses, fmt.Sprintf("%s @> $%d::jsonb", column, len(*args)))
	return nil
}

type findingRow struct {
	ID                    string
	Fingerprint           string
	TenantID              string
	RuntimeID             string
	RuleID                string
	Title                 string
	Severity              string
	Status                string
	Summary               string
	ResourceURNsJSON      string
	EventIDsJSON          string
	ObservedPolicyIDsJSON string
	ControlRefsJSON       string
	PolicyID              string
	PolicyName            string
	CheckID               string
	CheckName             string
	AttributesJSON        string
	Assignee              string
	StatusReason          string
	StatusUpdatedAt       sql.NullTime
	FirstObservedAt       time.Time
	LastObservedAt        time.Time
}

func (r findingRow) record() (*ports.FindingRecord, error) {
	resourceURNs := []string{}
	if err := json.Unmarshal([]byte(r.ResourceURNsJSON), &resourceURNs); err != nil {
		return nil, fmt.Errorf("decode finding resource urns: %w", err)
	}
	eventIDs := []string{}
	if err := json.Unmarshal([]byte(r.EventIDsJSON), &eventIDs); err != nil {
		return nil, fmt.Errorf("decode finding event ids: %w", err)
	}
	observedPolicyIDs := []string{}
	if err := json.Unmarshal([]byte(r.ObservedPolicyIDsJSON), &observedPolicyIDs); err != nil {
		return nil, fmt.Errorf("decode finding observed policy ids: %w", err)
	}
	controlRefs := []ports.FindingControlRef{}
	if err := json.Unmarshal([]byte(r.ControlRefsJSON), &controlRefs); err != nil {
		return nil, fmt.Errorf("decode finding control refs: %w", err)
	}
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(r.AttributesJSON), &attributes); err != nil {
		return nil, fmt.Errorf("decode finding attributes: %w", err)
	}
	return &ports.FindingRecord{
		ID:                r.ID,
		Fingerprint:       r.Fingerprint,
		TenantID:          r.TenantID,
		RuntimeID:         r.RuntimeID,
		RuleID:            r.RuleID,
		Title:             r.Title,
		Severity:          r.Severity,
		Status:            r.Status,
		Summary:           r.Summary,
		ResourceURNs:      resourceURNs,
		EventIDs:          eventIDs,
		ObservedPolicyIDs: observedPolicyIDs,
		PolicyID:          r.PolicyID,
		PolicyName:        r.PolicyName,
		CheckID:           r.CheckID,
		CheckName:         r.CheckName,
		ControlRefs:       controlRefs,
		Attributes:        attributes,
		Assignee:          r.Assignee,
		StatusReason:      r.StatusReason,
		FirstObservedAt:   r.FirstObservedAt.UTC(),
		LastObservedAt:    r.LastObservedAt.UTC(),
		StatusUpdatedAt:   findingStatusUpdatedAt(r.StatusUpdatedAt),
	}, nil
}

func findingStatusUpdatedAt(value sql.NullTime) time.Time {
	if !value.Valid || value.Time.IsZero() {
		return time.Time{}
	}
	return value.Time.UTC()
}
