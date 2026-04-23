package postgres

import (
	"context"
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
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  first_observed_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS findings_runtime_rule_idx ON findings (runtime_id, rule_id)`,
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
	attributesJSON, err := findingAttributesJSON(finding.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal finding attributes: %w", err)
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
  resource_urns_json, event_ids_json, attributes_json, first_observed_at, last_observed_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13, $14)
ON CONFLICT (id)
DO UPDATE SET
  fingerprint = EXCLUDED.fingerprint,
  tenant_id = EXCLUDED.tenant_id,
  runtime_id = EXCLUDED.runtime_id,
  rule_id = EXCLUDED.rule_id,
  title = EXCLUDED.title,
  severity = EXCLUDED.severity,
  status = EXCLUDED.status,
  summary = EXCLUDED.summary,
  resource_urns_json = EXCLUDED.resource_urns_json,
  event_ids_json = EXCLUDED.event_ids_json,
  attributes_json = EXCLUDED.attributes_json,
  first_observed_at = LEAST(findings.first_observed_at, EXCLUDED.first_observed_at),
  last_observed_at = GREATEST(findings.last_observed_at, EXCLUDED.last_observed_at),
  updated_at = NOW()
RETURNING
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, attributes_json::text, first_observed_at, last_observed_at`,
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
		attributesJSON,
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
		&stored.AttributesJSON,
		&stored.FirstObservedAt,
		&stored.LastObservedAt,
	); err != nil {
		return nil, fmt.Errorf("upsert finding %q: %w", id, err)
	}
	return stored.record()
}

// ListFindings loads persisted findings for one runtime.
func (s *Store) ListFindings(ctx context.Context, request ports.ListFindingsRequest) (_ []*ports.FindingRecord, err error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("finding runtime id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT
  id, fingerprint, tenant_id, runtime_id, rule_id, title, severity, status, summary,
  resource_urns_json::text, event_ids_json::text, attributes_json::text, first_observed_at, last_observed_at
FROM findings
WHERE runtime_id = $1
ORDER BY last_observed_at DESC, id`, runtimeID)
	if err != nil {
		return nil, fmt.Errorf("query findings for runtime %q: %w", runtimeID, err)
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
			&row.AttributesJSON,
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

type findingRow struct {
	ID               string
	Fingerprint      string
	TenantID         string
	RuntimeID        string
	RuleID           string
	Title            string
	Severity         string
	Status           string
	Summary          string
	ResourceURNsJSON string
	EventIDsJSON     string
	AttributesJSON   string
	FirstObservedAt  time.Time
	LastObservedAt   time.Time
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
	attributes := map[string]string{}
	if err := json.Unmarshal([]byte(r.AttributesJSON), &attributes); err != nil {
		return nil, fmt.Errorf("decode finding attributes: %w", err)
	}
	return &ports.FindingRecord{
		ID:              r.ID,
		Fingerprint:     r.Fingerprint,
		TenantID:        r.TenantID,
		RuntimeID:       r.RuntimeID,
		RuleID:          r.RuleID,
		Title:           r.Title,
		Severity:        r.Severity,
		Status:          r.Status,
		Summary:         r.Summary,
		ResourceURNs:    resourceURNs,
		EventIDs:        eventIDs,
		Attributes:      attributes,
		FirstObservedAt: r.FirstObservedAt.UTC(),
		LastObservedAt:  r.LastObservedAt.UTC(),
	}, nil
}
