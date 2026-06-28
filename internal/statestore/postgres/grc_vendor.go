package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureGRCVendorDiscoveryDecisionStatements = []string{
	`CREATE TABLE IF NOT EXISTS grc_vendor_discovery_decisions (
  tenant_id TEXT NOT NULL,
  discovery_urn TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  linked_vendor_urn TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, discovery_urn)
)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_discovery_decisions_tenant_source_decision_idx ON grc_vendor_discovery_decisions (tenant_id, source_id, decision, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_discovery_decisions_tenant_decision_idx ON grc_vendor_discovery_decisions (tenant_id, decision, updated_at DESC)`,
}

func (s *Store) UpsertGRCVendorDiscoveryDecision(ctx context.Context, record ports.GRCVendorDiscoveryDecisionRecord) (*ports.GRCVendorDiscoveryDecisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCVendorDiscoveryDecisionTables(ctx); err != nil {
		return nil, err
	}
	record.TenantID = strings.TrimSpace(record.TenantID)
	record.DiscoveryURN = strings.TrimSpace(record.DiscoveryURN)
	record.SourceID = strings.TrimSpace(record.SourceID)
	record.Decision = strings.TrimSpace(record.Decision)
	record.Reason = strings.TrimSpace(record.Reason)
	record.LinkedVendorURN = strings.TrimSpace(record.LinkedVendorURN)
	record.UpdatedBy = strings.TrimSpace(record.UpdatedBy)
	if record.TenantID == "" || record.DiscoveryURN == "" || record.Decision == "" {
		return nil, errors.New("tenant_id, discovery_urn, and decision are required")
	}
	if !ports.IsGRCVendorDiscoveryDecision(record.Decision) {
		return nil, errors.New("decision is invalid")
	}
	if record.Decision == ports.GRCVendorDiscoveryDecisionLinked && record.LinkedVendorURN == "" {
		return nil, errors.New("linked_vendor_urn is required for linked decisions")
	}
	attrs, err := json.Marshal(emptyStringMap(record.Attributes))
	if err != nil {
		return nil, fmt.Errorf("marshal vendor discovery decision attributes: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO grc_vendor_discovery_decisions (tenant_id, discovery_urn, source_id, decision, reason, linked_vendor_urn, updated_by, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
ON CONFLICT (tenant_id, discovery_urn)
DO UPDATE SET source_id = EXCLUDED.source_id,
              decision = EXCLUDED.decision,
              reason = EXCLUDED.reason,
              linked_vendor_urn = EXCLUDED.linked_vendor_urn,
              updated_by = EXCLUDED.updated_by,
              attributes_json = EXCLUDED.attributes_json,
              updated_at = NOW()
RETURNING tenant_id, discovery_urn, source_id, decision, reason, linked_vendor_urn, updated_by, attributes_json::text, created_at, updated_at`,
		record.TenantID, record.DiscoveryURN, record.SourceID, record.Decision, record.Reason, record.LinkedVendorURN, record.UpdatedBy, string(attrs))
	return scanGRCVendorDiscoveryDecision(row)
}

func (s *Store) ListGRCVendorDiscoveryDecisions(ctx context.Context, filter ports.GRCVendorDiscoveryDecisionFilter) ([]*ports.GRCVendorDiscoveryDecisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureGRCVendorDiscoveryDecisionTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	addTextFilter(&clauses, &args, "tenant_id", filter.TenantID)
	addTextFilter(&clauses, &args, "source_id", filter.SourceID)
	addTextFilter(&clauses, &args, "decision", filter.Decision)
	addStringInFilter(&clauses, &args, "discovery_urn", filter.DiscoveryURNs)
	limit := filter.Limit
	if limit == 0 || limit > 500 {
		limit = 500
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are assembled from fixed column predicates and values remain parameterized.
	query := fmt.Sprintf(`
SELECT tenant_id, discovery_urn, source_id, decision, reason, linked_vendor_urn, updated_by, attributes_json::text, created_at, updated_at
FROM grc_vendor_discovery_decisions
WHERE %s
ORDER BY updated_at DESC, discovery_urn ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vendor discovery decisions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCVendorDiscoveryDecisionRecord{}
	for rows.Next() {
		record, err := scanGRCVendorDiscoveryDecision(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) ensureGRCVendorDiscoveryDecisionTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.vendorDiscovery, "grc vendor discovery decision", ensureGRCVendorDiscoveryDecisionStatements)
}

func scanGRCVendorDiscoveryDecision(row scanner) (*ports.GRCVendorDiscoveryDecisionRecord, error) {
	record := &ports.GRCVendorDiscoveryDecisionRecord{}
	var attrs string
	if err := row.Scan(&record.TenantID, &record.DiscoveryURN, &record.SourceID, &record.Decision, &record.Reason, &record.LinkedVendorURN, &record.UpdatedBy, &attrs, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	return record, nil
}
