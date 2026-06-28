package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

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
  decision_event_id TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, discovery_urn)
)`,
	`ALTER TABLE grc_vendor_discovery_decisions ADD COLUMN IF NOT EXISTS decision_event_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE grc_vendor_discovery_decisions ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_discovery_decisions_tenant_source_decision_idx ON grc_vendor_discovery_decisions (tenant_id, source_id, decision, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_discovery_decisions_tenant_decision_idx ON grc_vendor_discovery_decisions (tenant_id, decision, updated_at DESC)`,
	`CREATE TABLE IF NOT EXISTS grc_vendor_discovery_decision_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  discovery_urn TEXT NOT NULL,
  source_id TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  linked_vendor_urn TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  version INTEGER NOT NULL,
  supersedes_event_id TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS grc_vendor_discovery_decision_events_tenant_discovery_version_uidx ON grc_vendor_discovery_decision_events (tenant_id, discovery_urn, version)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_discovery_decision_events_tenant_discovery_idx ON grc_vendor_discovery_decision_events (tenant_id, discovery_urn, version DESC)`,
	`CREATE INDEX IF NOT EXISTS grc_vendor_discovery_decision_events_tenant_source_decision_idx ON grc_vendor_discovery_decision_events (tenant_id, source_id, decision, created_at DESC)`,
}

func grcVendorDiscoveryDecisionAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('grc_vendor_discovery_decision'), hashtext($1))`
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin vendor discovery decision upsert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, grcVendorDiscoveryDecisionAdvisoryLockSQL(), record.TenantID+"\x00"+record.DiscoveryURN); err != nil {
		return nil, fmt.Errorf("lock vendor discovery decision: %w", err)
	}
	var supersedesEventID string
	var previousVersion int
	err = tx.QueryRowContext(ctx, `
SELECT decision_event_id, version
FROM grc_vendor_discovery_decisions
WHERE tenant_id = $1 AND discovery_urn = $2
FOR UPDATE`, record.TenantID, record.DiscoveryURN).Scan(&supersedesEventID, &previousVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("load previous vendor discovery decision: %w", err)
	}
	version := previousVersion + 1
	if version <= 0 {
		version = 1
	}
	eventID := strings.TrimSpace(record.DecisionEventID)
	if eventID == "" {
		eventID = grcVendorDiscoveryDecisionEventID(record, version)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO grc_vendor_discovery_decision_events (
  id, tenant_id, discovery_urn, source_id, decision, reason, linked_vendor_urn,
  updated_by, attributes_json, version, supersedes_event_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)`,
		eventID, record.TenantID, record.DiscoveryURN, record.SourceID, record.Decision, record.Reason,
		record.LinkedVendorURN, record.UpdatedBy, string(attrs), version, supersedesEventID); err != nil {
		return nil, fmt.Errorf("insert vendor discovery decision event: %w", err)
	}
	row := tx.QueryRowContext(ctx, `
INSERT INTO grc_vendor_discovery_decisions (
  tenant_id, discovery_urn, source_id, decision, reason, linked_vendor_urn,
  decision_event_id, version, updated_by, attributes_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
ON CONFLICT (tenant_id, discovery_urn)
DO UPDATE SET source_id = EXCLUDED.source_id,
              decision = EXCLUDED.decision,
              reason = EXCLUDED.reason,
              linked_vendor_urn = EXCLUDED.linked_vendor_urn,
              decision_event_id = EXCLUDED.decision_event_id,
              version = EXCLUDED.version,
              updated_by = EXCLUDED.updated_by,
              attributes_json = EXCLUDED.attributes_json,
              updated_at = NOW()
RETURNING tenant_id, discovery_urn, source_id, decision_event_id, version, decision, reason, linked_vendor_urn, updated_by, attributes_json::text, created_at, updated_at`,
		record.TenantID, record.DiscoveryURN, record.SourceID, record.Decision, record.Reason,
		record.LinkedVendorURN, eventID, version, record.UpdatedBy, string(attrs))
	result, err := scanGRCVendorDiscoveryDecision(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit vendor discovery decision upsert: %w", err)
	}
	return result, nil
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
SELECT tenant_id, discovery_urn, source_id, decision_event_id, version, decision, reason, linked_vendor_urn, updated_by, attributes_json::text, created_at, updated_at
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

func (s *Store) ListGRCVendorDiscoveryDecisionEvents(ctx context.Context, filter ports.GRCVendorDiscoveryDecisionEventFilter) ([]*ports.GRCVendorDiscoveryDecisionEventRecord, error) {
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
SELECT id, tenant_id, discovery_urn, source_id, decision, reason, linked_vendor_urn, updated_by, attributes_json::text, version, supersedes_event_id, created_at
FROM grc_vendor_discovery_decision_events
WHERE %s
ORDER BY created_at DESC, version DESC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list vendor discovery decision events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.GRCVendorDiscoveryDecisionEventRecord{}
	for rows.Next() {
		record, err := scanGRCVendorDiscoveryDecisionEvent(rows)
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
	if err := row.Scan(&record.TenantID, &record.DiscoveryURN, &record.SourceID, &record.DecisionEventID, &record.Version, &record.Decision, &record.Reason, &record.LinkedVendorURN, &record.UpdatedBy, &attrs, &record.CreatedAt, &record.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	return record, nil
}

func scanGRCVendorDiscoveryDecisionEvent(row scanner) (*ports.GRCVendorDiscoveryDecisionEventRecord, error) {
	record := &ports.GRCVendorDiscoveryDecisionEventRecord{}
	var attrs string
	if err := row.Scan(&record.ID, &record.TenantID, &record.DiscoveryURN, &record.SourceID, &record.Decision, &record.Reason, &record.LinkedVendorURN, &record.UpdatedBy, &attrs, &record.Version, &record.SupersedesEventID, &record.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, err
	}
	record.Attributes = map[string]string{}
	_ = json.Unmarshal([]byte(attrs), &record.Attributes)
	return record, nil
}

func grcVendorDiscoveryDecisionEventID(record ports.GRCVendorDiscoveryDecisionRecord, version int) string {
	seed := strings.Join([]string{
		"grc_vendor_discovery_decision_event",
		record.TenantID,
		record.DiscoveryURN,
		record.SourceID,
		record.Decision,
		record.LinkedVendorURN,
		fmt.Sprint(version),
		time.Now().UTC().Format(time.RFC3339Nano),
	}, "\x00")
	sum := sha256.Sum256([]byte(seed))
	return "grc-vendor-decision-" + hex.EncodeToString(sum[:12])
}
