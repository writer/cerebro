package postgres

import "context"

var ensureSourceTrustStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_source_check_snapshots (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, objective_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, source_id TEXT NOT NULL, runtime_id TEXT NOT NULL DEFAULT '',
  dimension_id TEXT NOT NULL, support_state TEXT NOT NULL, health_state TEXT NOT NULL,
  assessment_state TEXT NOT NULL, certification_tier TEXT NOT NULL,
  certification_receipt_id TEXT NOT NULL DEFAULT '', certification_revision_json JSONB,
  proof_revisions_json JSONB NOT NULL, snapshot_hash TEXT NOT NULL, content_digest TEXT NOT NULL,
  snapshot_json JSONB NOT NULL, checked_at TIMESTAMPTZ NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, run_id, objective_id, snapshot_id),
  UNIQUE (tenant_id, run_id, objective_id, source_id, dimension_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_source_checks_source_dimension_idx ON compliance_source_check_snapshots (tenant_id, source_id, dimension_id, checked_at DESC)`,
	`CREATE TABLE IF NOT EXISTS compliance_objective_source_assessments (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, objective_id TEXT NOT NULL,
  assessment_id TEXT NOT NULL, expected_check_count BIGINT NOT NULL,
  observed_check_count BIGINT NOT NULL, complete BOOLEAN NOT NULL,
  requirement_revision_json JSONB NOT NULL, expected_source_check_ids_json JSONB NOT NULL,
  source_state TEXT NOT NULL, content_digest TEXT NOT NULL,
  assessment_json JSONB NOT NULL, assessed_at TIMESTAMPTZ NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
  CHECK (expected_check_count >= 0 AND observed_check_count >= 0),
  CHECK (NOT complete OR expected_check_count = observed_check_count),
  PRIMARY KEY (tenant_id, run_id, objective_id),
  UNIQUE (tenant_id, assessment_id)
)`,
	`ALTER TABLE compliance_objective_source_assessments ADD COLUMN IF NOT EXISTS requirement_revision_json JSONB NOT NULL DEFAULT '{}'::jsonb`,
	`ALTER TABLE compliance_objective_source_assessments ADD COLUMN IF NOT EXISTS expected_source_check_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`CREATE TABLE IF NOT EXISTS compliance_objective_source_check_refs (
  tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, objective_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, run_id, objective_id, snapshot_id),
  FOREIGN KEY (tenant_id, run_id, objective_id) REFERENCES compliance_objective_source_assessments (tenant_id, run_id, objective_id),
  FOREIGN KEY (tenant_id, run_id, objective_id, snapshot_id) REFERENCES compliance_source_check_snapshots (tenant_id, run_id, objective_id, snapshot_id)
)`,
	`CREATE TABLE IF NOT EXISTS compliance_source_trust_event_receipts (
  tenant_id TEXT NOT NULL, event_id TEXT NOT NULL, event_digest TEXT NOT NULL,
  aggregate_type TEXT NOT NULL, aggregate_id TEXT NOT NULL, aggregate_version BIGINT NOT NULL,
  operation TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, event_id)
)`,
	`ALTER TABLE compliance_source_trust_event_receipts ADD COLUMN IF NOT EXISTS event_digest TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS compliance_source_trust_receipts_aggregate_idx ON compliance_source_trust_event_receipts (tenant_id, aggregate_type, aggregate_id, aggregate_version)`,
}

func (s *Store) ensureSourceTrustTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.sourceTrust, "compliance source trust", ensureSourceTrustStatements)
}
