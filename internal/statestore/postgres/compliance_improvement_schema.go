package postgres

import "context"

var ensureComplianceImprovementStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_improvement_runs (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  program_id TEXT NOT NULL,
  state TEXT NOT NULL,
  decision_owner TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  current_revision_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  run_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, program_id, idempotency_key)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_improvement_runs_tenant_state_updated_idx ON compliance_improvement_runs (tenant_id, state, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_improvement_revisions (
  tenant_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  content_digest TEXT NOT NULL,
  predecessor_id TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  revision_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, run_id, revision_id),
  UNIQUE (tenant_id, run_id, version),
  FOREIGN KEY (tenant_id, run_id) REFERENCES compliance_improvement_runs (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS compliance_improvement_revisions_tenant_run_version_idx ON compliance_improvement_revisions (tenant_id, run_id, version DESC)`,
	`CREATE TABLE IF NOT EXISTS compliance_improvement_team_outbox (
  tenant_id TEXT NOT NULL,
  outbox_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  proposal_digest TEXT NOT NULL,
  update_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  delivered_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, outbox_id),
  UNIQUE (tenant_id, idempotency_key)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_improvement_team_outbox_pending_idx ON compliance_improvement_team_outbox (tenant_id, created_at, outbox_id) WHERE delivered_at IS NULL`,
}

func (s *Store) ensureComplianceImprovementTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.complianceImprovement, "compliance improvement", ensureComplianceImprovementStatements)
}
