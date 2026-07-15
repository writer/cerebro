package postgres

import "context"

var ensureComplianceReviewStatements = []string{
	`CREATE TABLE IF NOT EXISTS compliance_reviews (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  body_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_reviews_tenant_updated_idx ON compliance_reviews (tenant_id, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_review_revisions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  review_id TEXT NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  body_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, review_id, sequence),
  FOREIGN KEY (tenant_id, review_id) REFERENCES compliance_reviews (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS compliance_review_revisions_tenant_review_idx ON compliance_review_revisions (tenant_id, review_id, sequence)`,
	`CREATE TABLE IF NOT EXISTS compliance_risks (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  body_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_risks_tenant_updated_idx ON compliance_risks (tenant_id, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_exceptions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  body_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_exceptions_tenant_updated_idx ON compliance_exceptions (tenant_id, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_work_items (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  body_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_work_items_tenant_updated_idx ON compliance_work_items (tenant_id, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_work_occurrences (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  work_item_id TEXT NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  body_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, work_item_id, sequence),
  FOREIGN KEY (tenant_id, work_item_id) REFERENCES compliance_work_items (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS compliance_work_occurrences_tenant_item_idx ON compliance_work_occurrences (tenant_id, work_item_id, sequence)`,
	`CREATE TABLE IF NOT EXISTS compliance_work_actions (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  work_item_id TEXT NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  body_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, work_item_id, sequence),
  FOREIGN KEY (tenant_id, work_item_id) REFERENCES compliance_work_items (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS compliance_work_actions_tenant_item_idx ON compliance_work_actions (tenant_id, work_item_id, sequence)`,
	`CREATE TABLE IF NOT EXISTS compliance_remediation_plans (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  body_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_remediation_plans_tenant_updated_idx ON compliance_remediation_plans (tenant_id, updated_at DESC, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_remediation_milestones (
  tenant_id TEXT NOT NULL,
  id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  plan_version BIGINT NOT NULL CHECK (plan_version > 0),
  body_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, plan_id, id),
  FOREIGN KEY (tenant_id, plan_id) REFERENCES compliance_remediation_plans (tenant_id, id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS compliance_remediation_milestones_tenant_plan_idx ON compliance_remediation_milestones (tenant_id, plan_id, id)`,
	`CREATE TABLE IF NOT EXISTS compliance_review_event_receipts (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version BIGINT NOT NULL CHECK (aggregate_version > 0),
  payload_hash TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, event_id)
)`,
	`CREATE INDEX IF NOT EXISTS compliance_review_event_receipts_tenant_aggregate_idx ON compliance_review_event_receipts (tenant_id, event_kind, aggregate_id, aggregate_version)`,
}

func (s *Store) ensureComplianceReviewTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.grc.complianceReview, "compliance review projection", ensureComplianceReviewStatements)
}
