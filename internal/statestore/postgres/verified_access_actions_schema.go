package postgres

import "context"

var ensureVerifiedAccessActionStatements = []string{
	`CREATE TABLE IF NOT EXISTS verified_access_actions (
  tenant_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  status TEXT NOT NULL,
  record_digest TEXT NOT NULL,
  last_transition_digest TEXT NOT NULL,
  record_json JSONB NOT NULL,
  proposed_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, action_id),
  UNIQUE (tenant_id, idempotency_key)
)`,
	`CREATE INDEX IF NOT EXISTS verified_access_actions_tenant_status_updated_idx
ON verified_access_actions (tenant_id, status, updated_at DESC, action_id)`,
	`CREATE TABLE IF NOT EXISTS verified_access_action_transitions (
  tenant_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  transition_id TEXT NOT NULL,
  sequence BIGINT GENERATED ALWAYS AS IDENTITY,
  transition_digest TEXT NOT NULL,
  previous_transition_digest TEXT NOT NULL DEFAULT '',
  record_digest TEXT NOT NULL,
  from_status TEXT NOT NULL DEFAULT '',
  to_status TEXT NOT NULL,
  result_code TEXT NOT NULL,
  transition_json JSONB NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, action_id, transition_id),
  UNIQUE (tenant_id, transition_digest),
  FOREIGN KEY (tenant_id, action_id)
    REFERENCES verified_access_actions (tenant_id, action_id) ON DELETE CASCADE
)`,
	`CREATE INDEX IF NOT EXISTS verified_access_action_transitions_chain_idx
ON verified_access_action_transitions (tenant_id, action_id, sequence)`,
}

func (s *Store) ensureVerifiedAccessActionTables(ctx context.Context) error {
	return s.ensureStatements(
		ctx,
		&s.platform.verifiedAccessAction,
		"verified access actions",
		ensureVerifiedAccessActionStatements,
	)
}
