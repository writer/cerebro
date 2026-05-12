package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var ensureFindingEvidenceStatements = []string{
	`CREATE TABLE IF NOT EXISTS finding_evidence (
  id TEXT PRIMARY KEY,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  claim_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  event_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  graph_root_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  graph_path_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL,
  last_observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finding_evidence_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS graph_path_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb`,
	`ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb`,
	`ALTER TABLE finding_evidence ADD COLUMN IF NOT EXISTS last_observed_at TIMESTAMPTZ`,
	`UPDATE finding_evidence SET last_observed_at = created_at WHERE last_observed_at IS NULL`,
	`ALTER TABLE finding_evidence ALTER COLUMN last_observed_at SET DEFAULT NOW()`,
	`ALTER TABLE finding_evidence ALTER COLUMN last_observed_at SET NOT NULL`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_runtime_idx ON finding_evidence (runtime_id, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_finding_idx ON finding_evidence (finding_id, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_run_idx ON finding_evidence (run_id, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_rule_idx ON finding_evidence (rule_id, created_at DESC)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_claim_ids_gin_idx ON finding_evidence USING GIN (claim_ids_json)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_event_ids_gin_idx ON finding_evidence USING GIN (event_ids_json)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_graph_root_urns_gin_idx ON finding_evidence USING GIN (graph_root_urns_json)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_graph_path_urns_gin_idx ON finding_evidence USING GIN (graph_path_urns_json)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_attributes_gin_idx ON finding_evidence USING GIN (attributes_json)`,
	`CREATE INDEX IF NOT EXISTS finding_evidence_last_observed_idx ON finding_evidence (runtime_id, last_observed_at DESC)`,
}

func findingEvidenceUpsertSQL() string {
	return `
INSERT INTO finding_evidence (
  id, runtime_id, rule_id, finding_id, run_id, claim_ids_json, event_ids_json, graph_root_urns_json, graph_path_urns_json, attributes_json, created_at, last_observed_at, finding_evidence_json
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12, $13::jsonb)
ON CONFLICT (id)
DO UPDATE SET
  runtime_id = EXCLUDED.runtime_id,
  rule_id = EXCLUDED.rule_id,
  finding_id = EXCLUDED.finding_id,
  run_id = EXCLUDED.run_id,
  claim_ids_json = EXCLUDED.claim_ids_json,
  event_ids_json = EXCLUDED.event_ids_json,
  graph_root_urns_json = EXCLUDED.graph_root_urns_json,
  graph_path_urns_json = EXCLUDED.graph_path_urns_json,
  attributes_json = EXCLUDED.attributes_json,
  last_observed_at = GREATEST(finding_evidence.last_observed_at, EXCLUDED.last_observed_at),
  finding_evidence_json = jsonb_set(
    CASE
      WHEN finding_evidence.finding_evidence_json ? 'created_at'
        THEN jsonb_set(EXCLUDED.finding_evidence_json, '{created_at}', finding_evidence.finding_evidence_json->'created_at', true)
      ELSE EXCLUDED.finding_evidence_json
    END,
    '{last_observed_at}',
    to_jsonb(GREATEST(finding_evidence.last_observed_at, EXCLUDED.last_observed_at)),
    true
  ),
  updated_at = NOW()`
}

// PutFindingEvidence upserts one durable finding evidence record.
func (s *Store) PutFindingEvidence(ctx context.Context, evidence *cerebrov1.FindingEvidence) error {
	if evidence == nil {
		return errors.New("finding evidence is required")
	}
	id := strings.TrimSpace(evidence.GetId())
	if id == "" {
		return errors.New("finding evidence id is required")
	}
	runtimeID := strings.TrimSpace(evidence.GetRuntimeId())
	if runtimeID == "" {
		return errors.New("finding evidence runtime id is required")
	}
	ruleID := strings.TrimSpace(evidence.GetRuleId())
	if ruleID == "" {
		return errors.New("finding evidence rule id is required")
	}
	findingID := strings.TrimSpace(evidence.GetFindingId())
	if findingID == "" {
		return errors.New("finding evidence finding id is required")
	}
	runID := strings.TrimSpace(evidence.GetRunId())
	if runID == "" {
		return errors.New("finding evidence run id is required")
	}
	createdAt := evidence.GetCreatedAt()
	if createdAt == nil || createdAt.AsTime().IsZero() {
		return errors.New("finding evidence created_at is required")
	}
	if evidence.GetLastObservedAt() == nil || evidence.GetLastObservedAt().AsTime().IsZero() {
		evidence.LastObservedAt = createdAt
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvidenceTables(ctx); err != nil {
		return err
	}
	claimIDsJSON, err := findingStringsJSON(evidence.GetClaimIds())
	if err != nil {
		return fmt.Errorf("marshal finding evidence claim ids: %w", err)
	}
	eventIDsJSON, err := findingStringsJSON(evidence.GetEventIds())
	if err != nil {
		return fmt.Errorf("marshal finding evidence event ids: %w", err)
	}
	graphRootURNsJSON, err := findingStringsJSON(evidence.GetGraphRootUrns())
	if err != nil {
		return fmt.Errorf("marshal finding evidence graph roots: %w", err)
	}
	graphPathURNsJSON, err := findingStringsJSON(evidence.GetGraphPathUrns())
	if err != nil {
		return fmt.Errorf("marshal finding evidence graph path urns: %w", err)
	}
	attributesJSON, err := findingAttributesJSON(evidence.GetAttributes())
	if err != nil {
		return fmt.Errorf("marshal finding evidence attributes: %w", err)
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("marshal finding evidence: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, findingEvidenceUpsertSQL(),
		id,
		runtimeID,
		ruleID,
		findingID,
		runID,
		claimIDsJSON,
		eventIDsJSON,
		graphRootURNsJSON,
		graphPathURNsJSON,
		attributesJSON,
		evidence.GetCreatedAt().AsTime().UTC(),
		evidence.GetLastObservedAt().AsTime().UTC(),
		string(payload),
	); err != nil {
		return fmt.Errorf("upsert finding evidence %q: %w", id, err)
	}
	return nil
}

// GetFindingEvidence loads one persisted finding evidence record.
func (s *Store) GetFindingEvidence(ctx context.Context, evidenceID string) (*cerebrov1.FindingEvidence, error) {
	id := strings.TrimSpace(evidenceID)
	if id == "" {
		return nil, errors.New("finding evidence id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvidenceTables(ctx); err != nil {
		return nil, err
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, `SELECT finding_evidence_json::text FROM finding_evidence WHERE id = $1`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrFindingEvidenceNotFound, id)
		}
		return nil, fmt.Errorf("query finding evidence %q: %w", id, err)
	}
	evidence := &cerebrov1.FindingEvidence{}
	if err := protojson.Unmarshal([]byte(payload), evidence); err != nil {
		return nil, fmt.Errorf("decode finding evidence %q: %w", id, err)
	}
	return evidence, nil
}

// ListFindingEvidence loads persisted finding evidence for one runtime.
func (s *Store) ListFindingEvidence(ctx context.Context, request ports.ListFindingEvidenceRequest) (_ []*cerebrov1.FindingEvidence, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvidenceTables(ctx); err != nil {
		return nil, err
	}
	query, args, err := findingEvidenceListQuery(request)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query finding evidence for runtime %q: %w", strings.TrimSpace(request.RuntimeID), err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close finding evidence rows: %w", closeErr)
		}
	}()

	evidence := []*cerebrov1.FindingEvidence{}
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan finding evidence row: %w", err)
		}
		record := &cerebrov1.FindingEvidence{}
		if err := protojson.Unmarshal([]byte(payload), record); err != nil {
			return nil, fmt.Errorf("decode finding evidence: %w", err)
		}
		evidence = append(evidence, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding evidence rows: %w", err)
	}
	return evidence, nil
}

func (s *Store) ensureFindingEvidenceTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingEvidenceReady, "finding evidence", ensureFindingEvidenceStatements)
}

func findingEvidenceListQuery(request ports.ListFindingEvidenceRequest) (string, []any, error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return "", nil, errors.New("finding evidence runtime id is required")
	}
	clauses := []string{"runtime_id = $1"}
	args := []any{runtimeID}
	addFindingFilter(&clauses, &args, "finding_id", request.FindingID)
	addFindingFilter(&clauses, &args, "run_id", request.RunID)
	addFindingFilter(&clauses, &args, "rule_id", request.RuleID)
	if err := addFindingArrayContainsFilter(&clauses, &args, "claim_ids_json", request.ClaimID); err != nil {
		return "", nil, err
	}
	if err := addFindingArrayContainsFilter(&clauses, &args, "event_ids_json", request.EventID); err != nil {
		return "", nil, err
	}
	if err := addFindingArrayContainsFilter(&clauses, &args, "graph_root_urns_json", request.GraphRootURN); err != nil {
		return "", nil, err
	}
	query := `
SELECT finding_evidence_json::text
FROM finding_evidence
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY last_observed_at DESC, created_at DESC, id`
	if request.Limit != 0 {
		args = append(args, int64(request.Limit))
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	return query, args, nil
}
