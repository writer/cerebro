package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/verifiedaccessaction"
)

const maxVerifiedAccessActionJSONBytes = 1024 * 1024

var _ verifiedaccessaction.Store = (*Store)(nil)

func (s *Store) CreateAccessAction(ctx context.Context, outcome verifiedaccessaction.Outcome) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	if err := verifiedaccessaction.VerifyCreateOutcome(outcome); err != nil {
		return false, err
	}
	if err := s.ensureVerifiedAccessActionTables(ctx); err != nil {
		return false, err
	}
	recordJSON, transitionJSON, err := marshalVerifiedAccessActionOutcome(outcome)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin verified access action create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
INSERT INTO verified_access_actions (
  tenant_id, action_id, idempotency_key, status, record_digest,
  last_transition_digest, record_json, proposed_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
ON CONFLICT DO NOTHING`,
		outcome.Record.TenantID, outcome.Record.ID, outcome.Record.IdempotencyKey,
		outcome.Record.Status, outcome.Record.Digest, outcome.Record.LastTransitionDigest,
		recordJSON, outcome.Record.ProposedAt, outcome.Transition.OccurredAt)
	if err != nil {
		return false, fmt.Errorf("insert verified access action: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read verified access action insert result: %w", err)
	}
	if rows == 0 {
		var existingRecordJSON string
		queryErr := tx.QueryRowContext(ctx, `
SELECT record_json::text
FROM verified_access_actions
WHERE tenant_id = $1 AND (action_id = $2 OR idempotency_key = $3)
FOR UPDATE`,
			outcome.Record.TenantID, outcome.Record.ID, outcome.Record.IdempotencyKey).
			Scan(&existingRecordJSON)
		if queryErr != nil {
			return false, fmt.Errorf("read conflicting verified access action: %w", queryErr)
		}
		existing, decodeErr := decodeVerifiedAccessActionRecord(existingRecordJSON)
		if decodeErr != nil {
			return false, decodeErr
		}
		if existing.ID == outcome.Record.ID &&
			existing.Digest == outcome.Record.Digest &&
			existing.LastTransitionDigest == outcome.Transition.Digest {
			return false, nil
		}
		return false, verifiedaccessaction.ErrConflict
	}
	if err := insertVerifiedAccessActionTransition(ctx, tx, outcome.Transition, transitionJSON); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit verified access action create: %w", err)
	}
	return true, nil
}

func (s *Store) GetAccessAction(ctx context.Context, tenantID, actionID string) (verifiedaccessaction.Record, error) {
	if s == nil || s.db == nil {
		return verifiedaccessaction.Record{}, errors.New("postgres is not configured")
	}
	tenantID, actionID = strings.TrimSpace(tenantID), strings.TrimSpace(actionID)
	if tenantID == "" || actionID == "" {
		return verifiedaccessaction.Record{}, verifiedaccessaction.ErrInvalid
	}
	if err := s.ensureVerifiedAccessActionTables(ctx); err != nil {
		return verifiedaccessaction.Record{}, err
	}
	var recordJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT record_json::text
FROM verified_access_actions
WHERE tenant_id = $1 AND action_id = $2`, tenantID, actionID).Scan(&recordJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return verifiedaccessaction.Record{}, verifiedaccessaction.ErrNotFound
	}
	if err != nil {
		return verifiedaccessaction.Record{}, fmt.Errorf("query verified access action: %w", err)
	}
	return decodeVerifiedAccessActionRecord(recordJSON)
}

func (s *Store) AppendAccessAction(ctx context.Context, outcome verifiedaccessaction.Outcome) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	if err := verifiedaccessaction.VerifyAppendOutcome(outcome); err != nil {
		return false, err
	}
	if err := s.ensureVerifiedAccessActionTables(ctx); err != nil {
		return false, err
	}
	recordJSON, transitionJSON, err := marshalVerifiedAccessActionOutcome(outcome)
	if err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin verified access action append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var currentJSON string
	err = tx.QueryRowContext(ctx, `
SELECT record_json::text
FROM verified_access_actions
WHERE tenant_id = $1 AND action_id = $2
FOR UPDATE`, outcome.Record.TenantID, outcome.Record.ID).Scan(&currentJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return false, verifiedaccessaction.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("lock verified access action: %w", err)
	}
	current, err := decodeVerifiedAccessActionRecord(currentJSON)
	if err != nil {
		return false, err
	}
	if current.Digest == outcome.Record.Digest &&
		current.LastTransitionDigest == outcome.Transition.Digest {
		var digest string
		err = tx.QueryRowContext(ctx, `
SELECT transition_digest
FROM verified_access_action_transitions
WHERE tenant_id = $1 AND action_id = $2 AND transition_id = $3`,
			outcome.Record.TenantID, outcome.Record.ID, outcome.Transition.ID).Scan(&digest)
		if err != nil || digest != outcome.Transition.Digest {
			return false, verifiedaccessaction.ErrConflict
		}
		return false, nil
	}
	if current.Status != outcome.Transition.FromStatus ||
		current.LastTransitionDigest != outcome.Transition.PreviousTransitionDigest {
		return false, verifiedaccessaction.ErrConflict
	}
	if err := insertVerifiedAccessActionTransition(ctx, tx, outcome.Transition, transitionJSON); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE verified_access_actions
SET status = $1, record_digest = $2, last_transition_digest = $3,
    record_json = $4::jsonb, updated_at = $5
WHERE tenant_id = $6 AND action_id = $7
  AND record_digest = $8 AND last_transition_digest = $9`,
		outcome.Record.Status, outcome.Record.Digest, outcome.Record.LastTransitionDigest,
		recordJSON, outcome.Transition.OccurredAt,
		outcome.Record.TenantID, outcome.Record.ID,
		current.Digest, current.LastTransitionDigest)
	if err != nil {
		return false, fmt.Errorf("update verified access action: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return false, verifiedaccessaction.ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit verified access action append: %w", err)
	}
	return true, nil
}

func (s *Store) ListAccessActionTransitions(ctx context.Context, tenantID, actionID string) ([]verifiedaccessaction.TransitionReceipt, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	tenantID, actionID = strings.TrimSpace(tenantID), strings.TrimSpace(actionID)
	if tenantID == "" || actionID == "" {
		return nil, verifiedaccessaction.ErrInvalid
	}
	if err := s.ensureVerifiedAccessActionTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT transition_json::text
FROM verified_access_action_transitions
WHERE tenant_id = $1 AND action_id = $2
ORDER BY sequence`, tenantID, actionID)
	if err != nil {
		return nil, fmt.Errorf("query verified access action transitions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result []verifiedaccessaction.TransitionReceipt
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan verified access action transition: %w", err)
		}
		var receipt verifiedaccessaction.TransitionReceipt
		if err := json.Unmarshal([]byte(payload), &receipt); err != nil {
			return nil, fmt.Errorf("decode verified access action transition: %w", err)
		}
		result = append(result, receipt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate verified access action transitions: %w", err)
	}
	if len(result) == 0 {
		return nil, verifiedaccessaction.ErrNotFound
	}
	return result, nil
}

func insertVerifiedAccessActionTransition(
	ctx context.Context,
	tx *sql.Tx,
	receipt verifiedaccessaction.TransitionReceipt,
	payload string,
) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO verified_access_action_transitions (
  tenant_id, action_id, transition_id, transition_digest,
  previous_transition_digest, record_digest, from_status, to_status,
  result_code, transition_json, occurred_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`,
		receipt.TenantID, receipt.ActionID, receipt.ID, receipt.Digest,
		receipt.PreviousTransitionDigest, receipt.RecordDigest,
		receipt.FromStatus, receipt.ToStatus, receipt.ResultCode,
		payload, receipt.OccurredAt)
	if err != nil {
		return fmt.Errorf("insert verified access action transition: %w", err)
	}
	return nil
}

func marshalVerifiedAccessActionOutcome(outcome verifiedaccessaction.Outcome) (string, string, error) {
	recordJSON, err := json.Marshal(outcome.Record)
	if err != nil {
		return "", "", fmt.Errorf("encode verified access action: %w", err)
	}
	transitionJSON, err := json.Marshal(outcome.Transition)
	if err != nil {
		return "", "", fmt.Errorf("encode verified access action transition: %w", err)
	}
	if len(recordJSON) > maxVerifiedAccessActionJSONBytes ||
		len(transitionJSON) > maxVerifiedAccessActionJSONBytes {
		return "", "", verifiedaccessaction.ErrInvalid
	}
	return string(recordJSON), string(transitionJSON), nil
}

func decodeVerifiedAccessActionRecord(payload string) (verifiedaccessaction.Record, error) {
	var record verifiedaccessaction.Record
	if err := json.Unmarshal([]byte(payload), &record); err != nil {
		return verifiedaccessaction.Record{}, fmt.Errorf("decode verified access action: %w", err)
	}
	if err := verifiedaccessaction.VerifyRecord(record); err != nil {
		return verifiedaccessaction.Record{}, err
	}
	return record, nil
}
