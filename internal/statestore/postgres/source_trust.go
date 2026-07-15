package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/workflowevents"
)

const maxSourceTrustPayloadBytes = 512 * 1024

var _ complianceassessment.SourceTrustStateStore = (*Store)(nil)

type sourceTrustEvent struct {
	eventID          string
	tenantID         string
	aggregateType    string
	aggregateID      string
	aggregateVersion uint64
	operation        string
	contentDigest    string
	payloadJSON      string
	recordedAt       time.Time
	eventDigest      string
}

func (s *Store) ApplySourceTrustEvent(ctx context.Context, envelope *cerebrov1.EventEnvelope) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	event, err := decodeSourceTrustEvent(envelope)
	if err != nil {
		return false, err
	}
	if err := s.ensureSourceTrustTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin source trust projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, sourceTrustAdvisoryLockSQL(), event.tenantID+"\x00"+event.aggregateType+"\x00"+event.aggregateID); err != nil {
		return false, fmt.Errorf("lock source trust aggregate: %w", err)
	}
	existingDigest, exists, err := loadSourceTrustReceipt(ctx, tx, event.tenantID, event.eventID)
	if err != nil {
		return false, err
	}
	apply, err := sourceTrustReceiptDecision(existingDigest, exists, event.eventDigest)
	if err != nil || !apply {
		return false, err
	}
	switch event.aggregateType {
	case complianceassessment.AggregateTypeSourceCheckSnapshot:
		err = applySourceCheckSnapshot(ctx, tx, event)
	case complianceassessment.AggregateTypeObjectiveSourceAssessment:
		err = applyObjectiveSourceAssessment(ctx, tx, event)
	default:
		err = complianceassessment.ErrSourceTrustProjectionConflict
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_source_trust_event_receipts (
  tenant_id, event_id, event_digest, aggregate_type, aggregate_id, aggregate_version, operation
)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, event.tenantID, event.eventID, event.eventDigest,
		event.aggregateType, event.aggregateID, event.aggregateVersion, event.operation); err != nil {
		if sourceTrustUniqueViolation(err) {
			return false, complianceassessment.ErrSourceTrustProjectionConflict
		}
		return false, fmt.Errorf("insert source trust receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit source trust projection: %w", err)
	}
	return true, nil
}

func (s *Store) GetSourceCheckSnapshot(ctx context.Context, tenantID string, runID string, objectiveID string, snapshotID string) (*complianceassessment.SourceCheckRecordedPayload, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureSourceTrustTables(ctx); err != nil {
		return nil, err
	}
	var snapshotJSON, certificationJSON, proofJSON, contentDigest string
	err := s.db.QueryRowContext(ctx, `
SELECT snapshot_json::text, COALESCE(certification_revision_json::text, 'null'),
  proof_revisions_json::text, content_digest
FROM compliance_source_check_snapshots
WHERE tenant_id = $1 AND run_id = $2 AND objective_id = $3 AND snapshot_id = $4`,
		strings.TrimSpace(tenantID), strings.TrimSpace(runID), strings.TrimSpace(objectiveID), strings.TrimSpace(snapshotID)).
		Scan(&snapshotJSON, &certificationJSON, &proofJSON, &contentDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, complianceassessment.ErrSourceCheckNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get source check snapshot: %w", err)
	}
	result := &complianceassessment.SourceCheckRecordedPayload{
		RunID: strings.TrimSpace(runID), ObjectiveID: strings.TrimSpace(objectiveID), ContentDigest: contentDigest,
	}
	if err := json.Unmarshal([]byte(snapshotJSON), &result.Snapshot); err != nil {
		return nil, fmt.Errorf("decode source check snapshot: %w", err)
	}
	if certificationJSON != "null" {
		if err := json.Unmarshal([]byte(certificationJSON), &result.CertificationRevision); err != nil {
			return nil, fmt.Errorf("decode certification revision: %w", err)
		}
	}
	if err := json.Unmarshal([]byte(proofJSON), &result.ProofRevisions); err != nil {
		return nil, fmt.Errorf("decode proof revisions: %w", err)
	}
	return result, nil
}

func (s *Store) GetObjectiveSourceAssessment(ctx context.Context, tenantID string, runID string, objectiveID string) (*complianceassessment.ObjectiveSourceAssessmentRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureSourceTrustTables(ctx); err != nil {
		return nil, err
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `
SELECT assessment_json::text FROM compliance_objective_source_assessments
WHERE tenant_id = $1 AND run_id = $2 AND objective_id = $3`, strings.TrimSpace(tenantID), strings.TrimSpace(runID), strings.TrimSpace(objectiveID)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, complianceassessment.ErrObjectiveSourceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get objective source assessment: %w", err)
	}
	var result complianceassessment.ObjectiveSourceAssessmentRecord
	if err := json.Unmarshal([]byte(payload), &result); err != nil {
		return nil, fmt.Errorf("decode objective source assessment: %w", err)
	}
	return &result, nil
}

func applySourceCheckSnapshot(ctx context.Context, tx *sql.Tx, event sourceTrustEvent) error {
	var payload complianceassessment.SourceCheckRecordedPayload
	if err := json.Unmarshal([]byte(event.payloadJSON), &payload); err != nil {
		return fmt.Errorf("decode source check payload: %w", err)
	}
	if err := validateSourceCheckRecord(event, payload); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM compliance_source_check_snapshots
  WHERE tenant_id = $1 AND run_id = $2 AND objective_id = $3 AND snapshot_id = $4
)`, event.tenantID, payload.RunID, payload.ObjectiveID, payload.Snapshot.ID).Scan(&exists); err != nil {
		return fmt.Errorf("check source check snapshot: %w", err)
	}
	if exists {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	snapshotJSON, err := marshalSourceTrustJSON(payload.Snapshot)
	if err != nil {
		return err
	}
	certificationJSON := "null"
	if payload.CertificationRevision != nil {
		certificationJSON, err = marshalSourceTrustJSON(payload.CertificationRevision)
		if err != nil {
			return err
		}
	}
	proofJSON, err := marshalSourceTrustJSON(payload.ProofRevisions)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO compliance_source_check_snapshots (
  tenant_id, run_id, objective_id, snapshot_id, source_id, runtime_id, dimension_id,
  support_state, health_state, assessment_state, certification_tier,
  certification_receipt_id, certification_revision_json, proof_revisions_json,
  snapshot_hash, content_digest, snapshot_json, checked_at, recorded_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb,
  $14::jsonb, $15, $16, $17::jsonb, $18, $19)`, event.tenantID, payload.RunID,
		payload.ObjectiveID, payload.Snapshot.ID, payload.Snapshot.SourceID, payload.Snapshot.RuntimeID,
		payload.Snapshot.DimensionID, payload.Snapshot.Support, payload.Snapshot.Health, payload.Snapshot.State,
		payload.Snapshot.Certification, payload.Snapshot.CertificationReceiptID, certificationJSON, proofJSON,
		payload.Snapshot.SnapshotHash, payload.ContentDigest, snapshotJSON, payload.Snapshot.CheckedAt, event.recordedAt)
	if err != nil {
		if sourceTrustUniqueViolation(err) {
			return complianceassessment.ErrSourceTrustProjectionConflict
		}
		return fmt.Errorf("insert source check snapshot: %w", err)
	}
	return nil
}

func applyObjectiveSourceAssessment(ctx context.Context, tx *sql.Tx, event sourceTrustEvent) error {
	var record complianceassessment.ObjectiveSourceAssessmentRecord
	if err := json.Unmarshal([]byte(event.payloadJSON), &record); err != nil {
		return fmt.Errorf("decode objective source assessment: %w", err)
	}
	if err := validateObjectiveSourceRecord(event, record); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1 FROM compliance_objective_source_assessments
  WHERE tenant_id = $1 AND run_id = $2 AND objective_id = $3
)`, event.tenantID, record.RunID, record.ObjectiveID).Scan(&exists); err != nil {
		return fmt.Errorf("check objective source assessment: %w", err)
	}
	if exists {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	if err := validateObjectiveSourceProjection(ctx, tx, event, record); err != nil {
		return err
	}
	payloadJSON, err := marshalSourceTrustJSON(record)
	if err != nil {
		return err
	}
	requirementRevisionJSON, err := marshalSourceTrustJSON(record.RequirementRevision)
	if err != nil {
		return err
	}
	expectedSourceCheckIDsJSON, err := marshalSourceTrustJSON(record.ExpectedSourceCheckIDs)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_objective_source_assessments (
  tenant_id, run_id, objective_id, assessment_id, expected_check_count,
  observed_check_count, complete, requirement_revision_json, expected_source_check_ids_json,
  source_state, content_digest, assessment_json, assessed_at, recorded_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10, $11, $12::jsonb, $13, $14)`, record.TenantID,
		record.RunID, record.ObjectiveID, record.ID, record.ExpectedCheckCount, record.ObservedCheckCount,
		record.Complete, requirementRevisionJSON, expectedSourceCheckIDsJSON, record.Assessment.State,
		record.ContentDigest, payloadJSON, record.AssessedAt, event.recordedAt); err != nil {
		if sourceTrustUniqueViolation(err) {
			return complianceassessment.ErrSourceTrustProjectionConflict
		}
		return fmt.Errorf("insert objective source assessment: %w", err)
	}
	for _, snapshotID := range record.Assessment.SourceCheckIDs {
		result, err := tx.ExecContext(ctx, `
INSERT INTO compliance_objective_source_check_refs (tenant_id, run_id, objective_id, snapshot_id)
VALUES ($1, $2, $3, $4)`, record.TenantID, record.RunID, record.ObjectiveID, snapshotID)
		if err != nil {
			return fmt.Errorf("insert objective source check reference: %w", err)
		}
		if err := requireSourceTrustRow(result); err != nil {
			return err
		}
	}
	return nil
}

func validateSourceCheckRecord(event sourceTrustEvent, payload complianceassessment.SourceCheckRecordedPayload) error {
	if event.aggregateVersion != 1 || payload.RunID == "" || payload.RunID != strings.TrimSpace(payload.RunID) ||
		payload.ObjectiveID == "" || payload.ObjectiveID != strings.TrimSpace(payload.ObjectiveID) ||
		payload.Snapshot.ID != event.aggregateID || payload.Snapshot.TenantID != event.tenantID ||
		!containsSourceTrustString(payload.Snapshot.AffectedObjectiveIDs, payload.ObjectiveID) {
		return complianceassessment.ErrInvalidSourceCheck
	}
	if err := complianceassessment.VerifySourceCheckSnapshot(payload.Snapshot); err != nil {
		return err
	}
	if payload.Snapshot.CheckedAt.After(event.recordedAt) {
		return complianceassessment.ErrInvalidSourceCheck
	}
	if payload.Snapshot.CertificationReceiptID == "" {
		if payload.CertificationRevision != nil {
			return complianceassessment.ErrInvalidSourceCheck
		}
	} else {
		if payload.CertificationRevision == nil || payload.CertificationRevision.ID != payload.Snapshot.CertificationReceiptID {
			return complianceassessment.ErrInvalidSourceCheck
		}
		if err := payload.CertificationRevision.Validate(); err != nil {
			return fmt.Errorf("certification revision: %w", err)
		}
		if !payload.CertificationRevision.LastModified.Equal(sourceTrustTime(payload.CertificationRevision.LastModified)) {
			return complianceassessment.ErrInvalidSourceCheck
		}
		if payload.CertificationRevision.LastModified.After(payload.Snapshot.CheckedAt) {
			return complianceassessment.ErrInvalidSourceCheck
		}
	}
	if payload.Snapshot.CollectionReceiptID == "" && len(payload.ProofRevisions) != 0 {
		return complianceassessment.ErrInvalidSourceCheck
	}
	if payload.Snapshot.CollectionReceiptID != "" && len(payload.ProofRevisions) != 1 {
		return complianceassessment.ErrInvalidSourceCheck
	}
	proofFound := payload.Snapshot.CollectionReceiptID == ""
	for _, revision := range payload.ProofRevisions {
		if err := revision.Validate(); err != nil {
			return fmt.Errorf("proof revision: %w", err)
		}
		if !revision.LastModified.Equal(sourceTrustTime(revision.LastModified)) {
			return complianceassessment.ErrInvalidSourceCheck
		}
		if revision.LastModified.After(payload.Snapshot.CheckedAt) {
			return complianceassessment.ErrInvalidSourceCheck
		}
		if revision.ID == payload.Snapshot.CollectionReceiptID && string(revision.ContentDigest) == payload.Snapshot.CollectionReceiptHash {
			proofFound = true
		}
	}
	if !proofFound {
		return complianceassessment.ErrInvalidSourceCheck
	}
	digest, err := sourceTrustContentDigest(payload)
	if err != nil {
		return err
	}
	if payload.ContentDigest != digest || event.contentDigest != digest {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	return nil
}

func validateObjectiveSourceRecord(event sourceTrustEvent, record complianceassessment.ObjectiveSourceAssessmentRecord) error {
	if event.aggregateVersion != 1 || record.ID != event.aggregateID || record.ID == "" || record.TenantID != event.tenantID ||
		record.RunID == "" || record.RunID != strings.TrimSpace(record.RunID) ||
		record.ObjectiveID == "" || record.ObjectiveID != strings.TrimSpace(record.ObjectiveID) || record.ObjectiveID != record.Assessment.ObjectiveID ||
		record.ObjectiveID != record.Requirement.ObjectiveID ||
		!record.Complete || record.ObservedCheckCount != uint64(len(record.Assessment.SourceCheckIDs)) ||
		record.ExpectedCheckCount != uint64(len(record.Requirement.Sources)) ||
		record.ExpectedCheckCount != uint64(len(record.ExpectedSourceCheckIDs)) ||
		record.ObservedCheckCount != record.ExpectedCheckCount ||
		!reflect.DeepEqual(record.ExpectedSourceCheckIDs, record.Assessment.SourceCheckIDs) ||
		record.AssessedAt.IsZero() || !record.AssessedAt.Equal(sourceTrustTime(record.AssessedAt)) || record.AssessedAt.After(event.recordedAt) {
		return complianceassessment.ErrInvalidSourceCheck
	}
	canonicalRequirement, err := complianceassessment.CanonicalObjectiveSourceRequirement(record.Requirement)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(canonicalRequirement, record.Requirement) {
		return complianceassessment.ErrInvalidSourceCheck
	}
	if err := record.RequirementRevision.Validate(); err != nil {
		return fmt.Errorf("source requirement revision: %w", err)
	}
	if !record.RequirementRevision.LastModified.Equal(sourceTrustTime(record.RequirementRevision.LastModified)) {
		return complianceassessment.ErrInvalidSourceCheck
	}
	if record.RequirementRevision.LastModified.After(record.AssessedAt) {
		return complianceassessment.ErrInvalidSourceCheck
	}
	requirementDigest, err := sourceTrustValueDigest(canonicalRequirement)
	if err != nil {
		return err
	}
	if string(record.RequirementRevision.ContentDigest) != requirementDigest {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	digest, err := objectiveSourceContentDigest(record)
	if err != nil {
		return err
	}
	if record.ContentDigest != digest || event.contentDigest != digest {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	return nil
}

func validateObjectiveSourceProjection(ctx context.Context, tx *sql.Tx, event sourceTrustEvent, record complianceassessment.ObjectiveSourceAssessmentRecord) error {
	snapshots := make([]complianceassessment.SourceCheckSnapshot, 0, len(record.ExpectedSourceCheckIDs))
	for _, snapshotID := range record.ExpectedSourceCheckIDs {
		var snapshotJSON string
		err := tx.QueryRowContext(ctx, `
SELECT snapshot_json::text FROM compliance_source_check_snapshots
WHERE tenant_id = $1 AND run_id = $2 AND objective_id = $3 AND snapshot_id = $4`,
			event.tenantID, record.RunID, record.ObjectiveID, snapshotID).Scan(&snapshotJSON)
		if errors.Is(err, sql.ErrNoRows) {
			return complianceassessment.ErrSourceTrustProjectionConflict
		}
		if err != nil {
			return fmt.Errorf("load objective source check: %w", err)
		}
		var snapshot complianceassessment.SourceCheckSnapshot
		if err := json.Unmarshal([]byte(snapshotJSON), &snapshot); err != nil {
			return fmt.Errorf("decode objective source check: %w", err)
		}
		snapshots = append(snapshots, snapshot)
	}
	return validateDerivedObjectiveSourceAssessment(record, snapshots)
}

func validateDerivedObjectiveSourceAssessment(record complianceassessment.ObjectiveSourceAssessmentRecord, snapshots []complianceassessment.SourceCheckSnapshot) error {
	for _, snapshot := range snapshots {
		if snapshot.CheckedAt.After(record.AssessedAt) {
			return complianceassessment.ErrInvalidSourceCheck
		}
	}
	derived, err := complianceassessment.AssessObjectiveSourceChecks(record.Requirement, snapshots)
	if err != nil {
		return err
	}
	derivedDigest, err := sourceTrustValueDigest(derived)
	if err != nil {
		return err
	}
	recordedDigest, err := sourceTrustValueDigest(record.Assessment)
	if err != nil {
		return err
	}
	if derivedDigest != recordedDigest {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	return nil
}

func decodeSourceTrustEvent(envelope *cerebrov1.EventEnvelope) (sourceTrustEvent, error) {
	payload, err := workflowevents.DecodeComplianceAggregate(envelope)
	if err != nil {
		return sourceTrustEvent{}, err
	}
	if payload.AggregateVersion < 1 {
		return sourceTrustEvent{}, complianceassessment.ErrSourceTrustProjectionConflict
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(payload.RecordedAt))
	if err != nil {
		return sourceTrustEvent{}, fmt.Errorf("parse source trust recorded_at: %w", err)
	}
	event := sourceTrustEvent{
		eventID: strings.TrimSpace(envelope.GetId()), tenantID: strings.TrimSpace(payload.TenantID),
		aggregateType: strings.TrimSpace(payload.AggregateType), aggregateID: strings.TrimSpace(payload.AggregateID),
		aggregateVersion: uint64(payload.AggregateVersion), // #nosec G115 -- positive int64 fits in uint64.
		operation:        strings.TrimSpace(payload.Operation), contentDigest: strings.TrimSpace(payload.ContentDigest),
		payloadJSON: payload.PayloadJSON, recordedAt: sourceTrustTime(recordedAt), eventDigest: sourceTrustDigest(envelope.GetPayload()),
	}
	if envelope.GetKind() != workflowevents.EventKindComplianceSourceCheckRecorded || event.eventID == "" ||
		event.tenantID == "" || event.tenantID != strings.TrimSpace(envelope.GetTenantId()) || event.aggregateID == "" ||
		event.operation != "recorded" || event.recordedAt.IsZero() || strings.TrimSpace(event.payloadJSON) == "" ||
		len(event.payloadJSON) > maxSourceTrustPayloadBytes || !json.Valid([]byte(event.payloadJSON)) || !validSourceTrustDigest(event.contentDigest) ||
		(event.aggregateType != complianceassessment.AggregateTypeSourceCheckSnapshot && event.aggregateType != complianceassessment.AggregateTypeObjectiveSourceAssessment) {
		return sourceTrustEvent{}, complianceassessment.ErrSourceTrustProjectionConflict
	}
	return event, nil
}

func sourceTrustContentDigest(payload complianceassessment.SourceCheckRecordedPayload) (string, error) {
	payload.ContentDigest = ""
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode source check content: %w", err)
	}
	return sourceTrustDigest(encoded), nil
}

func objectiveSourceContentDigest(record complianceassessment.ObjectiveSourceAssessmentRecord) (string, error) {
	record.ContentDigest = ""
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode objective source content: %w", err)
	}
	return sourceTrustDigest(encoded), nil
}

func sourceTrustValueDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode source trust content: %w", err)
	}
	return sourceTrustDigest(encoded), nil
}

func sourceTrustReceiptDecision(existing string, exists bool, incoming string) (bool, error) {
	if !exists {
		return true, nil
	}
	if existing == incoming {
		return false, nil
	}
	return false, complianceassessment.ErrSourceTrustProjectionConflict
}

func loadSourceTrustReceipt(ctx context.Context, tx *sql.Tx, tenantID string, eventID string) (string, bool, error) {
	var digest string
	err := tx.QueryRowContext(ctx, `
SELECT event_digest FROM compliance_source_trust_event_receipts
WHERE tenant_id = $1 AND event_id = $2 FOR UPDATE`, tenantID, eventID).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load source trust receipt: %w", err)
	}
	return digest, true, nil
}

func sourceTrustAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('compliance_source_trust'), hashtext($1))`
}

func marshalSourceTrustJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode source trust state: %w", err)
	}
	if len(payload) > maxSourceTrustPayloadBytes {
		return "", complianceassessment.ErrSourceTrustProjectionConflict
	}
	return string(payload), nil
}

func sourceTrustDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSourceTrustDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func containsSourceTrustString(values []string, wanted string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == wanted {
			return true
		}
	}
	return false
}

func requireSourceTrustRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read source trust row count: %w", err)
	}
	if count != 1 {
		return complianceassessment.ErrSourceTrustProjectionConflict
	}
	return nil
}

func sourceTrustTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}

func sourceTrustUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
