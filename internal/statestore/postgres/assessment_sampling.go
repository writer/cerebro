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

const maxAssessmentSamplingPayloadBytes = 512 * 1024

var _ complianceassessment.SamplingStateStore = (*Store)(nil)

type assessmentSamplingEvent struct {
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
	kind             string
}

func (s *Store) ApplyAssessmentSamplingEvent(ctx context.Context, envelope *cerebrov1.EventEnvelope) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	event, err := decodeAssessmentSamplingEvent(envelope)
	if err != nil {
		return false, err
	}
	if err := s.ensureAssessmentSamplingTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin assessment sampling projection: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, assessmentSamplingAdvisoryLockSQL(), event.tenantID+"\x00"+event.aggregateType+"\x00"+event.aggregateID); err != nil {
		return false, fmt.Errorf("lock assessment sampling aggregate: %w", err)
	}
	existingDigest, exists, err := loadAssessmentSamplingReceipt(ctx, tx, event.tenantID, event.eventID)
	if err != nil {
		return false, err
	}
	apply, err := assessmentSamplingReceiptDecision(existingDigest, exists, event.eventDigest)
	if err != nil || !apply {
		return false, err
	}
	switch event.aggregateType {
	case complianceassessment.AggregateTypeAssessmentActivity:
		err = applyAssessmentActivity(ctx, tx, event)
	case complianceassessment.AggregateTypeAssessmentPopulation:
		err = applyAssessmentPopulation(ctx, tx, event)
	case complianceassessment.AggregateTypeAssessmentSample:
		err = applyAssessmentSample(ctx, tx, event)
	default:
		err = complianceassessment.ErrSamplingProjectionConflict
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_sampling_event_application_receipts (
  tenant_id, event_id, event_digest, aggregate_type, aggregate_id, aggregate_version, operation
)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, event.tenantID, event.eventID, event.eventDigest,
		event.aggregateType, event.aggregateID, event.aggregateVersion, event.operation); err != nil {
		if samplingPostgresUniqueViolation(err) {
			return false, complianceassessment.ErrSamplingProjectionConflict
		}
		return false, fmt.Errorf("insert assessment sampling receipt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit assessment sampling projection: %w", err)
	}
	return true, nil
}

func (s *Store) GetAssessmentActivity(ctx context.Context, tenantID string, activityID string) (*complianceassessment.AssessmentActivity, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureAssessmentSamplingTables(ctx); err != nil {
		return nil, err
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `
SELECT activity_json::text FROM compliance_assessment_activities
WHERE tenant_id = $1 AND activity_id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(activityID)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, complianceassessment.ErrActivityNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get assessment activity: %w", err)
	}
	var activity complianceassessment.AssessmentActivity
	if err := json.Unmarshal([]byte(payload), &activity); err != nil {
		return nil, fmt.Errorf("decode assessment activity: %w", err)
	}
	return &activity, nil
}

func (s *Store) GetAssessmentPopulation(ctx context.Context, tenantID string, populationID string) (*complianceassessment.PopulationRecordedPayload, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureAssessmentSamplingTables(ctx); err != nil {
		return nil, err
	}
	var snapshotJSON string
	err := s.db.QueryRowContext(ctx, `
SELECT snapshot_json::text FROM compliance_assessment_populations
WHERE tenant_id = $1 AND population_id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(populationID)).Scan(&snapshotJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, complianceassessment.ErrPopulationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get assessment population: %w", err)
	}
	result := &complianceassessment.PopulationRecordedPayload{}
	if err := json.Unmarshal([]byte(snapshotJSON), &result.Snapshot); err != nil {
		return nil, fmt.Errorf("decode assessment population: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT subject_id, subject_type FROM compliance_assessment_population_subjects
WHERE tenant_id = $1 AND population_id = $2 ORDER BY subject_type, subject_id`, strings.TrimSpace(tenantID), strings.TrimSpace(populationID))
	if err != nil {
		return nil, fmt.Errorf("list assessment population subjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var subject complianceassessment.PopulationSubject
		if err := rows.Scan(&subject.ID, &subject.Type); err != nil {
			return nil, fmt.Errorf("scan assessment population subject: %w", err)
		}
		result.Subjects = append(result.Subjects, subject)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate assessment population subjects: %w", err)
	}
	return result, nil
}

func (s *Store) GetAssessmentSample(ctx context.Context, tenantID string, sampleID string) (*complianceassessment.SampleSelection, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureAssessmentSamplingTables(ctx); err != nil {
		return nil, err
	}
	var payload string
	err := s.db.QueryRowContext(ctx, `
SELECT selection_json::text FROM compliance_assessment_samples
WHERE tenant_id = $1 AND sample_id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(sampleID)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, complianceassessment.ErrSampleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get assessment sample: %w", err)
	}
	var sample complianceassessment.SampleSelection
	if err := json.Unmarshal([]byte(payload), &sample); err != nil {
		return nil, fmt.Errorf("decode assessment sample: %w", err)
	}
	return &sample, nil
}

func applyAssessmentActivity(ctx context.Context, tx *sql.Tx, event assessmentSamplingEvent) error {
	var activity complianceassessment.AssessmentActivity
	if err := decodeAssessmentSamplingPayload(event, &activity); err != nil {
		return err
	}
	if activity.ID != event.aggregateID || activity.RunID == "" || activity.ObjectiveID == "" || activity.PlanTaskID == "" ||
		activity.Method == "" || activity.Procedure == "" || activity.ExpectedResult == "" ||
		event.contentDigest != complianceassessmentPayloadDigest(event.payloadJSON) {
		return complianceassessment.ErrSamplingProjectionConflict
	}
	var currentVersion uint64
	var currentState complianceassessment.ActivityExecutionState
	err := tx.QueryRowContext(ctx, `
SELECT aggregate_version, execution_state FROM compliance_assessment_activities
WHERE tenant_id = $1 AND activity_id = $2 FOR UPDATE`, event.tenantID, event.aggregateID).Scan(&currentVersion, &currentState)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load assessment activity state: %w", err)
	}
	if err := validateSamplingAdvance(exists, currentVersion, event.aggregateVersion); err != nil {
		return err
	}
	if !activityTransitionAllowed(currentState, activity.ExecutionState, exists) {
		return complianceassessment.ErrSamplingProjectionConflict
	}
	payloadJSON, err := marshalAssessmentSamplingJSON(activity)
	if err != nil {
		return err
	}
	if !exists {
		_, err = tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_activities (
  tenant_id, activity_id, run_id, aggregate_version, execution_state, activity_json, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`, event.tenantID, activity.ID, activity.RunID,
			event.aggregateVersion, activity.ExecutionState, payloadJSON, event.recordedAt)
	} else {
		_, err = tx.ExecContext(ctx, `
UPDATE compliance_assessment_activities
SET run_id = $3, aggregate_version = $4, execution_state = $5,
  activity_json = $6::jsonb, updated_at = $7
WHERE tenant_id = $1 AND activity_id = $2`, event.tenantID, activity.ID, activity.RunID,
			event.aggregateVersion, activity.ExecutionState, payloadJSON, event.recordedAt)
	}
	if err != nil {
		return fmt.Errorf("write assessment activity state: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_activity_revisions (
  tenant_id, activity_id, aggregate_version, execution_state, content_digest, activity_json, recorded_at
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`, event.tenantID, activity.ID,
		event.aggregateVersion, activity.ExecutionState, event.contentDigest, payloadJSON, event.recordedAt); err != nil {
		return fmt.Errorf("insert assessment activity revision: %w", err)
	}
	return nil
}

func applyAssessmentPopulation(ctx context.Context, tx *sql.Tx, event assessmentSamplingEvent) error {
	var payload complianceassessment.PopulationRecordedPayload
	if err := decodeAssessmentSamplingPayload(event, &payload); err != nil {
		return err
	}
	normalized, err := validateCompleteAssessmentPopulation(event, payload)
	if err != nil {
		return err
	}
	snapshot := payload.Snapshot
	var exists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM compliance_assessment_populations WHERE tenant_id = $1 AND population_id = $2)`,
		event.tenantID, snapshot.ID).Scan(&exists); err != nil {
		return fmt.Errorf("check assessment population: %w", err)
	}
	if exists {
		return complianceassessment.ErrSamplingProjectionConflict
	}
	snapshotJSON, err := marshalAssessmentSamplingJSON(snapshot)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_populations (
  tenant_id, population_id, run_id, objective_id, expected_count, observed_count,
  complete, content_digest, snapshot_json, source_watermark, recorded_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)`, event.tenantID,
		snapshot.ID, snapshot.RunID, snapshot.ObjectiveID, snapshot.ExpectedCount, snapshot.ObservedCount,
		snapshot.Complete, snapshot.ContentDigest, snapshotJSON, snapshot.SourceWatermark, event.recordedAt); err != nil {
		return fmt.Errorf("insert assessment population: %w", err)
	}
	for _, subject := range normalized {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_population_subjects (tenant_id, population_id, subject_type, subject_id)
VALUES ($1, $2, $3, $4)`, event.tenantID, snapshot.ID, subject.Type, subject.ID); err != nil {
			return fmt.Errorf("insert assessment population subject: %w", err)
		}
	}
	return nil
}

func applyAssessmentSample(ctx context.Context, tx *sql.Tx, event assessmentSamplingEvent) error {
	var sample complianceassessment.SampleSelection
	if err := decodeAssessmentSamplingPayload(event, &sample); err != nil {
		return err
	}
	if event.aggregateVersion != 1 || sample.ID != event.aggregateID || sample.ID == "" ||
		sample.Algorithm != complianceassessment.DeterministicSampleAlgorithm || sample.Seed == "" ||
		event.contentDigest != sample.SelectionDigest {
		return complianceassessment.ErrInvalidSample
	}
	population, err := loadAssessmentPopulationForSample(ctx, tx, event.tenantID, sample.PopulationID)
	if err != nil {
		return err
	}
	if err := validateDeterministicAssessmentSample(sample, *population); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (SELECT 1 FROM compliance_assessment_samples WHERE tenant_id = $1 AND sample_id = $2)`,
		event.tenantID, sample.ID).Scan(&exists); err != nil {
		return fmt.Errorf("check assessment sample: %w", err)
	}
	if exists {
		return complianceassessment.ErrSamplingProjectionConflict
	}
	payloadJSON, err := marshalAssessmentSamplingJSON(sample)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_samples (
  tenant_id, sample_id, population_id, algorithm, seed, requested_size,
  population_digest, selection_digest, selection_json, recorded_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)`, event.tenantID,
		sample.ID, sample.PopulationID, sample.Algorithm, sample.Seed, sample.RequestedSize,
		sample.PopulationDigest, sample.SelectionDigest, payloadJSON, event.recordedAt); err != nil {
		return fmt.Errorf("insert assessment sample: %w", err)
	}
	for ordinal, subject := range sample.Subjects {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO compliance_assessment_sample_subjects (
  tenant_id, sample_id, subject_type, subject_id, ordinal
)
VALUES ($1, $2, $3, $4, $5)`, event.tenantID, sample.ID, subject.Type, subject.ID, ordinal); err != nil {
			return fmt.Errorf("insert assessment sample subject: %w", err)
		}
	}
	return nil
}

func loadAssessmentPopulationForSample(ctx context.Context, tx *sql.Tx, tenantID string, populationID string) (*complianceassessment.PopulationRecordedPayload, error) {
	var snapshotJSON string
	err := tx.QueryRowContext(ctx, `
SELECT snapshot_json::text FROM compliance_assessment_populations
WHERE tenant_id = $1 AND population_id = $2`, tenantID, populationID).Scan(&snapshotJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, complianceassessment.ErrPopulationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load assessment population for sample: %w", err)
	}
	result := &complianceassessment.PopulationRecordedPayload{}
	if err := json.Unmarshal([]byte(snapshotJSON), &result.Snapshot); err != nil {
		return nil, fmt.Errorf("decode assessment population for sample: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
SELECT subject_id, subject_type FROM compliance_assessment_population_subjects
WHERE tenant_id = $1 AND population_id = $2 ORDER BY subject_type, subject_id`, tenantID, populationID)
	if err != nil {
		return nil, fmt.Errorf("list assessment population subjects for sample: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var subject complianceassessment.PopulationSubject
		if err := rows.Scan(&subject.ID, &subject.Type); err != nil {
			return nil, fmt.Errorf("scan assessment population subject for sample: %w", err)
		}
		result.Subjects = append(result.Subjects, subject)
	}
	return result, rows.Err()
}

func validateCompleteAssessmentPopulation(event assessmentSamplingEvent, payload complianceassessment.PopulationRecordedPayload) ([]complianceassessment.PopulationSubject, error) {
	normalized, err := complianceassessment.NormalizePopulation(payload.Subjects)
	if err != nil {
		return nil, err
	}
	digest, err := complianceassessment.PopulationDigest(normalized)
	if err != nil {
		return nil, err
	}
	snapshot := payload.Snapshot
	if event.aggregateVersion != 1 || snapshot.ID != event.aggregateID || snapshot.ID == "" || snapshot.RunID == "" ||
		snapshot.ObjectiveID == "" || snapshot.QueryDigest == "" || snapshot.SourceWatermark.IsZero() ||
		!snapshot.Complete || snapshot.ExpectedCount != snapshot.ObservedCount || snapshot.ObservedCount != uint64(len(normalized)) ||
		snapshot.ContentDigest != digest || event.contentDigest != digest {
		return nil, complianceassessment.ErrInvalidPopulation
	}
	return normalized, nil
}

func validateDeterministicAssessmentSample(sample complianceassessment.SampleSelection, population complianceassessment.PopulationRecordedPayload) error {
	expected, err := complianceassessment.SelectDeterministicSample(sample.PopulationID, sample.Seed, sample.RequestedSize, population.Subjects)
	if err != nil {
		return err
	}
	if sample.PopulationDigest != population.Snapshot.ContentDigest || sample.PopulationDigest != expected.PopulationDigest ||
		sample.SelectionDigest != expected.SelectionDigest || !reflect.DeepEqual(sample.Subjects, expected.Subjects) {
		return complianceassessment.ErrInvalidSample
	}
	return nil
}

func decodeAssessmentSamplingEvent(envelope *cerebrov1.EventEnvelope) (assessmentSamplingEvent, error) {
	payload, err := workflowevents.DecodeComplianceAggregate(envelope)
	if err != nil {
		return assessmentSamplingEvent{}, err
	}
	if payload.AggregateVersion < 1 {
		return assessmentSamplingEvent{}, complianceassessment.ErrSamplingProjectionGap
	}
	recordedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(payload.RecordedAt))
	if err != nil {
		return assessmentSamplingEvent{}, fmt.Errorf("parse assessment sampling recorded_at: %w", err)
	}
	event := assessmentSamplingEvent{
		eventID: strings.TrimSpace(envelope.GetId()), tenantID: strings.TrimSpace(payload.TenantID),
		aggregateType: strings.TrimSpace(payload.AggregateType), aggregateID: strings.TrimSpace(payload.AggregateID),
		aggregateVersion: uint64(payload.AggregateVersion), // #nosec G115 -- positive int64 fits in uint64.
		operation:        strings.TrimSpace(payload.Operation), contentDigest: strings.TrimSpace(payload.ContentDigest),
		payloadJSON: payload.PayloadJSON, recordedAt: payloadTime(recordedAt), kind: strings.TrimSpace(payload.Kind),
		eventDigest: assessmentSamplingDigest(envelope.GetPayload()),
	}
	if event.eventID == "" || event.tenantID == "" || event.tenantID != strings.TrimSpace(envelope.GetTenantId()) ||
		event.aggregateID == "" || event.operation == "" || event.recordedAt.IsZero() ||
		strings.TrimSpace(event.payloadJSON) == "" || len(event.payloadJSON) > maxAssessmentSamplingPayloadBytes ||
		!json.Valid([]byte(event.payloadJSON)) || !validSamplingDigest(event.contentDigest) || !samplingKindMatchesAggregate(event.kind, event.aggregateType) {
		return assessmentSamplingEvent{}, complianceassessment.ErrSamplingProjectionConflict
	}
	return event, nil
}

func samplingKindMatchesAggregate(kind string, aggregateType string) bool {
	switch aggregateType {
	case complianceassessment.AggregateTypeAssessmentActivity:
		return kind == workflowevents.EventKindComplianceActivityRecorded
	case complianceassessment.AggregateTypeAssessmentPopulation:
		return kind == workflowevents.EventKindCompliancePopulationRecorded
	case complianceassessment.AggregateTypeAssessmentSample:
		return kind == workflowevents.EventKindComplianceSampleRecorded
	default:
		return false
	}
}

func decodeAssessmentSamplingPayload(event assessmentSamplingEvent, target any) error {
	if err := json.Unmarshal([]byte(event.payloadJSON), target); err != nil {
		return fmt.Errorf("decode assessment sampling payload: %w", err)
	}
	return nil
}

func assessmentSamplingReceiptDecision(existing string, exists bool, incoming string) (bool, error) {
	if !exists {
		return true, nil
	}
	if existing == incoming {
		return false, nil
	}
	return false, complianceassessment.ErrSamplingProjectionConflict
}

func validateSamplingAdvance(exists bool, current uint64, incoming uint64) error {
	if !exists && incoming == 1 || exists && incoming == current+1 {
		return nil
	}
	if !exists || incoming > current+1 {
		return complianceassessment.ErrSamplingProjectionGap
	}
	return complianceassessment.ErrSamplingProjectionConflict
}

func activityTransitionAllowed(current complianceassessment.ActivityExecutionState, next complianceassessment.ActivityExecutionState, exists bool) bool {
	if !exists {
		return next == complianceassessment.ActivityQueued
	}
	if current == next {
		return true
	}
	switch current {
	case complianceassessment.ActivityQueued:
		return next == complianceassessment.ActivityRunning || next == complianceassessment.ActivitySkipped ||
			next == complianceassessment.ActivityCancelled || next == complianceassessment.ActivityError
	case complianceassessment.ActivityRunning:
		return next == complianceassessment.ActivityCompleted || next == complianceassessment.ActivityFailed ||
			next == complianceassessment.ActivityError || next == complianceassessment.ActivityCancelled
	default:
		return false
	}
}

func loadAssessmentSamplingReceipt(ctx context.Context, tx *sql.Tx, tenantID string, eventID string) (string, bool, error) {
	var digest string
	err := tx.QueryRowContext(ctx, `
SELECT event_digest FROM compliance_sampling_event_application_receipts
WHERE tenant_id = $1 AND event_id = $2 FOR UPDATE`, tenantID, eventID).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load assessment sampling receipt: %w", err)
	}
	return digest, true, nil
}

func assessmentSamplingAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('compliance_assessment_sampling'), hashtext($1))`
}

func marshalAssessmentSamplingJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode assessment sampling state: %w", err)
	}
	if len(payload) > maxAssessmentSamplingPayloadBytes {
		return "", complianceassessment.ErrSamplingProjectionConflict
	}
	return string(payload), nil
}

func complianceassessmentPayloadDigest(value string) string {
	return assessmentSamplingDigest([]byte(value))
}

func assessmentSamplingDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSamplingDigest(value string) bool {
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

func payloadTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}

func samplingPostgresUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
