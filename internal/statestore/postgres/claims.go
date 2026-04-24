package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

var ensureClaimStatements = []string{
	`CREATE TABLE IF NOT EXISTS claims (
  id TEXT PRIMARY KEY,
  runtime_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  subject_urn TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object_urn TEXT NOT NULL DEFAULT '',
  object_value TEXT NOT NULL DEFAULT '',
  claim_type TEXT NOT NULL,
  status TEXT NOT NULL,
  source_event_id TEXT NOT NULL DEFAULT '',
  observed_at TIMESTAMPTZ,
  valid_from TIMESTAMPTZ,
  valid_to TIMESTAMPTZ,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  claim_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS claims_runtime_subject_idx ON claims (runtime_id, subject_urn)`,
	`CREATE INDEX IF NOT EXISTS claims_runtime_predicate_idx ON claims (runtime_id, predicate)`,
	`CREATE INDEX IF NOT EXISTS claims_runtime_object_idx ON claims (runtime_id, object_urn)`,
	`CREATE INDEX IF NOT EXISTS claims_runtime_type_status_idx ON claims (runtime_id, claim_type, status)`,
	`CREATE INDEX IF NOT EXISTS claims_runtime_object_value_idx ON claims (runtime_id, object_value)`,
	`CREATE INDEX IF NOT EXISTS claims_runtime_source_event_idx ON claims (runtime_id, source_event_id)`,
}

// UpsertClaim persists one normalized claim in the current-state store.
func (s *Store) UpsertClaim(ctx context.Context, claim *ports.ClaimRecord) (*ports.ClaimRecord, error) {
	if claim == nil {
		return nil, errors.New("claim is required")
	}
	id := strings.TrimSpace(claim.ID)
	if id == "" {
		return nil, errors.New("claim id is required")
	}
	runtimeID := strings.TrimSpace(claim.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("claim runtime id is required")
	}
	tenantID := strings.TrimSpace(claim.TenantID)
	if tenantID == "" {
		return nil, errors.New("claim tenant id is required")
	}
	subjectURN := strings.TrimSpace(claim.SubjectURN)
	if subjectURN == "" {
		return nil, errors.New("claim subject urn is required")
	}
	predicate := strings.TrimSpace(claim.Predicate)
	if predicate == "" {
		return nil, errors.New("claim predicate is required")
	}
	claimType := strings.TrimSpace(claim.ClaimType)
	if claimType == "" {
		return nil, errors.New("claim type is required")
	}
	status := strings.TrimSpace(claim.Status)
	if status == "" {
		return nil, errors.New("claim status is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureClaimTables(ctx); err != nil {
		return nil, err
	}
	attributesJSON, err := claimAttributesJSON(claim.Attributes)
	if err != nil {
		return nil, fmt.Errorf("marshal claim attributes: %w", err)
	}
	claimJSON, err := claimJSON(claim)
	if err != nil {
		return nil, fmt.Errorf("marshal claim json: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO claims (
  id, runtime_id, tenant_id, subject_urn, predicate, object_urn, object_value,
  claim_type, status, source_event_id, observed_at, valid_from, valid_to, attributes_json, claim_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15::jsonb)
ON CONFLICT (id)
DO UPDATE SET
  runtime_id = EXCLUDED.runtime_id,
  tenant_id = EXCLUDED.tenant_id,
  subject_urn = EXCLUDED.subject_urn,
  predicate = EXCLUDED.predicate,
  object_urn = EXCLUDED.object_urn,
  object_value = EXCLUDED.object_value,
  claim_type = EXCLUDED.claim_type,
  status = EXCLUDED.status,
  source_event_id = EXCLUDED.source_event_id,
  observed_at = EXCLUDED.observed_at,
  valid_from = EXCLUDED.valid_from,
  valid_to = EXCLUDED.valid_to,
  attributes_json = EXCLUDED.attributes_json,
  claim_json = EXCLUDED.claim_json,
  updated_at = NOW()`,
		id,
		runtimeID,
		tenantID,
		subjectURN,
		predicate,
		strings.TrimSpace(claim.ObjectURN),
		strings.TrimSpace(claim.ObjectValue),
		claimType,
		status,
		strings.TrimSpace(claim.SourceEventID),
		nullableTime(claim.ObservedAt),
		nullableTime(claim.ValidFrom),
		nullableTime(claim.ValidTo),
		attributesJSON,
		claimJSON,
	); err != nil {
		return nil, fmt.Errorf("upsert claim %q: %w", id, err)
	}
	return cloneClaimRecord(claim), nil
}

// ListClaims loads persisted claims for one runtime.
func (s *Store) ListClaims(ctx context.Context, request ports.ListClaimsRequest) (_ []*ports.ClaimRecord, err error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("claim runtime id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureClaimTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"runtime_id = $1"}
	args := []any{runtimeID}
	addFilter := func(column string, value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		args = append(args, trimmed)
		clauses = append(clauses, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addFilter("id", request.ClaimID)
	addFilter("subject_urn", request.SubjectURN)
	addFilter("predicate", request.Predicate)
	addFilter("object_urn", request.ObjectURN)
	addFilter("object_value", request.ObjectValue)
	addFilter("claim_type", request.ClaimType)
	addFilter("status", request.Status)
	addFilter("source_event_id", request.SourceEventID)

	query := `
SELECT runtime_id, tenant_id, claim_json::text
FROM claims
WHERE ` + strings.Join(clauses, " AND ") + `
ORDER BY observed_at DESC NULLS LAST, updated_at DESC, id`
	if request.Limit != 0 {
		args = append(args, int64(request.Limit))
		query += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query claims for runtime %q: %w", runtimeID, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close claims rows: %w", closeErr)
		}
	}()

	claims := []*ports.ClaimRecord{}
	for rows.Next() {
		var storedRuntimeID string
		var tenantID string
		var claimJSON string
		if err := rows.Scan(&storedRuntimeID, &tenantID, &claimJSON); err != nil {
			return nil, fmt.Errorf("scan claim row: %w", err)
		}
		record, err := claimRecordFromJSON(storedRuntimeID, tenantID, claimJSON)
		if err != nil {
			return nil, err
		}
		claims = append(claims, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claims rows: %w", err)
	}
	return claims, nil
}

func (s *Store) ensureClaimTables(ctx context.Context) error {
	for _, statement := range ensureClaimStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure claims tables: %w", err)
		}
	}
	return nil
}

func claimAttributesJSON(attributes map[string]string) (string, error) {
	if len(attributes) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func claimJSON(record *ports.ClaimRecord) (string, error) {
	message := &cerebrov1.Claim{
		Id:            record.ID,
		SubjectUrn:    record.SubjectURN,
		SubjectRef:    cloneClaimEntityRef(record.SubjectRef),
		Predicate:     record.Predicate,
		ObjectUrn:     record.ObjectURN,
		ObjectRef:     cloneClaimEntityRef(record.ObjectRef),
		ObjectValue:   record.ObjectValue,
		ClaimType:     record.ClaimType,
		Status:        record.Status,
		SourceEventId: record.SourceEventID,
		Attributes:    record.Attributes,
	}
	if !record.ObservedAt.IsZero() {
		message.ObservedAt = timestamppb.New(record.ObservedAt.UTC())
	}
	if !record.ValidFrom.IsZero() {
		message.ValidFrom = timestamppb.New(record.ValidFrom.UTC())
	}
	if !record.ValidTo.IsZero() {
		message.ValidTo = timestamppb.New(record.ValidTo.UTC())
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func cloneClaimRecord(record *ports.ClaimRecord) *ports.ClaimRecord {
	if record == nil {
		return nil
	}
	attributes := make(map[string]string, len(record.Attributes))
	for key, value := range record.Attributes {
		attributes[key] = value
	}
	return &ports.ClaimRecord{
		ID:            record.ID,
		RuntimeID:     record.RuntimeID,
		TenantID:      record.TenantID,
		SubjectURN:    record.SubjectURN,
		SubjectRef:    cloneClaimEntityRef(record.SubjectRef),
		Predicate:     record.Predicate,
		ObjectURN:     record.ObjectURN,
		ObjectRef:     cloneClaimEntityRef(record.ObjectRef),
		ObjectValue:   record.ObjectValue,
		ClaimType:     record.ClaimType,
		Status:        record.Status,
		SourceEventID: record.SourceEventID,
		ObservedAt:    record.ObservedAt,
		ValidFrom:     record.ValidFrom,
		ValidTo:       record.ValidTo,
		Attributes:    attributes,
	}
}

func cloneClaimEntityRef(ref *cerebrov1.EntityRef) *cerebrov1.EntityRef {
	if ref == nil {
		return nil
	}
	return &cerebrov1.EntityRef{
		Urn:        ref.GetUrn(),
		EntityType: ref.GetEntityType(),
		Label:      ref.GetLabel(),
	}
}

func claimRecordFromJSON(runtimeID string, tenantID string, payload string) (*ports.ClaimRecord, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, errors.New("claim json is required")
	}
	claim := &cerebrov1.Claim{}
	if err := protojson.Unmarshal([]byte(payload), claim); err != nil {
		return nil, fmt.Errorf("unmarshal claim json: %w", err)
	}
	return &ports.ClaimRecord{
		ID:            strings.TrimSpace(claim.GetId()),
		RuntimeID:     strings.TrimSpace(runtimeID),
		TenantID:      strings.TrimSpace(tenantID),
		SubjectURN:    strings.TrimSpace(claim.GetSubjectUrn()),
		SubjectRef:    cloneClaimEntityRef(claim.GetSubjectRef()),
		Predicate:     strings.TrimSpace(claim.GetPredicate()),
		ObjectURN:     strings.TrimSpace(claim.GetObjectUrn()),
		ObjectRef:     cloneClaimEntityRef(claim.GetObjectRef()),
		ObjectValue:   strings.TrimSpace(claim.GetObjectValue()),
		ClaimType:     strings.TrimSpace(claim.GetClaimType()),
		Status:        strings.TrimSpace(claim.GetStatus()),
		SourceEventID: strings.TrimSpace(claim.GetSourceEventId()),
		ObservedAt:    claimMessageTime(claim.GetObservedAt()),
		ValidFrom:     claimMessageTime(claim.GetValidFrom()),
		ValidTo:       claimMessageTime(claim.GetValidTo()),
		Attributes:    cloneClaimAttributes(claim.GetAttributes()),
	}, nil
}

func cloneClaimAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(attributes))
	for key, value := range attributes {
		cloned[key] = value
	}
	return cloned
}

func claimMessageTime(value interface{ AsTime() time.Time }) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}
