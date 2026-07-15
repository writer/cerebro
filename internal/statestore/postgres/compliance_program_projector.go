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

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

// ApplyComplianceProgramEvent applies one already-appended compliance event to
// Postgres. The immutable row, current pointer, and application receipt commit
// together; callers may safely retry an event with the same content digest.
func (s *Store) ApplyComplianceProgramEvent(ctx context.Context, event *cerebrov1.EventEnvelope) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("postgres is not configured")
	}
	application, err := decodeComplianceProgramApplication(event)
	if err != nil {
		return false, err
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin compliance program event application: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, complianceApplicationAdvisoryLockSQL(), application.tenantID+"\x00"+application.eventID); err != nil {
		return false, fmt.Errorf("lock compliance event application: %w", err)
	}
	existingDigest, receiptExists, err := loadComplianceApplicationReceipt(ctx, tx, application.tenantID, application.eventID)
	if err != nil {
		return false, err
	}
	apply, err := complianceReceiptDecision(existingDigest, receiptExists, application.eventDigest)
	if err != nil || !apply {
		return false, err
	}
	program, err := loadComplianceProgramForUpdate(ctx, tx, application.tenantID, application.programID)
	programExists := err == nil
	if err != nil && !errors.Is(err, ports.ErrComplianceProgramNotFound) {
		return false, err
	}
	currentVersion := uint64(0)
	if programExists {
		currentVersion = program.AggregateVersion
	}
	if err := validateComplianceAggregateAdvance(programExists, currentVersion, application.aggregateVersion); err != nil {
		return false, err
	}
	program, err = applyComplianceProgramPayload(ctx, tx, application, program)
	if err != nil {
		return false, err
	}
	if program.AggregateVersion != application.aggregateVersion {
		return false, ports.ErrComplianceProgramVersionConflict
	}
	if err := insertComplianceApplicationReceipt(ctx, tx, application); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit compliance program event application: %w", err)
	}
	return true, nil
}

type complianceProgramApplication struct {
	eventID          string
	tenantID         string
	programID        string
	revisionID       string
	aggregateVersion uint64
	operation        string
	contentDigest    string
	eventDigest      string
	kind             string
	payloadJSON      string
}

func decodeComplianceProgramApplication(event *cerebrov1.EventEnvelope) (complianceProgramApplication, error) {
	payload, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return complianceProgramApplication{}, err
	}
	application := complianceProgramApplication{
		eventID: strings.TrimSpace(event.GetId()), tenantID: strings.TrimSpace(payload.TenantID),
		programID: strings.TrimSpace(payload.AggregateID), revisionID: strings.TrimSpace(payload.RevisionID),
		operation: strings.TrimSpace(payload.Operation), contentDigest: strings.TrimSpace(payload.ContentDigest),
		kind: strings.TrimSpace(payload.Kind), payloadJSON: payload.PayloadJSON,
	}
	payloadDigest := sha256.Sum256(event.GetPayload())
	application.eventDigest = "sha256:" + hex.EncodeToString(payloadDigest[:])
	if payload.AggregateVersion > 0 {
		application.aggregateVersion = uint64(payload.AggregateVersion)
	}
	if application.eventID == "" || application.tenantID == "" || application.programID == "" ||
		application.aggregateVersion == 0 || application.operation == "" || strings.TrimSpace(application.payloadJSON) == "" {
		return complianceProgramApplication{}, errors.New("compliance program event identity, version, operation, and payload are required")
	}
	if application.tenantID != strings.TrimSpace(event.GetTenantId()) {
		return complianceProgramApplication{}, errors.New("compliance program event tenant does not match its envelope")
	}
	if payload.AggregateType != "program" && payload.AggregateType != "compliance_program" {
		return complianceProgramApplication{}, errors.New("compliance program event aggregate_type is invalid")
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(application.contentDigest)); err != nil {
		return complianceProgramApplication{}, fmt.Errorf("compliance program event content digest: %w", err)
	}
	switch application.kind {
	case workflowevents.EventKindComplianceProgramRecorded,
		workflowevents.EventKindComplianceProgramScopeRecorded,
		workflowevents.EventKindComplianceImplementationRecorded:
		return application, nil
	default:
		return complianceProgramApplication{}, errors.New("event kind is not a compliance program projection event")
	}
}

func applyComplianceProgramPayload(ctx context.Context, tx *sql.Tx, application complianceProgramApplication, program *grcprogram.ComplianceProgramRecord) (*grcprogram.ComplianceProgramRecord, error) {
	switch application.kind {
	case workflowevents.EventKindComplianceProgramRecorded:
		return applyComplianceProgramRecorded(ctx, tx, application, program)
	case workflowevents.EventKindComplianceProgramScopeRecorded:
		return applyComplianceProgramScopeRecorded(ctx, tx, application, program)
	case workflowevents.EventKindComplianceImplementationRecorded:
		return applyComplianceImplementationRecorded(ctx, tx, application, program)
	default:
		return nil, errors.New("event kind is not a compliance program projection event")
	}
}

func applyComplianceProgramRecorded(ctx context.Context, tx *sql.Tx, application complianceProgramApplication, current *grcprogram.ComplianceProgramRecord) (*grcprogram.ComplianceProgramRecord, error) {
	var record grcprogram.ComplianceProgramRecord
	if err := json.Unmarshal([]byte(application.payloadJSON), &record); err != nil {
		return nil, fmt.Errorf("decode compliance program event payload: %w", err)
	}
	if record.TenantID != application.tenantID || record.ID != application.programID {
		return nil, errors.New("compliance program payload identity does not match the event")
	}
	if current != nil {
		return nil, ports.ErrProgramRevisionConflict
	}
	record.AggregateVersion = application.aggregateVersion
	if err := insertComplianceProgram(ctx, tx, record); err != nil {
		return nil, err
	}
	return &record, nil
}

func applyComplianceProgramScopeRecorded(ctx context.Context, tx *sql.Tx, application complianceProgramApplication, program *grcprogram.ComplianceProgramRecord) (*grcprogram.ComplianceProgramRecord, error) {
	if program == nil {
		return nil, ports.ErrComplianceEventVersionGap
	}
	var revision grcprogram.ProgramScopeRevisionRecord
	if err := json.Unmarshal([]byte(application.payloadJSON), &revision); err != nil {
		return nil, fmt.Errorf("decode program scope event payload: %w", err)
	}
	if revision.TenantID != application.tenantID || revision.ProgramID != application.programID ||
		revision.Version.RevisionID != application.revisionID || string(revision.Version.ContentDigest) != application.contentDigest {
		return nil, errors.New("program scope payload identity or digest does not match the event")
	}
	if err := validateProgramScopePredecessor(ctx, tx, *program, revision); err != nil {
		return nil, err
	}
	if err := insertProgramScopeRevision(ctx, tx, revision); err != nil {
		return nil, err
	}
	program.ScopeID = revision.Version.ID
	program.CurrentScopeRevisionID = revision.Version.RevisionID
	program.AggregateVersion = application.aggregateVersion
	program.UpdatedAt = revision.Version.LastModified
	if err := updateComplianceProgram(ctx, tx, *program); err != nil {
		return nil, err
	}
	return program, nil
}

func applyComplianceImplementationRecorded(ctx context.Context, tx *sql.Tx, application complianceProgramApplication, program *grcprogram.ComplianceProgramRecord) (*grcprogram.ComplianceProgramRecord, error) {
	if program == nil {
		return nil, ports.ErrComplianceEventVersionGap
	}
	var payload grcprogram.ControlImplementationRecordedPayload
	if err := json.Unmarshal([]byte(application.payloadJSON), &payload); err != nil {
		return nil, fmt.Errorf("decode control implementation event payload: %w", err)
	}
	if payload.Implementation.TenantID != application.tenantID || payload.Implementation.ProgramID != application.programID ||
		payload.Revision.TenantID != application.tenantID || payload.Revision.ProgramID != application.programID ||
		payload.Revision.ImplementationID != payload.Implementation.ID ||
		payload.Revision.Version.RevisionID != application.revisionID || string(payload.Revision.Version.ContentDigest) != application.contentDigest {
		return nil, errors.New("control implementation payload identity or digest does not match the event")
	}
	current, err := loadControlImplementationForUpdate(ctx, tx, application.tenantID, application.programID, payload.Implementation.ID)
	if errors.Is(err, ports.ErrControlImplementationNotFound) {
		current = nil
	} else if err != nil {
		return nil, err
	}
	if current == nil {
		if payload.Implementation.AggregateVersion != 1 {
			return nil, ports.ErrComplianceEventVersionGap
		}
		if err := insertControlImplementation(ctx, tx, payload.Implementation); err != nil {
			return nil, err
		}
	} else {
		if payload.Implementation.AggregateVersion != current.AggregateVersion+1 {
			return nil, ports.ErrComplianceProgramVersionConflict
		}
	}
	if err := validateImplementationPredecessor(current, payload.Revision); err != nil {
		return nil, err
	}
	if err := insertControlImplementationRevision(ctx, tx, payload.Revision); err != nil {
		return nil, err
	}
	if err := updateControlImplementation(ctx, tx, payload.Implementation); err != nil {
		return nil, err
	}
	program.AggregateVersion = application.aggregateVersion
	program.UpdatedAt = payload.Revision.Version.LastModified
	if err := updateComplianceProgram(ctx, tx, *program); err != nil {
		return nil, err
	}
	return program, nil
}

func insertComplianceProgram(ctx context.Context, tx *sql.Tx, record grcprogram.ComplianceProgramRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO grc_programs (
  tenant_id, program_id, name, owner_team, risk_owner, status, scope_id,
  current_scope_revision_id, aggregate_version, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, record.TenantID,
		record.ID, record.Name, record.OwnerTeam, record.RiskOwner, record.Status, record.ScopeID,
		record.CurrentScopeRevisionID, record.AggregateVersion, record.CreatedAt, record.UpdatedAt)
	if err != nil {
		if postgresUniqueViolation(err) {
			return ports.ErrComplianceProgramVersionConflict
		}
		return fmt.Errorf("insert compliance program projection: %w", err)
	}
	return nil
}

func loadComplianceApplicationReceipt(ctx context.Context, tx *sql.Tx, tenantID string, eventID string) (string, bool, error) {
	var digest string
	err := tx.QueryRowContext(ctx, `
SELECT event_digest
FROM grc_compliance_event_application_receipts
WHERE tenant_id = $1 AND event_id = $2
FOR UPDATE`, tenantID, eventID).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load compliance event application receipt: %w", err)
	}
	return digest, true, nil
}

func complianceApplicationAdvisoryLockSQL() string {
	return `SELECT pg_advisory_xact_lock(hashtext('grc_compliance_event_application'), hashtext($1))`
}

func insertComplianceApplicationReceipt(ctx context.Context, tx *sql.Tx, application complianceProgramApplication) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO grc_compliance_event_application_receipts (
  tenant_id, event_id, event_digest, aggregate_type, aggregate_id,
  revision_id, aggregate_version, operation
)
VALUES ($1, $2, $3, 'program', $4, $5, $6, $7)`, application.tenantID,
		application.eventID, application.eventDigest, application.programID,
		application.revisionID, application.aggregateVersion, application.operation)
	if err != nil {
		if postgresUniqueViolation(err) {
			return ports.ErrComplianceEventApplicationConflict
		}
		return fmt.Errorf("insert compliance event application receipt: %w", err)
	}
	return nil
}

func complianceReceiptDecision(existingDigest string, exists bool, incomingDigest string) (bool, error) {
	if !exists {
		return true, nil
	}
	if strings.TrimSpace(existingDigest) == strings.TrimSpace(incomingDigest) {
		return false, nil
	}
	return false, ports.ErrComplianceEventApplicationConflict
}

func validateComplianceAggregateAdvance(currentExists bool, currentVersion uint64, incomingVersion uint64) error {
	if !currentExists {
		if incomingVersion == 1 {
			return nil
		}
		return ports.ErrComplianceEventVersionGap
	}
	if incomingVersion == currentVersion+1 {
		return nil
	}
	if incomingVersion <= currentVersion {
		return ports.ErrComplianceProgramVersionConflict
	}
	return ports.ErrComplianceEventVersionGap
}
