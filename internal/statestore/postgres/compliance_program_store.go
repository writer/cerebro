package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/grcprogram"
	"github.com/writer/cerebro/internal/ports"
)

const maxComplianceProgramJSONBytes = 512 * 1024

var _ grcprogram.ComplianceProgramStore = (*Store)(nil)

func (s *Store) CreateComplianceProgram(ctx context.Context, record grcprogram.ComplianceProgramRecord) (*grcprogram.ComplianceProgramRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, err
	}
	if err := validateComplianceProgramRecord(record); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO grc_programs (
  tenant_id, program_id, name, owner_team, risk_owner, status, scope_id,
  current_scope_revision_id, aggregate_version, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING tenant_id, program_id, name, owner_team, risk_owner, status, scope_id,
  current_scope_revision_id, aggregate_version, created_at, updated_at`,
		record.TenantID, record.ID, record.Name, record.OwnerTeam, record.RiskOwner, record.Status,
		record.ScopeID, record.CurrentScopeRevisionID, record.AggregateVersion, record.CreatedAt, record.UpdatedAt)
	result, err := scanComplianceProgram(row)
	if err != nil {
		if postgresUniqueViolation(err) {
			return nil, ports.ErrComplianceProgramVersionConflict
		}
		return nil, fmt.Errorf("create compliance program: %w", err)
	}
	return result, nil
}

func (s *Store) GetComplianceProgram(ctx context.Context, tenantID string, programID string) (*grcprogram.ComplianceProgramRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, err
	}
	record, err := scanComplianceProgram(s.db.QueryRowContext(ctx, complianceProgramSelectSQL, strings.TrimSpace(tenantID), strings.TrimSpace(programID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrComplianceProgramNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get compliance program: %w", err)
	}
	return record, nil
}

func (s *Store) GetProgramScopeRevision(ctx context.Context, tenantID string, programID string, revisionID string) (*grcprogram.ProgramScopeRevisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, err
	}
	revision, err := scanProgramScopeRevision(s.db.QueryRowContext(ctx, `
SELECT tenant_id, program_id, scope_id, revision_id, revision_version, state,
  content_digest, predecessor_id, created_by, change_summary, specification_json::text, created_at
FROM grc_program_scope_revisions
WHERE tenant_id = $1 AND program_id = $2 AND revision_id = $3`,
		strings.TrimSpace(tenantID), strings.TrimSpace(programID), strings.TrimSpace(revisionID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrProgramRevisionConflict
	}
	if err != nil {
		return nil, fmt.Errorf("get program scope revision: %w", err)
	}
	return revision, nil
}

func (s *Store) AppendProgramScopeRevision(ctx context.Context, request grcprogram.AppendProgramScopeRevisionRequest) (*grcprogram.ComplianceProgramRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, err
	}
	if request.Revision.TenantID != request.TenantID || request.Revision.ProgramID != request.ProgramID {
		return nil, ports.ErrProgramRevisionConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin program scope revision append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	program, err := loadComplianceProgramForUpdate(ctx, tx, request.TenantID, request.ProgramID)
	if err != nil {
		return nil, err
	}
	if program.AggregateVersion != request.ExpectedProgramVersion {
		return nil, ports.ErrComplianceProgramVersionConflict
	}
	if err := validateProgramScopePredecessor(ctx, tx, *program, request.Revision); err != nil {
		return nil, err
	}
	if err := insertProgramScopeRevision(ctx, tx, request.Revision); err != nil {
		return nil, err
	}
	program.ScopeID = request.Revision.Version.ID
	program.CurrentScopeRevisionID = request.Revision.Version.RevisionID
	program.AggregateVersion++
	program.UpdatedAt = request.Revision.Version.LastModified
	if err := updateComplianceProgram(ctx, tx, *program); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit program scope revision append: %w", err)
	}
	return program, nil
}

func (s *Store) GetControlImplementation(ctx context.Context, tenantID string, programID string, implementationID string) (*grcprogram.ControlImplementationRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, err
	}
	record, err := scanControlImplementation(s.db.QueryRowContext(ctx, controlImplementationSelectSQL,
		strings.TrimSpace(tenantID), strings.TrimSpace(programID), strings.TrimSpace(implementationID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrControlImplementationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get control implementation: %w", err)
	}
	return record, nil
}

func (s *Store) GetControlImplementationRevision(ctx context.Context, tenantID string, programID string, implementationID string, revisionID string) (*grcprogram.ControlImplementationRevisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, err
	}
	revision, err := scanControlImplementationRevision(s.db.QueryRowContext(ctx, `
SELECT tenant_id, program_id, implementation_id, revision_id, revision_version,
  content_digest, predecessor_id, created_by, change_summary, specification_json::text, created_at
FROM grc_control_implementation_revisions
WHERE tenant_id = $1 AND program_id = $2 AND implementation_id = $3 AND revision_id = $4`,
		strings.TrimSpace(tenantID), strings.TrimSpace(programID), strings.TrimSpace(implementationID), strings.TrimSpace(revisionID)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrControlImplementationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get control implementation revision: %w", err)
	}
	return revision, nil
}

func (s *Store) AppendControlImplementationRevision(ctx context.Context, request grcprogram.AppendControlImplementationRevisionRequest) (*grcprogram.ComplianceProgramRecord, *grcprogram.ControlImplementationRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil, errors.New("postgres is not configured")
	}
	if err := s.ensureComplianceProgramTables(ctx); err != nil {
		return nil, nil, err
	}
	if request.Implementation.TenantID != request.TenantID || request.Implementation.ProgramID != request.ProgramID ||
		request.Revision.TenantID != request.TenantID || request.Revision.ProgramID != request.ProgramID ||
		request.Revision.ImplementationID != request.Implementation.ID {
		return nil, nil, ports.ErrProgramRevisionConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin control implementation revision append: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	program, err := loadComplianceProgramForUpdate(ctx, tx, request.TenantID, request.ProgramID)
	if err != nil {
		return nil, nil, err
	}
	if program.AggregateVersion != request.ExpectedProgramVersion {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	implementation, err := loadControlImplementationForUpdate(ctx, tx, request.TenantID, request.ProgramID, request.Implementation.ID)
	if errors.Is(err, ports.ErrControlImplementationNotFound) && request.ExpectedImplementationVersion == 0 {
		implementation = nil
	} else if err != nil {
		return nil, nil, err
	}
	if implementation != nil && implementation.AggregateVersion != request.ExpectedImplementationVersion {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	if implementation == nil && request.ExpectedImplementationVersion != 0 {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	if err := validateImplementationPredecessor(implementation, request.Revision); err != nil {
		return nil, nil, err
	}
	if implementation == nil {
		if err := insertControlImplementation(ctx, tx, request.Implementation); err != nil {
			return nil, nil, err
		}
		implementation = &request.Implementation
	}
	if err := insertControlImplementationRevision(ctx, tx, request.Revision); err != nil {
		return nil, nil, err
	}
	implementation.CurrentRevisionID = request.Revision.Version.RevisionID
	implementation.AggregateVersion = request.ExpectedImplementationVersion + 1
	implementation.UpdatedAt = request.Revision.Version.LastModified
	if err := updateControlImplementation(ctx, tx, *implementation); err != nil {
		return nil, nil, err
	}
	program.AggregateVersion++
	program.UpdatedAt = request.Revision.Version.LastModified
	if err := updateComplianceProgram(ctx, tx, *program); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit control implementation revision append: %w", err)
	}
	return program, implementation, nil
}

const complianceProgramSelectSQL = `
SELECT tenant_id, program_id, name, owner_team, risk_owner, status, scope_id,
  current_scope_revision_id, aggregate_version, created_at, updated_at
FROM grc_programs
WHERE tenant_id = $1 AND program_id = $2`

const controlImplementationSelectSQL = `
SELECT tenant_id, program_id, implementation_id, current_revision_id,
  aggregate_version, created_at, updated_at
FROM grc_control_implementations
WHERE tenant_id = $1 AND program_id = $2 AND implementation_id = $3`

func loadComplianceProgramForUpdate(ctx context.Context, tx *sql.Tx, tenantID string, programID string) (*grcprogram.ComplianceProgramRecord, error) {
	record, err := scanComplianceProgram(tx.QueryRowContext(ctx, complianceProgramSelectSQL+" FOR UPDATE", tenantID, programID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrComplianceProgramNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load compliance program for update: %w", err)
	}
	return record, nil
}

func loadControlImplementationForUpdate(ctx context.Context, tx *sql.Tx, tenantID string, programID string, implementationID string) (*grcprogram.ControlImplementationRecord, error) {
	record, err := scanControlImplementation(tx.QueryRowContext(ctx, controlImplementationSelectSQL+" FOR UPDATE", tenantID, programID, implementationID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ports.ErrControlImplementationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load control implementation for update: %w", err)
	}
	return record, nil
}

func insertProgramScopeRevision(ctx context.Context, tx *sql.Tx, revision grcprogram.ProgramScopeRevisionRecord) error {
	if err := validateProgramScopeRevisionRecord(revision); err != nil {
		return err
	}
	specificationJSON, err := marshalBoundedComplianceProgramJSON(revision.Specification)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_program_scope_revisions (
  tenant_id, program_id, scope_id, revision_id, revision_version, state,
  content_digest, predecessor_id, created_by, change_summary, specification_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)`,
		revision.TenantID, revision.ProgramID, revision.Version.ID, revision.Version.RevisionID,
		revision.Version.Version, revision.State, revision.Version.ContentDigest, revision.Version.PredecessorID,
		revision.Version.CreatedBy, revision.ChangeSummary, specificationJSON, revision.Version.LastModified)
	if err != nil {
		if postgresUniqueViolation(err) {
			return ports.ErrProgramRevisionConflict
		}
		return fmt.Errorf("insert program scope revision: %w", err)
	}
	resolutionBySelector := make(map[string]grcprogram.SelectorResolution, len(revision.Specification.SubjectManifest.SelectorResolutions))
	for _, resolution := range revision.Specification.SubjectManifest.SelectorResolutions {
		resolutionBySelector[resolution.SelectorID] = resolution
	}
	for _, selector := range revision.Specification.Selectors {
		selectorJSON, marshalErr := marshalBoundedComplianceProgramJSON(selector)
		if marshalErr != nil {
			return marshalErr
		}
		resolution := resolutionBySelector[selector.ID]
		if _, execErr := tx.ExecContext(ctx, `
INSERT INTO grc_program_scope_selectors (
  tenant_id, program_id, revision_id, selector_id, kind, mode,
  resolution_state, unresolved_reason, selector_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
			revision.TenantID, revision.ProgramID, revision.Version.RevisionID, selector.ID,
			selector.Kind, selector.Mode, resolution.State, resolution.ReasonCode, selectorJSON); execErr != nil {
			return fmt.Errorf("insert program scope selector: %w", execErr)
		}
	}
	for _, subject := range revision.Specification.SubjectManifest.Subjects {
		if _, execErr := tx.ExecContext(ctx, `
INSERT INTO grc_program_scope_subjects (tenant_id, program_id, revision_id, subject_type, subject_id)
VALUES ($1, $2, $3, $4, $5)`, revision.TenantID, revision.ProgramID,
			revision.Version.RevisionID, subject.Type, subject.ID); execErr != nil {
			return fmt.Errorf("insert program scope subject: %w", execErr)
		}
	}
	return nil
}

func validateProgramScopePredecessor(ctx context.Context, tx *sql.Tx, program grcprogram.ComplianceProgramRecord, revision grcprogram.ProgramScopeRevisionRecord) error {
	if program.CurrentScopeRevisionID == "" {
		if revision.Version.Version != 1 || revision.Version.PredecessorID != "" {
			return ports.ErrProgramRevisionConflict
		}
		return nil
	}
	var scopeID string
	var version uint64
	err := tx.QueryRowContext(ctx, `
SELECT scope_id, revision_version
FROM grc_program_scope_revisions
WHERE tenant_id = $1 AND program_id = $2 AND revision_id = $3`, program.TenantID,
		program.ID, program.CurrentScopeRevisionID).Scan(&scopeID, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return ports.ErrProgramRevisionConflict
	}
	if err != nil {
		return fmt.Errorf("load scope predecessor: %w", err)
	}
	if revision.Version.ID != scopeID || revision.Version.Version != version+1 || revision.Version.PredecessorID != program.CurrentScopeRevisionID {
		return ports.ErrProgramRevisionConflict
	}
	return nil
}

func validateImplementationPredecessor(current *grcprogram.ControlImplementationRecord, revision grcprogram.ControlImplementationRevisionRecord) error {
	if current == nil {
		if revision.Version.Version != 1 || revision.Version.PredecessorID != "" {
			return ports.ErrProgramRevisionConflict
		}
		return nil
	}
	if revision.Version.ID != current.ID || revision.Version.Version != current.AggregateVersion+1 || revision.Version.PredecessorID != current.CurrentRevisionID {
		return ports.ErrProgramRevisionConflict
	}
	return nil
}

func insertControlImplementation(ctx context.Context, tx *sql.Tx, record grcprogram.ControlImplementationRecord) error {
	if err := validateControlImplementationRecord(record); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO grc_control_implementations (
  tenant_id, program_id, implementation_id, current_revision_id,
  aggregate_version, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)`, record.TenantID, record.ProgramID, record.ID,
		record.CurrentRevisionID, record.AggregateVersion, record.CreatedAt, record.UpdatedAt)
	if err != nil {
		if postgresUniqueViolation(err) {
			return ports.ErrComplianceProgramVersionConflict
		}
		return fmt.Errorf("insert control implementation: %w", err)
	}
	return nil
}

func insertControlImplementationRevision(ctx context.Context, tx *sql.Tx, revision grcprogram.ControlImplementationRevisionRecord) error {
	if err := validateControlImplementationRevisionRecord(revision); err != nil {
		return err
	}
	specificationJSON, err := marshalBoundedComplianceProgramJSON(revision.Specification)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO grc_control_implementation_revisions (
  tenant_id, program_id, implementation_id, revision_id, revision_version,
  scope_revision_id, content_digest, predecessor_id, created_by,
  change_summary, specification_json, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)`,
		revision.TenantID, revision.ProgramID, revision.ImplementationID, revision.Version.RevisionID,
		revision.Version.Version, revision.Specification.ScopeRevisionID, revision.Version.ContentDigest,
		revision.Version.PredecessorID, revision.Version.CreatedBy, revision.ChangeSummary,
		specificationJSON, revision.Version.LastModified)
	if err != nil {
		if postgresUniqueViolation(err) {
			return ports.ErrProgramRevisionConflict
		}
		return fmt.Errorf("insert control implementation revision: %w", err)
	}
	for _, mapping := range revision.Specification.MappingRefs {
		mappingJSON, marshalErr := marshalBoundedComplianceProgramJSON(mapping)
		if marshalErr != nil {
			return marshalErr
		}
		if _, execErr := tx.ExecContext(ctx, `
INSERT INTO grc_control_mapping_revisions (
  tenant_id, program_id, implementation_id, implementation_revision_id,
  mapping_id, mapping_revision_id, relationship, source_revision_id,
  target_revision_id, mapping_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)`, revision.TenantID,
			revision.ProgramID, revision.ImplementationID, revision.Version.RevisionID,
			mapping.ID, mapping.RevisionID, mapping.Relationship, mapping.Source.RevisionID,
			mapping.Target.RevisionID, mappingJSON); execErr != nil {
			return fmt.Errorf("insert control mapping revision: %w", execErr)
		}
	}
	return nil
}

func updateComplianceProgram(ctx context.Context, tx *sql.Tx, record grcprogram.ComplianceProgramRecord) error {
	result, err := tx.ExecContext(ctx, `
UPDATE grc_programs
SET name = $3, owner_team = $4, risk_owner = $5, status = $6, scope_id = $7,
  current_scope_revision_id = $8, aggregate_version = $9, updated_at = $10
WHERE tenant_id = $1 AND program_id = $2`, record.TenantID, record.ID, record.Name,
		record.OwnerTeam, record.RiskOwner, record.Status, record.ScopeID,
		record.CurrentScopeRevisionID, record.AggregateVersion, record.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update compliance program: %w", err)
	}
	return requireOneComplianceRow(result, ports.ErrComplianceProgramNotFound)
}

func updateControlImplementation(ctx context.Context, tx *sql.Tx, record grcprogram.ControlImplementationRecord) error {
	result, err := tx.ExecContext(ctx, `
UPDATE grc_control_implementations
SET current_revision_id = $4, aggregate_version = $5, updated_at = $6
WHERE tenant_id = $1 AND program_id = $2 AND implementation_id = $3`, record.TenantID,
		record.ProgramID, record.ID, record.CurrentRevisionID, record.AggregateVersion, record.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update control implementation: %w", err)
	}
	return requireOneComplianceRow(result, ports.ErrControlImplementationNotFound)
}

func requireOneComplianceRow(result sql.Result, notFound error) error {
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read affected compliance rows: %w", err)
	}
	if count != 1 {
		return notFound
	}
	return nil
}

func scanComplianceProgram(row scanner) (*grcprogram.ComplianceProgramRecord, error) {
	record := &grcprogram.ComplianceProgramRecord{}
	err := row.Scan(&record.TenantID, &record.ID, &record.Name, &record.OwnerTeam, &record.RiskOwner,
		&record.Status, &record.ScopeID, &record.CurrentScopeRevisionID, &record.AggregateVersion,
		&record.CreatedAt, &record.UpdatedAt)
	return record, err
}

func scanProgramScopeRevision(row scanner) (*grcprogram.ProgramScopeRevisionRecord, error) {
	record := &grcprogram.ProgramScopeRevisionRecord{}
	var specificationJSON string
	err := row.Scan(&record.TenantID, &record.ProgramID, &record.Version.ID, &record.Version.RevisionID,
		&record.Version.Version, &record.State, &record.Version.ContentDigest, &record.Version.PredecessorID,
		&record.Version.CreatedBy, &record.ChangeSummary, &specificationJSON, &record.Version.LastModified)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(specificationJSON), &record.Specification); err != nil {
		return nil, fmt.Errorf("decode program scope specification: %w", err)
	}
	return record, nil
}

func scanControlImplementation(row scanner) (*grcprogram.ControlImplementationRecord, error) {
	record := &grcprogram.ControlImplementationRecord{}
	err := row.Scan(&record.TenantID, &record.ProgramID, &record.ID, &record.CurrentRevisionID,
		&record.AggregateVersion, &record.CreatedAt, &record.UpdatedAt)
	return record, err
}

func scanControlImplementationRevision(row scanner) (*grcprogram.ControlImplementationRevisionRecord, error) {
	record := &grcprogram.ControlImplementationRevisionRecord{}
	var specificationJSON string
	err := row.Scan(&record.TenantID, &record.ProgramID, &record.ImplementationID,
		&record.Version.RevisionID, &record.Version.Version, &record.Version.ContentDigest,
		&record.Version.PredecessorID, &record.Version.CreatedBy, &record.ChangeSummary,
		&specificationJSON, &record.Version.LastModified)
	if err != nil {
		return nil, err
	}
	record.Version.ID = record.ImplementationID
	if err := json.Unmarshal([]byte(specificationJSON), &record.Specification); err != nil {
		return nil, fmt.Errorf("decode control implementation specification: %w", err)
	}
	return record, nil
}

func marshalBoundedComplianceProgramJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal compliance program JSON: %w", err)
	}
	if len(payload) > maxComplianceProgramJSONBytes {
		return "", fmt.Errorf("compliance program JSON exceeds %d bytes", maxComplianceProgramJSONBytes)
	}
	return string(payload), nil
}

func validateComplianceProgramRecord(record grcprogram.ComplianceProgramRecord) error {
	if strings.TrimSpace(record.TenantID) == "" || strings.TrimSpace(record.Name) == "" ||
		strings.TrimSpace(record.OwnerTeam) == "" || strings.TrimSpace(record.Status) == "" ||
		record.AggregateVersion != 1 || record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() ||
		record.ScopeID != "" || record.CurrentScopeRevisionID != "" {
		return errors.New("compliance program identity, ownership, status, version, and timestamps are required")
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierProgram, record.ID); err != nil {
		return fmt.Errorf("validate compliance program id: %w", err)
	}
	return nil
}

func validateProgramScopeRevisionRecord(record grcprogram.ProgramScopeRevisionRecord) error {
	if strings.TrimSpace(record.TenantID) == "" || strings.TrimSpace(record.ProgramID) == "" ||
		strings.TrimSpace(record.State) == "" || strings.TrimSpace(record.ChangeSummary) == "" {
		return errors.New("scope revision identity, state, and change summary are required")
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierProgram, record.ProgramID); err != nil {
		return fmt.Errorf("validate scope revision program id: %w", err)
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierScope, record.Version.ID); err != nil {
		return fmt.Errorf("validate scope id: %w", err)
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierScope, record.Version.RevisionID); err != nil {
		return fmt.Errorf("validate scope revision id: %w", err)
	}
	if err := record.Version.Validate(); err != nil {
		return fmt.Errorf("validate scope revision metadata: %w", err)
	}
	return nil
}

func validateControlImplementationRecord(record grcprogram.ControlImplementationRecord) error {
	if strings.TrimSpace(record.TenantID) == "" || strings.TrimSpace(record.ProgramID) == "" ||
		strings.TrimSpace(record.CurrentRevisionID) == "" || record.AggregateVersion == 0 ||
		record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() {
		return errors.New("control implementation identity, version, and timestamps are required")
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierProgram, record.ProgramID); err != nil {
		return fmt.Errorf("validate implementation program id: %w", err)
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierImplementation, record.ID); err != nil {
		return fmt.Errorf("validate implementation id: %w", err)
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierImplementation, record.CurrentRevisionID); err != nil {
		return fmt.Errorf("validate current implementation revision id: %w", err)
	}
	return nil
}

func validateControlImplementationRevisionRecord(record grcprogram.ControlImplementationRevisionRecord) error {
	if strings.TrimSpace(record.TenantID) == "" || strings.TrimSpace(record.ProgramID) == "" ||
		strings.TrimSpace(record.ImplementationID) == "" || strings.TrimSpace(record.ChangeSummary) == "" {
		return errors.New("control implementation revision identity and change summary are required")
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierProgram, record.ProgramID); err != nil {
		return fmt.Errorf("validate implementation revision program id: %w", err)
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierImplementation, record.ImplementationID); err != nil {
		return fmt.Errorf("validate implementation revision id: %w", err)
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierImplementation, record.Version.RevisionID); err != nil {
		return fmt.Errorf("validate immutable implementation revision id: %w", err)
	}
	if err := record.Version.Validate(); err != nil {
		return fmt.Errorf("validate implementation revision metadata: %w", err)
	}
	if record.Version.ID != record.ImplementationID {
		return errors.New("implementation revision logical id does not match implementation id")
	}
	return nil
}

func postgresUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
