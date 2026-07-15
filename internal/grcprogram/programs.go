package grcprogram

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

var (
	ErrInvalidProgramRequest = errors.New("invalid compliance program request")
	ErrProgramUnavailable    = errors.New("compliance program runtime unavailable")
)

type identifierFactory func(compliance.IdentifierKind) (string, error)

// Service owns program, scope, and control-implementation revision semantics.
// Persistence implementations enforce the same expected-version conditions
// atomically when appending a revision.
type Service struct {
	store       ComplianceProgramStore
	resolver    ProgramSubjectResolver
	now         func() time.Time
	newID       identifierFactory
	newRevision identifierFactory
}

type CreateProgramRequest struct {
	TenantID  string
	ID        string
	Name      string
	OwnerTeam string
	RiskOwner string
	Status    string
}

func NewService(store ComplianceProgramStore, resolver ProgramSubjectResolver) *Service {
	return &Service{
		store:       store,
		resolver:    resolver,
		now:         func() time.Time { return time.Now().UTC() },
		newID:       compliance.NewIdentifier,
		newRevision: compliance.NewRevisionIdentifier,
	}
}

func (service *Service) CreateProgram(ctx context.Context, request CreateProgramRequest) (*ComplianceProgramRecord, error) {
	if service == nil || service.store == nil {
		return nil, ErrProgramUnavailable
	}
	request = normalizeCreateProgramRequest(request)
	if err := validateCreateProgramRequest(request); err != nil {
		return nil, err
	}
	id := request.ID
	if id == "" {
		var err error
		id, err = service.newID(compliance.IdentifierProgram)
		if err != nil {
			return nil, fmt.Errorf("create program identifier: %w", err)
		}
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierProgram, id); err != nil {
		return nil, fmt.Errorf("%w: program id: %w", ErrInvalidProgramRequest, err)
	}
	now := compliance.CanonicalRevisionTime(service.now())
	record, err := service.store.CreateComplianceProgram(ctx, ComplianceProgramRecord{
		TenantID: request.TenantID, ID: id, Name: request.Name, OwnerTeam: request.OwnerTeam,
		RiskOwner: request.RiskOwner, Status: request.Status, AggregateVersion: 1,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return nil, programStoreError(err)
	}
	return record, nil
}

// GetProgram uses the tenant-scoped store lookup directly. A foreign tenant and
// an unknown identifier therefore return the same non-disclosing sentinel.
func (service *Service) GetProgram(ctx context.Context, tenantID string, programID string) (*ComplianceProgramRecord, error) {
	if service == nil || service.store == nil {
		return nil, ErrProgramUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	programID = strings.TrimSpace(programID)
	if tenantID == "" || programID == "" {
		return nil, ports.ErrComplianceProgramNotFound
	}
	record, err := service.store.GetComplianceProgram(ctx, tenantID, programID)
	if err != nil {
		return nil, programStoreError(err)
	}
	if record == nil || record.TenantID != tenantID {
		return nil, ports.ErrComplianceProgramNotFound
	}
	return record, nil
}

func normalizeCreateProgramRequest(request CreateProgramRequest) CreateProgramRequest {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ID = strings.TrimSpace(request.ID)
	request.Name = strings.TrimSpace(request.Name)
	request.OwnerTeam = strings.TrimSpace(request.OwnerTeam)
	request.RiskOwner = strings.TrimSpace(request.RiskOwner)
	request.Status = strings.TrimSpace(request.Status)
	if request.Status == "" {
		request.Status = ComplianceProgramDraft
	}
	return request
}

func validateCreateProgramRequest(request CreateProgramRequest) error {
	if request.TenantID == "" || request.Name == "" || request.OwnerTeam == "" {
		return fmt.Errorf("%w: tenant_id, name, and owner_team are required", ErrInvalidProgramRequest)
	}
	if !knownProgramStatus(request.Status) {
		return fmt.Errorf("%w: unknown program status %q", ErrInvalidProgramRequest, request.Status)
	}
	return nil
}

func knownProgramStatus(value string) bool {
	switch value {
	case ComplianceProgramDraft, ComplianceProgramActive, ComplianceProgramSuspended, ComplianceProgramRetired:
		return true
	default:
		return false
	}
}

func programStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ports.ErrComplianceProgramNotFound):
		return ports.ErrComplianceProgramNotFound
	case errors.Is(err, ports.ErrControlImplementationNotFound):
		return ports.ErrControlImplementationNotFound
	case errors.Is(err, ports.ErrComplianceProgramVersionConflict):
		return ports.ErrComplianceProgramVersionConflict
	case errors.Is(err, ports.ErrProgramRevisionConflict):
		return ports.ErrProgramRevisionConflict
	default:
		return err
	}
}
