package grcprogram

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

type RecordImplementationRevisionRequest struct {
	TenantID                      string
	ProgramID                     string
	ExpectedProgramVersion        uint64
	ImplementationID              string
	ExpectedImplementationVersion uint64
	ChangeSummary                 string
	CreatedBy                     string
	Specification                 ControlImplementationSpecification
}

type RecordImplementationRevisionResult struct {
	Program        *ComplianceProgramRecord
	Implementation *ControlImplementationRecord
	Revision       *ControlImplementationRevisionRecord
}

func (service *Service) GetImplementation(ctx context.Context, tenantID string, programID string, implementationID string) (*ControlImplementationRecord, error) {
	if service == nil || service.store == nil {
		return nil, ErrProgramUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	programID = strings.TrimSpace(programID)
	implementationID = strings.TrimSpace(implementationID)
	if tenantID == "" || programID == "" || implementationID == "" {
		return nil, ports.ErrControlImplementationNotFound
	}
	if _, err := service.GetProgram(ctx, tenantID, programID); err != nil {
		if errors.Is(err, ports.ErrComplianceProgramNotFound) {
			return nil, ports.ErrControlImplementationNotFound
		}
		return nil, err
	}
	record, err := service.store.GetControlImplementation(ctx, tenantID, programID, implementationID)
	if err != nil {
		if errors.Is(err, ports.ErrComplianceProgramNotFound) || errors.Is(err, ports.ErrControlImplementationNotFound) {
			return nil, ports.ErrControlImplementationNotFound
		}
		return nil, err
	}
	if record == nil || record.TenantID != tenantID || record.ProgramID != programID || record.ID != implementationID {
		return nil, ports.ErrControlImplementationNotFound
	}
	return record, nil
}

func (service *Service) GetImplementationRevision(ctx context.Context, tenantID string, programID string, implementationID string, revisionID string) (*ControlImplementationRevisionRecord, error) {
	revisionID = strings.TrimSpace(revisionID)
	implementation, err := service.GetImplementation(ctx, tenantID, programID, implementationID)
	if err != nil {
		return nil, err
	}
	if revisionID == "" {
		return nil, ports.ErrControlImplementationNotFound
	}
	revision, err := service.store.GetControlImplementationRevision(ctx, implementation.TenantID, implementation.ProgramID, implementation.ID, revisionID)
	if err != nil {
		if errors.Is(err, ports.ErrComplianceProgramNotFound) || errors.Is(err, ports.ErrControlImplementationNotFound) || errors.Is(err, ports.ErrProgramRevisionConflict) {
			return nil, ports.ErrControlImplementationNotFound
		}
		return nil, err
	}
	if revision == nil || revision.TenantID != implementation.TenantID || revision.ProgramID != implementation.ProgramID ||
		revision.ImplementationID != implementation.ID || revision.Version.RevisionID != revisionID {
		return nil, ports.ErrControlImplementationNotFound
	}
	return revision, nil
}

func (service *Service) RecordImplementationRevision(ctx context.Context, request RecordImplementationRevisionRequest) (*RecordImplementationRevisionResult, error) {
	if service == nil || service.store == nil {
		return nil, ErrProgramUnavailable
	}
	request = normalizeImplementationRequest(request)
	if err := validateImplementationRequest(request); err != nil {
		return nil, err
	}
	program, err := service.GetProgram(ctx, request.TenantID, request.ProgramID)
	if err != nil {
		return nil, err
	}
	if program.AggregateVersion != request.ExpectedProgramVersion {
		return nil, ports.ErrComplianceProgramVersionConflict
	}
	if _, err := service.store.GetProgramScopeRevision(ctx, request.TenantID, request.ProgramID, request.Specification.ScopeRevisionID); err != nil {
		if errors.Is(err, ports.ErrComplianceProgramNotFound) || errors.Is(err, ports.ErrProgramRevisionConflict) {
			return nil, ports.ErrProgramRevisionConflict
		}
		return nil, err
	}

	implementation, previous, err := service.loadImplementationRevision(ctx, request)
	if err != nil {
		return nil, err
	}
	implementationID := request.ImplementationID
	if implementationID == "" {
		implementationID, err = service.newID(compliance.IdentifierImplementation)
		if err != nil {
			return nil, fmt.Errorf("create implementation identifier: %w", err)
		}
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierImplementation, implementationID); err != nil {
		return nil, fmt.Errorf("%w: implementation id: %w", ErrInvalidProgramRequest, err)
	}
	revisionID, err := service.newRevision(compliance.IdentifierImplementation)
	if err != nil {
		return nil, fmt.Errorf("create implementation revision identifier: %w", err)
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierImplementation, revisionID); err != nil {
		return nil, fmt.Errorf("%w: implementation revision id: %w", ErrInvalidProgramRequest, err)
	}

	version := uint64(1)
	predecessorID := ""
	if previous != nil {
		if previous.Version.ID != implementationID {
			return nil, ports.ErrProgramRevisionConflict
		}
		if err := previous.Version.Validate(); err != nil {
			return nil, ports.ErrProgramRevisionConflict
		}
		version = previous.Version.Version + 1
		predecessorID = previous.Version.RevisionID
	}
	digest, err := semanticDigest(request.Specification)
	if err != nil {
		return nil, err
	}
	if previous != nil && previous.Version.ContentDigest == digest {
		return nil, ports.ErrProgramRevisionConflict
	}
	now := compliance.CanonicalRevisionTime(service.now())
	createdAt := now
	if implementation != nil {
		createdAt = implementation.CreatedAt
	}
	revision := ControlImplementationRevisionRecord{
		TenantID: request.TenantID, ProgramID: request.ProgramID, ImplementationID: implementationID,
		Version: compliance.VersionMetadata{
			ID: implementationID, RevisionID: revisionID, Version: version, LastModified: now,
			ContentDigest: digest, CreatedBy: request.CreatedBy, PredecessorID: predecessorID,
		},
		ChangeSummary: request.ChangeSummary, Specification: request.Specification,
	}
	aggregate := ControlImplementationRecord{
		TenantID: request.TenantID, ProgramID: request.ProgramID, ID: implementationID,
		CurrentRevisionID: revisionID, AggregateVersion: request.ExpectedImplementationVersion + 1,
		CreatedAt: createdAt, UpdatedAt: now,
	}
	updatedProgram, updatedImplementation, err := service.store.AppendControlImplementationRevision(ctx, AppendControlImplementationRevisionRequest{
		TenantID: request.TenantID, ProgramID: request.ProgramID,
		ExpectedProgramVersion:        request.ExpectedProgramVersion,
		ExpectedImplementationVersion: request.ExpectedImplementationVersion,
		Implementation:                aggregate, Revision: revision,
	})
	if err != nil {
		return nil, programStoreError(err)
	}
	return &RecordImplementationRevisionResult{
		Program: updatedProgram, Implementation: updatedImplementation, Revision: &revision,
	}, nil
}

func (service *Service) loadImplementationRevision(ctx context.Context, request RecordImplementationRevisionRequest) (*ControlImplementationRecord, *ControlImplementationRevisionRecord, error) {
	if request.ImplementationID == "" {
		if request.ExpectedImplementationVersion != 0 {
			return nil, nil, ports.ErrComplianceProgramVersionConflict
		}
		return nil, nil, nil
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierImplementation, request.ImplementationID); err != nil {
		return nil, nil, fmt.Errorf("%w: implementation id: %w", ErrInvalidProgramRequest, err)
	}
	implementation, err := service.store.GetControlImplementation(ctx, request.TenantID, request.ProgramID, request.ImplementationID)
	if err != nil {
		if errors.Is(err, ports.ErrControlImplementationNotFound) && request.ExpectedImplementationVersion == 0 {
			return nil, nil, nil
		}
		return nil, nil, programStoreError(err)
	}
	if implementation == nil || implementation.TenantID != request.TenantID || implementation.ProgramID != request.ProgramID {
		return nil, nil, ports.ErrControlImplementationNotFound
	}
	if implementation.AggregateVersion != request.ExpectedImplementationVersion {
		return nil, nil, ports.ErrComplianceProgramVersionConflict
	}
	previous, err := service.store.GetControlImplementationRevision(ctx, request.TenantID, request.ProgramID, request.ImplementationID, implementation.CurrentRevisionID)
	if err != nil {
		return nil, nil, programStoreError(err)
	}
	return implementation, previous, nil
}

func normalizeImplementationRequest(request RecordImplementationRevisionRequest) RecordImplementationRevisionRequest {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ProgramID = strings.TrimSpace(request.ProgramID)
	request.ImplementationID = strings.TrimSpace(request.ImplementationID)
	request.ChangeSummary = strings.TrimSpace(request.ChangeSummary)
	request.CreatedBy = strings.TrimSpace(request.CreatedBy)
	request.Specification = normalizeImplementationSpecification(request.Specification)
	return request
}

func validateImplementationRequest(request RecordImplementationRevisionRequest) error {
	if request.TenantID == "" || request.ProgramID == "" || request.ExpectedProgramVersion == 0 || request.ChangeSummary == "" || request.CreatedBy == "" {
		return fmt.Errorf("%w: tenant, program, expected version, change summary, and actor are required", ErrInvalidProgramRequest)
	}
	return validateImplementationSpecification(request.Specification)
}

func normalizeImplementationSpecification(value ControlImplementationSpecification) ControlImplementationSpecification {
	value.ScopeRevisionID = strings.TrimSpace(value.ScopeRevisionID)
	value.ControlRef = compliance.NormalizeControlRef(value.ControlRef)
	value.StatementID = strings.TrimSpace(value.StatementID)
	value.ObjectiveIDs = normalizedStrings(value.ObjectiveIDs)
	value.Status = strings.TrimSpace(value.Status)
	value.Narrative = strings.TrimSpace(value.Narrative)
	value.Procedure = strings.TrimSpace(value.Procedure)
	value.OwnerTeam = strings.TrimSpace(value.OwnerTeam)
	value.ReviewPolicy.Cadence = strings.TrimSpace(value.ReviewPolicy.Cadence)
	value.ReviewPolicy.EffectiveFrom = compliance.CanonicalRevisionTime(value.ReviewPolicy.EffectiveFrom)
	value.ReviewPolicy.EffectiveUntil = compliance.CanonicalRevisionTime(value.ReviewPolicy.EffectiveUntil)
	value.ResponsibleRoles = normalizedStrings(value.ResponsibleRoles)
	value.AccountableRoles = normalizedStrings(value.AccountableRoles)
	value.Responsibility = strings.TrimSpace(value.Responsibility)
	if value.UpstreamImplementation != nil {
		reference := normalizeSubjectRefs([]compliance.SubjectRef{*value.UpstreamImplementation})[0]
		value.UpstreamImplementation = &reference
	}
	value.SubjectRefs = normalizeSubjectRefs(value.SubjectRefs)
	value.ParameterValues = normalizeParameters(value.ParameterValues)
	value.MappingRefs = normalizeMappingRefs(value.MappingRefs)
	value.ExpectedTestRefs = normalizeSubjectRefs(value.ExpectedTestRefs)
	value.EvidenceRequirementRefs = normalizeSubjectRefs(value.EvidenceRequirementRefs)
	value.SourceDimensionRefs = normalizeSubjectRefs(value.SourceDimensionRefs)
	value.RiskRefs = normalizeSubjectRefs(value.RiskRefs)
	value.ExceptionRefs = normalizeSubjectRefs(value.ExceptionRefs)
	value.MaterialChangeCriteria = normalizedStrings(value.MaterialChangeCriteria)
	value.InvalidationRules = normalizedStrings(value.InvalidationRules)
	return value
}

func validateImplementationSpecification(value ControlImplementationSpecification) error {
	if value.ScopeRevisionID == "" || value.ControlRef.ControlID == "" || (value.ControlRef.FrameworkID == "" && value.ControlRef.FrameworkName == "") {
		return fmt.Errorf("%w: scope revision and exact control reference are required", ErrInvalidProgramRequest)
	}
	if value.Narrative == "" || value.OwnerTeam == "" || len(value.ResponsibleRoles) == 0 || len(value.AccountableRoles) == 0 {
		return fmt.Errorf("%w: narrative, owner, responsible roles, and accountable roles are required", ErrInvalidProgramRequest)
	}
	if value.ReviewPolicy.Cadence == "" || value.ReviewPolicy.EffectiveFrom.IsZero() {
		return fmt.Errorf("%w: review cadence and effective_from are required", ErrInvalidProgramRequest)
	}
	if !value.ReviewPolicy.EffectiveUntil.IsZero() && !value.ReviewPolicy.EffectiveUntil.After(value.ReviewPolicy.EffectiveFrom) {
		return fmt.Errorf("%w: effective_until must be after effective_from", ErrInvalidProgramRequest)
	}
	if !knownImplementationStatus(value.Status) || !knownResponsibility(value.Responsibility) {
		return fmt.Errorf("%w: implementation status or responsibility mode is invalid", ErrInvalidProgramRequest)
	}
	if (value.Responsibility == ResponsibilityInherited || value.Responsibility == ResponsibilityShared) && value.UpstreamImplementation == nil {
		return fmt.Errorf("%w: inherited and shared responsibilities require an upstream implementation", ErrInvalidProgramRequest)
	}
	if value.UpstreamImplementation != nil {
		if err := value.UpstreamImplementation.Validate(); err != nil {
			return fmt.Errorf("%w: invalid upstream implementation: %w", ErrInvalidProgramRequest, err)
		}
	}
	for _, parameter := range value.ParameterValues {
		if parameter.Name == "" || parameter.Value == "" || parameter.Rationale == "" {
			return fmt.Errorf("%w: implementation parameters require name, value, and rationale", ErrInvalidProgramRequest)
		}
	}
	for _, reference := range appendImplementationSubjectRefs(value) {
		if err := reference.Validate(); err != nil {
			return fmt.Errorf("%w: invalid implementation subject: %w", ErrInvalidProgramRequest, err)
		}
	}
	for _, mapping := range value.MappingRefs {
		if err := validateMappingRef(mapping); err != nil {
			return err
		}
	}
	return nil
}

func normalizeMappingRefs(values []ControlMappingRef) []ControlMappingRef {
	result := append([]ControlMappingRef(nil), values...)
	for index := range result {
		mapping := &result[index]
		mapping.ID = strings.TrimSpace(mapping.ID)
		mapping.RevisionID = strings.TrimSpace(mapping.RevisionID)
		mapping.Granularity = strings.TrimSpace(mapping.Granularity)
		mapping.Method = strings.TrimSpace(mapping.Method)
		mapping.Rationale = strings.TrimSpace(mapping.Rationale)
		mapping.Gaps = normalizedStrings(mapping.Gaps)
		mapping.Provenance = normalizeSubjectRefs(mapping.Provenance)
		mapping.AuthorID = strings.TrimSpace(mapping.AuthorID)
		mapping.ReviewerID = strings.TrimSpace(mapping.ReviewerID)
		mapping.Source = compliance.NormalizeRevisionRef(mapping.Source)
		mapping.Target = compliance.NormalizeRevisionRef(mapping.Target)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID+"\x00"+result[i].RevisionID < result[j].ID+"\x00"+result[j].RevisionID
	})
	return result
}

func validateMappingRef(value ControlMappingRef) error {
	if err := compliance.ValidateIdentifier(compliance.IdentifierMapping, value.ID); err != nil {
		return fmt.Errorf("%w: mapping id: %w", ErrInvalidProgramRequest, err)
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierMapping, value.RevisionID); err != nil {
		return fmt.Errorf("%w: mapping revision id: %w", ErrInvalidProgramRequest, err)
	}
	if value.Granularity == "" {
		return fmt.Errorf("%w: mapping granularity is required", ErrInvalidProgramRequest)
	}
	if value.Method == "" || value.Rationale == "" || value.AuthorID == "" {
		return fmt.Errorf("%w: mapping method, rationale, and author are required", ErrInvalidProgramRequest)
	}
	if err := value.Source.Validate(); err != nil {
		return fmt.Errorf("%w: mapping source: %w", ErrInvalidProgramRequest, err)
	}
	if err := value.Target.Validate(); err != nil {
		return fmt.Errorf("%w: mapping target: %w", ErrInvalidProgramRequest, err)
	}
	if value.Source.ID == value.Target.ID && value.Source.RevisionID == value.Target.RevisionID {
		return fmt.Errorf("%w: mapping source and target must differ", ErrInvalidProgramRequest)
	}
	for _, reference := range value.Provenance {
		if err := reference.Validate(); err != nil {
			return fmt.Errorf("%w: mapping provenance: %w", ErrInvalidProgramRequest, err)
		}
	}
	switch value.DecisionState {
	case compliance.MappingProposed:
	case compliance.MappingApproved, compliance.MappingRejected, compliance.MappingRetired:
		if value.ReviewerID == "" {
			return fmt.Errorf("%w: decided mappings require a reviewer", ErrInvalidProgramRequest)
		}
	default:
		return fmt.Errorf("%w: mapping decision state is invalid", ErrInvalidProgramRequest)
	}
	if value.CoverageBasisPoints > 10000 {
		return fmt.Errorf("%w: mapping coverage exceeds 10000 basis points", ErrInvalidProgramRequest)
	}
	switch value.Relationship {
	case compliance.MappingEquivalent:
		if value.CoverageBasisPoints != 10000 {
			return fmt.Errorf("%w: equivalent mappings require full coverage", ErrInvalidProgramRequest)
		}
		return nil
	case compliance.MappingNone:
		if value.CoverageBasisPoints != 0 {
			return fmt.Errorf("%w: no-relationship mappings require zero coverage", ErrInvalidProgramRequest)
		}
		return nil
	case compliance.MappingSubset, compliance.MappingSuperset, compliance.MappingOverlap:
		return nil
	default:
		return fmt.Errorf("%w: mapping relationship is invalid", ErrInvalidProgramRequest)
	}
}

func appendImplementationSubjectRefs(value ControlImplementationSpecification) []compliance.SubjectRef {
	result := append([]compliance.SubjectRef(nil), value.SubjectRefs...)
	result = append(result, value.ExpectedTestRefs...)
	result = append(result, value.EvidenceRequirementRefs...)
	result = append(result, value.SourceDimensionRefs...)
	result = append(result, value.RiskRefs...)
	result = append(result, value.ExceptionRefs...)
	return result
}

func knownImplementationStatus(value string) bool {
	switch value {
	case ImplementationPlanned, ImplementationPartial, ImplementationImplemented,
		ImplementationAlternative, ImplementationNotApplicable, ImplementationRetired:
		return true
	default:
		return false
	}
}

func knownResponsibility(value string) bool {
	switch value {
	case ResponsibilityDirect, ResponsibilityProvided, ResponsibilityCustomerResponsibility,
		ResponsibilityShared, ResponsibilityInherited:
		return true
	default:
		return false
	}
}
