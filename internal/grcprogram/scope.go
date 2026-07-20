package grcprogram

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
)

type RecordScopeRevisionRequest struct {
	TenantID               string
	ProgramID              string
	ExpectedProgramVersion uint64
	State                  string
	ChangeSummary          string
	CreatedBy              string
	Cutoff                 time.Time
	Specification          ProgramScopeSpecification
}

type RecordScopeRevisionResult struct {
	Program  *ComplianceProgramRecord
	Revision *ProgramScopeRevisionRecord
}

func (service *Service) RecordScopeRevision(ctx context.Context, request RecordScopeRevisionRequest) (*RecordScopeRevisionResult, error) {
	if service == nil || service.store == nil || service.resolver == nil {
		return nil, ErrProgramUnavailable
	}
	request = normalizeScopeRevisionRequest(request)
	if err := validateScopeRevisionRequest(request); err != nil {
		return nil, err
	}
	program, err := service.GetProgram(ctx, request.TenantID, request.ProgramID)
	if err != nil {
		return nil, err
	}
	if request.ExpectedProgramVersion != program.AggregateVersion {
		return nil, ports.ErrComplianceProgramVersionConflict
	}

	var previous *ProgramScopeRevisionRecord
	if program.CurrentScopeRevisionID != "" {
		previous, err = service.store.GetProgramScopeRevision(ctx, request.TenantID, request.ProgramID, program.CurrentScopeRevisionID)
		if err != nil {
			return nil, programStoreError(err)
		}
	}
	batch, err := service.resolver.ResolveProgramSubjects(ctx, SubjectResolutionRequest{
		TenantID: request.TenantID, Selectors: request.Specification.Selectors, Cutoff: request.Cutoff,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve program subjects: %w", err)
	}
	if !compliance.CanonicalRevisionTime(batch.Cutoff).Equal(request.Cutoff) {
		return nil, fmt.Errorf("%w: subject resolution cutoff differs from the requested cutoff", ErrInvalidProgramRequest)
	}
	manifest, err := BuildSubjectManifest(request.Specification.Selectors, batch)
	if err != nil {
		return nil, err
	}
	request.Specification.SubjectManifest = manifest
	request.Specification = normalizeScopeSpecification(request.Specification)
	if err := validateScopeSpecification(request.Specification); err != nil {
		return nil, err
	}

	scopeID := program.ScopeID
	if scopeID == "" {
		scopeID, err = service.newID(compliance.IdentifierScope)
		if err != nil {
			return nil, fmt.Errorf("create scope identifier: %w", err)
		}
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierScope, scopeID); err != nil {
		return nil, fmt.Errorf("%w: scope id: %w", ErrInvalidProgramRequest, err)
	}
	revisionID, err := service.newRevision(compliance.IdentifierScope)
	if err != nil {
		return nil, fmt.Errorf("create scope revision identifier: %w", err)
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierScope, revisionID); err != nil {
		return nil, fmt.Errorf("%w: scope revision id: %w", ErrInvalidProgramRequest, err)
	}
	version := uint64(1)
	predecessorID := ""
	if previous != nil {
		if previous.Version.ID != scopeID {
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
	revision := ProgramScopeRevisionRecord{
		TenantID: request.TenantID, ProgramID: request.ProgramID, State: request.State,
		Version: compliance.VersionMetadata{
			ID: scopeID, RevisionID: revisionID, Version: version, LastModified: now,
			ContentDigest: digest, CreatedBy: request.CreatedBy, PredecessorID: predecessorID,
		},
		ChangeSummary: request.ChangeSummary, Specification: request.Specification,
	}
	updated, err := service.store.AppendProgramScopeRevision(ctx, AppendProgramScopeRevisionRequest{
		TenantID: request.TenantID, ProgramID: request.ProgramID,
		ExpectedProgramVersion: request.ExpectedProgramVersion, Revision: revision,
	})
	if err != nil {
		return nil, programStoreError(err)
	}
	return &RecordScopeRevisionResult{Program: updated, Revision: &revision}, nil
}

// BuildSubjectManifest converts per-selector resolution facts into one stable
// included-subject set while retaining zero-match and unresolved selectors as
// separate, reviewable outcomes.
func BuildSubjectManifest(selectors []ProgramScopeSelector, batch SubjectResolutionBatch) (ProgramSubjectManifest, error) {
	selectors = normalizeSelectors(selectors)
	if err := validateSelectors(selectors); err != nil {
		return ProgramSubjectManifest{}, err
	}
	batch.Cutoff = compliance.CanonicalRevisionTime(batch.Cutoff)
	batch.Watermark = strings.TrimSpace(batch.Watermark)
	if batch.Cutoff.IsZero() || batch.Watermark == "" {
		return ProgramSubjectManifest{}, fmt.Errorf("%w: subject resolution cutoff and watermark are required", ErrInvalidProgramRequest)
	}

	selectorByID := make(map[string]ProgramScopeSelector, len(selectors))
	for _, selector := range selectors {
		selectorByID[selector.ID] = selector
	}
	resolutionByID := make(map[string]SelectorResolution, len(batch.Resolutions))
	for _, resolution := range batch.Resolutions {
		resolution = normalizeSelectorResolution(resolution)
		if _, exists := selectorByID[resolution.SelectorID]; !exists {
			return ProgramSubjectManifest{}, fmt.Errorf("%w: resolution references an unknown selector", ErrInvalidProgramRequest)
		}
		if _, exists := resolutionByID[resolution.SelectorID]; exists {
			return ProgramSubjectManifest{}, fmt.Errorf("%w: duplicate selector resolution", ErrInvalidProgramRequest)
		}
		if err := validateSelectorResolution(resolution); err != nil {
			return ProgramSubjectManifest{}, err
		}
		resolutionByID[resolution.SelectorID] = resolution
	}

	included := map[string]compliance.SubjectRef{}
	excluded := map[string]struct{}{}
	manifest := ProgramSubjectManifest{Watermark: batch.Watermark, Cutoff: batch.Cutoff}
	for _, selector := range selectors {
		resolution, exists := resolutionByID[selector.ID]
		if !exists {
			return ProgramSubjectManifest{}, fmt.Errorf("%w: selector resolution is missing", ErrInvalidProgramRequest)
		}
		manifest.SelectorResolutions = append(manifest.SelectorResolutions, resolution)
		if resolution.State == SubjectResolutionUnresolved {
			manifest.UnresolvedSelectorIDs = append(manifest.UnresolvedSelectorIDs, selector.ID)
			continue
		}
		if len(resolution.Subjects) == 0 {
			manifest.ZeroMatchSelectorIDs = append(manifest.ZeroMatchSelectorIDs, selector.ID)
		}
		for _, subject := range resolution.Subjects {
			key := subjectKey(subject)
			if selector.Mode == ScopeSelectorExclude {
				excluded[key] = struct{}{}
				continue
			}
			included[key] = subject
		}
	}
	for key, subject := range included {
		if _, removed := excluded[key]; removed {
			continue
		}
		manifest.Subjects = append(manifest.Subjects, subject)
	}
	manifest.Subjects = normalizeSubjectRefs(manifest.Subjects)
	manifest.ZeroMatchSelectorIDs = normalizedStrings(manifest.ZeroMatchSelectorIDs)
	manifest.UnresolvedSelectorIDs = normalizedStrings(manifest.UnresolvedSelectorIDs)
	sort.Slice(manifest.SelectorResolutions, func(i, j int) bool {
		return manifest.SelectorResolutions[i].SelectorID < manifest.SelectorResolutions[j].SelectorID
	})
	digestInput := manifest
	digestInput.ContentDigest = ""
	digest, err := semanticDigest(digestInput)
	if err != nil {
		return ProgramSubjectManifest{}, err
	}
	manifest.ContentDigest = digest
	return manifest, nil
}

func normalizeScopeRevisionRequest(request RecordScopeRevisionRequest) RecordScopeRevisionRequest {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.ProgramID = strings.TrimSpace(request.ProgramID)
	request.State = strings.TrimSpace(request.State)
	request.ChangeSummary = strings.TrimSpace(request.ChangeSummary)
	request.CreatedBy = strings.TrimSpace(request.CreatedBy)
	request.Cutoff = compliance.CanonicalRevisionTime(request.Cutoff)
	if request.State == "" {
		request.State = ScopeRevisionProposed
	}
	request.Specification = normalizeScopeSpecification(request.Specification)
	return request
}

func validateScopeRevisionRequest(request RecordScopeRevisionRequest) error {
	if request.TenantID == "" || request.ProgramID == "" || request.ExpectedProgramVersion == 0 || request.ChangeSummary == "" || request.CreatedBy == "" || request.Cutoff.IsZero() {
		return fmt.Errorf("%w: tenant, program, expected version, change summary, actor, and cutoff are required", ErrInvalidProgramRequest)
	}
	if request.State != ScopeRevisionProposed && request.State != ScopeRevisionActive {
		return fmt.Errorf("%w: unknown scope revision state %q", ErrInvalidProgramRequest, request.State)
	}
	return validateScopeSpecification(request.Specification)
}

func normalizeScopeSpecification(value ProgramScopeSpecification) ProgramScopeSpecification {
	value.FrameworkRevisions = normalizeRevisionRefs(value.FrameworkRevisions)
	value.ProfileRevisions = normalizeRevisionRefs(value.ProfileRevisions)
	value.Selectors = normalizeSelectors(value.Selectors)
	value.Parameters = normalizeParameters(value.Parameters)
	value.EvidenceWindow = strings.TrimSpace(value.EvidenceWindow)
	value.MonitoringCadence = strings.TrimSpace(value.MonitoringCadence)
	value.SourceProofPolicy = strings.TrimSpace(value.SourceProofPolicy)
	value.MaterialityLevel = strings.TrimSpace(value.MaterialityLevel)
	return value
}

func validateScopeSpecification(value ProgramScopeSpecification) error {
	if len(value.FrameworkRevisions) == 0 || len(value.ProfileRevisions) == 0 {
		return fmt.Errorf("%w: framework and profile revisions are required", ErrInvalidProgramRequest)
	}
	for _, revision := range append(append([]compliance.RevisionRef(nil), value.FrameworkRevisions...), value.ProfileRevisions...) {
		if err := revision.Validate(); err != nil {
			return fmt.Errorf("%w: invalid framework or profile revision: %w", ErrInvalidProgramRequest, err)
		}
	}
	if err := validateSelectors(value.Selectors); err != nil {
		return err
	}
	for _, parameter := range value.Parameters {
		if parameter.Name == "" || parameter.Value == "" || parameter.Rationale == "" {
			return fmt.Errorf("%w: scope parameters require name, value, and rationale", ErrInvalidProgramRequest)
		}
	}
	return nil
}

func normalizeSelectors(values []ProgramScopeSelector) []ProgramScopeSelector {
	result := append([]ProgramScopeSelector(nil), values...)
	for index := range result {
		selector := &result[index]
		selector.ID = strings.TrimSpace(selector.ID)
		selector.Kind = strings.TrimSpace(selector.Kind)
		selector.Mode = strings.TrimSpace(selector.Mode)
		selector.Source = strings.TrimSpace(selector.Source)
		selector.Reason = strings.TrimSpace(selector.Reason)
		selector.ApproverID = strings.TrimSpace(selector.ApproverID)
		selector.SupersedesSelectorID = strings.TrimSpace(selector.SupersedesSelectorID)
		selector.EffectiveFrom = compliance.CanonicalRevisionTime(selector.EffectiveFrom)
		selector.EffectiveUntil = compliance.CanonicalRevisionTime(selector.EffectiveUntil)
		selector.ReviewAt = compliance.CanonicalRevisionTime(selector.ReviewAt)
		selector.Criteria = append([]ScopeSelectorCriterion(nil), selector.Criteria...)
		for criterionIndex := range selector.Criteria {
			criterion := &selector.Criteria[criterionIndex]
			criterion.Field = strings.TrimSpace(criterion.Field)
			criterion.Operator = strings.TrimSpace(criterion.Operator)
			criterion.Value = strings.TrimSpace(criterion.Value)
		}
		sort.Slice(selector.Criteria, func(i, j int) bool {
			left, right := selector.Criteria[i], selector.Criteria[j]
			return left.Field+"\x00"+left.Operator+"\x00"+left.Value < right.Field+"\x00"+right.Operator+"\x00"+right.Value
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func validateSelectors(values []ProgramScopeSelector) error {
	if len(values) == 0 {
		return fmt.Errorf("%w: at least one scope selector is required", ErrInvalidProgramRequest)
	}
	seen := map[string]struct{}{}
	hasInclude := false
	for _, selector := range values {
		if selector.ID == "" || selector.Kind == "" || selector.Source == "" || selector.Reason == "" || selector.ApproverID == "" || selector.EffectiveFrom.IsZero() {
			return fmt.Errorf("%w: selectors require id, kind, source, reason, approver, and effective_from", ErrInvalidProgramRequest)
		}
		if _, exists := seen[selector.ID]; exists {
			return fmt.Errorf("%w: duplicate selector id", ErrInvalidProgramRequest)
		}
		seen[selector.ID] = struct{}{}
		if selector.Mode != ScopeSelectorInclude && selector.Mode != ScopeSelectorExclude {
			return fmt.Errorf("%w: selector mode is invalid", ErrInvalidProgramRequest)
		}
		if selector.Mode == ScopeSelectorInclude {
			hasInclude = true
		}
		if !knownSelectorKind(selector.Kind) || len(selector.Criteria) == 0 {
			return fmt.Errorf("%w: selector kind or criteria are invalid", ErrInvalidProgramRequest)
		}
		for _, criterion := range selector.Criteria {
			if criterion.Field == "" || criterion.Value == "" || !knownSelectorOperator(criterion.Operator) {
				return fmt.Errorf("%w: selector criterion is invalid", ErrInvalidProgramRequest)
			}
		}
	}
	if !hasInclude {
		return fmt.Errorf("%w: at least one include selector is required", ErrInvalidProgramRequest)
	}
	return nil
}

func normalizeSelectorResolution(value SelectorResolution) SelectorResolution {
	value.SelectorID = strings.TrimSpace(value.SelectorID)
	value.State = strings.TrimSpace(value.State)
	value.ReasonCode = strings.TrimSpace(value.ReasonCode)
	value.Subjects = normalizeSubjectRefs(value.Subjects)
	return value
}

func validateSelectorResolution(value SelectorResolution) error {
	if value.SelectorID == "" {
		return fmt.Errorf("%w: selector resolution id is required", ErrInvalidProgramRequest)
	}
	switch value.State {
	case SubjectResolutionResolved:
		if value.ReasonCode != "" {
			return fmt.Errorf("%w: resolved selector cannot have an unresolved reason", ErrInvalidProgramRequest)
		}
	case SubjectResolutionUnresolved:
		if !knownUnresolvedReason(value.ReasonCode) || len(value.Subjects) != 0 {
			return fmt.Errorf("%w: unresolved selector requires a bounded reason and no subjects", ErrInvalidProgramRequest)
		}
	default:
		return fmt.Errorf("%w: selector resolution state is invalid", ErrInvalidProgramRequest)
	}
	for _, subject := range value.Subjects {
		if err := subject.Validate(); err != nil {
			return fmt.Errorf("%w: invalid resolved subject: %w", ErrInvalidProgramRequest, err)
		}
	}
	return nil
}

func knownSelectorKind(value string) bool {
	switch value {
	case "system", "product", "business_unit", "region", "account", "environment", "data", "data_class", "people", "asset", "application", "vendor":
		return true
	default:
		return false
	}
}

func knownSelectorOperator(value string) bool {
	switch value {
	case "equals", "in", "prefix":
		return true
	default:
		return false
	}
}

func knownUnresolvedReason(value string) bool {
	switch value {
	case SubjectUnresolvedUnsupported, SubjectUnresolvedSourceUnavailable,
		SubjectUnresolvedInvalidSelector, SubjectUnresolvedWatermarkUnavailable:
		return true
	default:
		return false
	}
}
