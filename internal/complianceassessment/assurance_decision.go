package complianceassessment

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var (
	ErrAssuranceDecisionNotFound    = errors.New("assurance decision not found")
	ErrAssuranceDecisionUnavailable = errors.New("assurance decision persistence is unavailable")
)

const AssuranceDecisionVersion = "assurance-decision/v1"

// AssuranceDecision is an immutable decision-time record. InputSnapshot
// preserves the exact proof material evaluated by Qualification; Decision
// preserves the resulting fail-closed verdict and its content-addressed digest.
type AssuranceDecision struct {
	ID              string             `json:"id"`
	TenantID        string             `json:"tenant_id"`
	RunID           string             `json:"run_id"`
	ResultID        string             `json:"result_id"`
	ObjectiveID     string             `json:"objective_id"`
	ProgramID       string             `json:"program_id"`
	ScopeRevisionID string             `json:"scope_revision_id"`
	PlanRevisionID  string             `json:"plan_revision_id"`
	Version         string             `json:"version"`
	InputSnapshot   QualificationInput `json:"input_snapshot"`
	Decision        QualifiedDecision  `json:"decision"`
	RequestHash     string             `json:"request_hash"`
	IdempotencyKey  string             `json:"idempotency_key"`
	RecordedAt      time.Time          `json:"recorded_at"`
	RecordedBy      string             `json:"recorded_by"`
	RecordDigest    string             `json:"record_digest"`
}

type AssuranceDecisionRequest struct {
	TenantID       string
	RunID          string
	ResultID       string
	Input          QualificationInput
	IdempotencyKey string
	RecordedBy     string
}

// RecordAssuranceDecision records a decision only after binding its manifest
// and result to the completed assessment run. An unqualified verdict is still
// a valid durable decision; production authorization remains fail closed via
// QualifiedDecision.AuthorizeProductionUse.
func (s *Service) RecordAssuranceDecision(ctx context.Context, request AssuranceDecisionRequest) (AssuranceDecision, bool, error) {
	decisionStore, ok := s.assuranceDecisionStore()
	if !ok || s.log == nil {
		return AssuranceDecision{}, false, ErrAssuranceDecisionUnavailable
	}
	request = normalizeAssuranceDecisionRequest(request)
	if request.TenantID == "" || request.RunID == "" || request.ResultID == "" || request.IdempotencyKey == "" || request.RecordedBy == "" {
		return AssuranceDecision{}, false, fmt.Errorf("%w: decision request identity is incomplete", ErrInvalidResult)
	}
	run, err := s.store.GetRun(ctx, request.TenantID, request.RunID)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	if run.State != RunComplete || run.InputManifest == nil || run.InputHash == "" || run.AutomatedResultHash == "" || run.CompletedAt.IsZero() {
		return AssuranceDecision{}, false, fmt.Errorf("%w: assessment run is not complete", ErrAssessmentConflict)
	}
	storedManifest := NormalizeManifest(*run.InputManifest)
	storedManifestHash, err := CanonicalManifestDigest(storedManifest)
	if err != nil || storedManifestHash != run.InputHash {
		return AssuranceDecision{}, false, fmt.Errorf("%w: persisted assessment manifest does not match its input hash", ErrAssessmentConflict)
	}
	if !qualificationManifestEmpty(request.Input.Manifest) {
		manifestHash, manifestErr := CanonicalManifestDigest(request.Input.Manifest)
		if manifestErr != nil || manifestHash != storedManifestHash {
			return AssuranceDecision{}, false, fmt.Errorf("%w: decision manifest does not match assessment run", ErrAssessmentConflict)
		}
	}
	result, err := s.findRunResult(ctx, request.TenantID, request.RunID, request.ResultID, run.AutomatedResultHash, run.ResultCount)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	wantResultHash, err := CanonicalResultDigest(result)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	if !qualificationResultEmpty(request.Input.Result) {
		requestResultHash, resultErr := CanonicalResultDigest(request.Input.Result)
		if resultErr != nil || requestResultHash != wantResultHash {
			return AssuranceDecision{}, false, fmt.Errorf("%w: decision result does not match assessment result", ErrAssessmentConflict)
		}
	}
	request.Input.Manifest = storedManifest
	request.Input.Result = result
	request = normalizeAssuranceDecisionRequest(request)
	requestHash, err := semanticHash(request)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	if existing, findErr := decisionStore.FindAssuranceDecisionByIdempotency(ctx, request.TenantID, request.IdempotencyKey); findErr == nil {
		if existing.RequestHash != requestHash {
			return AssuranceDecision{}, false, ports.ErrJobIdempotencyConflict
		}
		return existing, false, nil
	} else if !errors.Is(findErr, ErrAssuranceDecisionNotFound) {
		return AssuranceDecision{}, false, findErr
	}
	recordedAt := CanonicalTime(s.now())
	if request.Input.AsOf.Before(run.CompletedAt) || request.Input.AsOf.After(recordedAt) {
		return AssuranceDecision{}, false, fmt.Errorf("%w: decision time is outside the completed assessment window", ErrInvalidResult)
	}

	qualified := QualifyDecision(ctx, request.Input)
	id, err := compliance.NewIdentifier(compliance.IdentifierDecision)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	record := AssuranceDecision{
		ID: id, TenantID: request.TenantID, RunID: run.ID, ResultID: result.ID,
		ObjectiveID: result.ObjectiveID, ProgramID: run.ProgramID,
		ScopeRevisionID: run.ScopeRevisionID, PlanRevisionID: run.PlanRevisionID,
		Version: AssuranceDecisionVersion, InputSnapshot: request.Input, Decision: qualified,
		RequestHash: requestHash, IdempotencyKey: request.IdempotencyKey,
		RecordedAt: recordedAt, RecordedBy: request.RecordedBy,
	}
	record.RecordDigest, err = assuranceDecisionDigest(record)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	if err := validateAssuranceDecision(record); err != nil {
		return AssuranceDecision{}, false, err
	}
	payload, err := canonicalBytes(record)
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind:     workflowevents.EventKindComplianceAssuranceDecisionRecorded,
		TenantID: record.TenantID, AggregateType: "assurance_decision", AggregateID: record.ID,
		AggregateVersion: 1, Operation: "assurance_decision_recorded",
		ContentDigest: record.RecordDigest, PayloadJSON: string(payload), ActorID: record.RecordedBy,
		RecordedAt: record.RecordedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return AssuranceDecision{}, false, err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return AssuranceDecision{}, false, fmt.Errorf("append assurance decision: %w", err)
	}
	if err := decisionStore.ApplyAssuranceDecision(ctx, event.GetId(), record); err != nil {
		return AssuranceDecision{}, false, fmt.Errorf("project assurance decision: %w", err)
	}
	return record, true, nil
}

func (s *Service) GetAssuranceDecision(ctx context.Context, tenantID, decisionID string) (AssuranceDecision, error) {
	store, ok := s.assuranceDecisionStore()
	if !ok {
		return AssuranceDecision{}, ErrAssuranceDecisionUnavailable
	}
	return store.GetAssuranceDecision(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(decisionID))
}

func (s *Service) assuranceDecisionStore() (AssuranceDecisionStore, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	store, ok := s.store.(AssuranceDecisionStore)
	return store, ok
}

func (s *Service) findRunResult(ctx context.Context, tenantID, runID, resultID, resultSetHash string, resultCount uint64) (ObjectiveResult, error) {
	_, allResults, err := s.loadVerifiedRunResults(ctx, tenantID, runID, resultSetHash, resultCount)
	if err != nil {
		return ObjectiveResult{}, err
	}
	for _, result := range allResults {
		if result.ID == resultID {
			return result, nil
		}
	}
	return ObjectiveResult{}, fmt.Errorf("%w: assessment result %q was not found", ErrInvalidResult, resultID)
}

func (s *Service) loadVerifiedRunResults(ctx context.Context, tenantID, runID, resultSetHash string, resultCount uint64) ([]ResultChunk, []ObjectiveResult, error) {
	chunks, err := s.store.ListResultChunks(ctx, tenantID, runID)
	if err != nil {
		return nil, nil, err
	}
	var (
		allResults []ObjectiveResult
		previous   string
	)
	for index, chunk := range chunks {
		if err := validateRecoveredResultChunk(chunk); err != nil || chunk.Sequence != uint32(index+1) || chunk.PreviousDigest != previous {
			return nil, nil, fmt.Errorf("%w: assessment result chunk chain is invalid", ErrAssessmentConflict)
		}
		previous = chunk.Digest
		for _, result := range chunk.Results {
			allResults = append(allResults, NormalizeResult(result))
		}
	}
	setDigest, err := CanonicalResultSetDigest(allResults)
	if err != nil || setDigest != resultSetHash || uint64(len(allResults)) != resultCount {
		return nil, nil, fmt.Errorf("%w: assessment results do not match completed run", ErrAssessmentConflict)
	}
	return chunks, allResults, nil
}

func normalizeAssuranceDecisionRequest(request AssuranceDecisionRequest) AssuranceDecisionRequest {
	sourceProofsDeclared := request.Input.SourceProofs != nil
	evidenceProofsDeclared := request.Input.EvidenceProofs != nil
	limitationsDeclared := request.Input.Limitations != nil
	reviewsDeclared := request.Input.RequiredReviews != nil
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.RunID = strings.TrimSpace(request.RunID)
	request.ResultID = strings.TrimSpace(request.ResultID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.RecordedBy = strings.TrimSpace(request.RecordedBy)
	request.Input.AsOf = CanonicalTime(request.Input.AsOf)
	request.Input.SourceProofs = normalizeSourceProofs(request.Input.SourceProofs)
	request.Input.EvidenceProofs = normalizeEvidenceProofs(request.Input.EvidenceProofs)
	request.Input.Limitations = normalizeLimitations(request.Input.Limitations)
	request.Input.RequiredReviews = normalizeReviews(request.Input.RequiredReviews)
	if sourceProofsDeclared && request.Input.SourceProofs == nil {
		request.Input.SourceProofs = []SourceProof{}
	}
	if evidenceProofsDeclared && request.Input.EvidenceProofs == nil {
		request.Input.EvidenceProofs = []EvidenceProof{}
	}
	if limitationsDeclared && request.Input.Limitations == nil {
		request.Input.Limitations = []Limitation{}
	}
	if reviewsDeclared && request.Input.RequiredReviews == nil {
		request.Input.RequiredReviews = []ReviewRequirement{}
	}
	request.Input.Exceptions = normalizeExceptionProofs(request.Input.Exceptions)
	request.Input.Verification.VerifiedAt = CanonicalTime(request.Input.Verification.VerifiedAt)
	request.Input.Verification.ValidUntil = CanonicalTime(request.Input.Verification.ValidUntil)
	return request
}

func qualificationManifestEmpty(value InputManifest) bool {
	return strings.TrimSpace(value.ProgramID) == "" && strings.TrimSpace(value.ScopeRevisionID) == "" &&
		strings.TrimSpace(value.PlanRevisionID) == "" && strings.TrimSpace(value.RequestedScopeDigest) == "" &&
		len(value.Revisions) == 0 && len(value.Receipts) == 0
}

func qualificationResultEmpty(value ObjectiveResult) bool {
	return strings.TrimSpace(value.ID) == "" && strings.TrimSpace(value.ObjectiveID) == ""
}

func assuranceDecisionDigest(record AssuranceDecision) (string, error) {
	record.RecordDigest = ""
	return semanticHash(record)
}

func validateAssuranceDecision(record AssuranceDecision) error {
	if compliance.ValidateIdentifier(compliance.IdentifierDecision, record.ID) != nil ||
		record.TenantID == "" || record.RunID == "" || record.ResultID == "" || record.ObjectiveID == "" ||
		record.ProgramID == "" || record.ScopeRevisionID == "" || record.PlanRevisionID == "" ||
		record.Version != AssuranceDecisionVersion || record.RequestHash == "" || record.IdempotencyKey == "" ||
		record.RecordedAt.IsZero() || record.RecordedBy == "" || record.RecordDigest == "" ||
		record.Decision.DecisionDigest == "" || record.Decision.ManifestHash == "" || record.Decision.ResultHash == "" {
		return fmt.Errorf("%w: assurance decision is incomplete", ErrInvalidResult)
	}
	if record.RecordedAt.Before(record.Decision.AsOf) || !record.Decision.AsOf.Equal(record.InputSnapshot.AsOf) ||
		record.InputSnapshot.Manifest.ProgramID != record.ProgramID ||
		record.InputSnapshot.Manifest.ScopeRevisionID != record.ScopeRevisionID ||
		record.InputSnapshot.Manifest.PlanRevisionID != record.PlanRevisionID ||
		record.InputSnapshot.Result.ID != record.ResultID || record.InputSnapshot.Result.ObjectiveID != record.ObjectiveID {
		return fmt.Errorf("%w: assurance decision identity does not match its input snapshot", ErrInvalidResult)
	}
	expected := evaluateQualification(record.InputSnapshot)
	expectedDigest, expectedErr := semanticHash(expected)
	decisionDigest, decisionErr := semanticHash(record.Decision)
	if expectedErr != nil || decisionErr != nil || expectedDigest != decisionDigest {
		return fmt.Errorf("%w: assurance decision verdict does not match its input snapshot", ErrInvalidResult)
	}
	digest, err := assuranceDecisionDigest(record)
	if err != nil || digest != record.RecordDigest {
		return fmt.Errorf("%w: assurance decision record digest does not match", ErrInvalidResult)
	}
	return nil
}
