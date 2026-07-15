package complianceremediation

import (
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/complianceassessment"
)

func workItemInput(input DeriveWorkInput) (complianceassessment.WorkItemInput, error) {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.ScopeRevisionID = strings.TrimSpace(input.ScopeRevisionID)
	input.SubjectID = strings.TrimSpace(input.SubjectID)
	input.SourceID = strings.TrimSpace(input.SourceID)
	input.OwnerID = strings.TrimSpace(input.OwnerID)
	if input.SourceID == "" && len(input.Result.SourceRuntimeIDs) != 0 {
		input.SourceID = strings.TrimSpace(input.Result.SourceRuntimeIDs[0])
	}
	result := complianceassessment.NormalizeResult(input.Result)
	if err := complianceassessment.ValidateObjectiveResult(result); err != nil {
		return complianceassessment.WorkItemInput{}, err
	}
	if result.AutomatedOutcome != complianceassessment.OutcomeNotSatisfied && result.AutomatedOutcome != complianceassessment.OutcomeIndeterminate {
		return complianceassessment.WorkItemInput{}, fmt.Errorf("%w: only failed or indeterminate results create work", ErrInvalidRequest)
	}
	kind, reason, err := deriveWorkBasis(result)
	if err != nil {
		return complianceassessment.WorkItemInput{}, err
	}
	return complianceassessment.WorkItemInput{
		Basis: complianceassessment.WorkFingerprintInput{
			TenantID: input.TenantID, ProgramID: input.ProgramID, ScopeRevisionID: input.ScopeRevisionID,
			ControlID: result.ControlRef.ControlID, ObjectiveID: result.ObjectiveID, Kind: kind,
			SubjectID: input.SubjectID, Reason: reason, SourceID: input.SourceID,
		},
		OwnerID: input.OwnerID, DueAt: input.DueAt, Priority: input.Priority,
		VerificationRequired: true,
		Occurrence: complianceassessment.WorkOccurrenceInput{
			AssessmentRunID: input.AssessmentRunID, ObjectiveResultID: result.ID,
			AutomatedResultHash: input.AutomatedResultHash, EvidenceIDs: result.EvidenceIDs,
			FindingIDs: result.FindingIDs, OccurredAt: result.EvaluatedAt,
		},
	}, nil
}

func deriveWorkBasis(result complianceassessment.ObjectiveResult) (complianceassessment.WorkItemKind, complianceassessment.ReasonCode, error) {
	priorities := []struct {
		action complianceassessment.NextAction
		kind   complianceassessment.WorkItemKind
	}{
		{complianceassessment.ActionRemediate, complianceassessment.WorkRemediateFinding},
		{complianceassessment.ActionRestoreSource, complianceassessment.WorkRepairSource},
		{complianceassessment.ActionRefreshEvidence, complianceassessment.WorkRefreshEvidence},
		{complianceassessment.ActionCollectEvidence, complianceassessment.WorkCollectEvidence},
		{complianceassessment.ActionReview, complianceassessment.WorkResolveConflict},
		{complianceassessment.ActionResolveScope, complianceassessment.WorkMapControl},
		{complianceassessment.ActionRetest, complianceassessment.WorkRemediateFinding},
	}
	for _, candidate := range priorities {
		if !containsAction(result.NextActions, candidate.action) {
			continue
		}
		return candidate.kind, reasonForAction(candidate.action, result.ReasonCodes), nil
	}
	return "", "", fmt.Errorf("%w: result has no actionable next step", ErrInvalidRequest)
}

func containsAction(actions []complianceassessment.NextAction, target complianceassessment.NextAction) bool {
	for _, action := range actions {
		if action == target {
			return true
		}
	}
	return false
}

func reasonForAction(action complianceassessment.NextAction, reasons []complianceassessment.ReasonCode) complianceassessment.ReasonCode {
	preferred := map[complianceassessment.NextAction][]complianceassessment.ReasonCode{
		complianceassessment.ActionRemediate:       {complianceassessment.ReasonActiveFinding},
		complianceassessment.ActionRefreshEvidence: {complianceassessment.ReasonEvidenceStale, complianceassessment.ReasonSourceStale},
		complianceassessment.ActionCollectEvidence: {complianceassessment.ReasonEvidenceMissing, complianceassessment.ReasonCoverageIncomplete, complianceassessment.ReasonPopulationEmpty},
		complianceassessment.ActionReview:          {complianceassessment.ReasonEvidenceInvalid, complianceassessment.ReasonEvidenceConflicting, complianceassessment.ReasonManualEvidence, complianceassessment.ReasonSourceUntrusted, complianceassessment.ReasonSourceUnknown},
		complianceassessment.ActionRestoreSource:   {complianceassessment.ReasonSourceFailed, complianceassessment.ReasonSourcePartial, complianceassessment.ReasonSourceUnconfigured, complianceassessment.ReasonSourceUnsupported},
		complianceassessment.ActionResolveScope:    {complianceassessment.ReasonScopeUnresolved},
		complianceassessment.ActionRetest:          {complianceassessment.ReasonAcceptedException, complianceassessment.ReasonAcceptedRisk},
	}
	for _, candidate := range preferred[action] {
		for _, reason := range reasons {
			if reason == candidate {
				return candidate
			}
		}
	}
	return reasons[0]
}
