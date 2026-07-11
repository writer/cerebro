package complianceassessment

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

type EvaluateInput struct {
	ResultID               string                                            `json:"result_id"`
	ObjectiveID            string                                            `json:"objective_id"`
	Control                compliance.ControlRef                             `json:"control_ref"`
	ScopeState             ScopeState                                        `json:"scope_state"`
	EvidenceIndex          *compliance.ControlEvidenceRequirementIndex       `json:"-"`
	Evidence               []compliance.ControlEvidenceRequirementSignal     `json:"evidence,omitempty"`
	RequirementAssessments []compliance.ControlEvidenceRequirementAssessment `json:"requirement_assessments,omitempty"`
	CoverageState          CoverageState                                     `json:"coverage_state"`
	SourceState            SourceState                                       `json:"source_state"`
	SourceRuntimeIDs       []string                                          `json:"source_runtime_ids,omitempty"`
	FindingIDs             []string                                          `json:"finding_ids,omitempty"`
	InvalidEvidence        bool                                              `json:"invalid_evidence,omitempty"`
	ConflictingEvidence    bool                                              `json:"conflicting_evidence,omitempty"`
	DispositionState       DispositionState                                  `json:"disposition_state,omitempty"`
	DesignState            DesignState                                       `json:"design_state,omitempty"`
	OperatingState         OperatingEffectivenessState                       `json:"operating_effectiveness_state,omitempty"`
	Inherited              bool                                              `json:"inherited,omitempty"`
	Sampled                bool                                              `json:"sampled,omitempty"`
	EvaluatorRevision      string                                            `json:"evaluator_revision"`
	Now                    time.Time                                         `json:"now"`
}

// EvaluateObjective derives one deterministic, multi-axis result. Missing
// coverage, evidence, or source trust always resolves to an explicit limitation;
// an empty finding set is never sufficient to pass.
func EvaluateObjective(input EvaluateInput) (ObjectiveResult, error) {
	input = normalizeEvaluateInput(input)
	if err := ValidateEvaluateInput(input); err != nil {
		return ObjectiveResult{}, err
	}
	now := CanonicalTime(input.Now)
	result := ObjectiveResult{
		ID:                          strings.TrimSpace(input.ResultID),
		ControlRef:                  input.Control,
		ObjectiveID:                 strings.TrimSpace(input.ObjectiveID),
		ScopeState:                  input.ScopeState,
		AutomatedOutcome:            OutcomeIndeterminate,
		DesignState:                 input.DesignState,
		OperatingEffectivenessState: input.OperatingState,
		EvidenceState:               EvidenceIncomplete,
		DispositionState:            input.DispositionState,
		Assurance:                   AssuranceNone,
		AuditorState:                AuditorNotReviewed,
		FindingIDs:                  input.FindingIDs,
		SourceRuntimeIDs:            input.SourceRuntimeIDs,
		EvaluatorRevision:           strings.TrimSpace(input.EvaluatorRevision),
		EvaluatedAt:                 now,
	}
	if result.ScopeState == "" {
		result.ScopeState = ScopeUnresolved
	}
	if result.DesignState == "" {
		result.DesignState = DesignUnknown
	}
	if result.OperatingEffectivenessState == "" {
		result.OperatingEffectivenessState = OperatingUnknown
	}
	if result.DispositionState == "" {
		result.DispositionState = DispositionNone
	}
	assessments := append([]compliance.ControlEvidenceRequirementAssessment(nil), input.RequirementAssessments...)
	if assessments == nil && input.EvidenceIndex != nil {
		assessments = compliance.AssessControlEvidenceRequirements(compliance.ControlEvidenceRequirementAssessmentInput{
			Index: input.EvidenceIndex, Control: input.Control, Evidence: input.Evidence, Now: now,
		})
	}
	for _, assessment := range assessments {
		result.EvidenceIDs = append(result.EvidenceIDs, assessment.EvidenceIDs...)
	}

	switch result.ScopeState {
	case ScopeNotApplicable:
		result.AutomatedOutcome = OutcomeNotAssessed
		result.EvidenceState = EvidenceSufficient
		result.DesignState = DesignNotAssessed
		result.OperatingEffectivenessState = OperatingNotTested
		result.ReasonCodes = append(result.ReasonCodes, ReasonNotApplicable)
		result.NextActions = append(result.NextActions, ActionNone)
		return validatedResult(result)
	case ScopeUnresolved:
		result.ReasonCodes = append(result.ReasonCodes, ReasonScopeUnresolved)
		result.NextActions = append(result.NextActions, ActionResolveScope)
		return validatedResult(applyDisposition(NormalizeResult(result)))
	}

	evidenceState, reasons, actions := evaluateEvidence(assessments, input)
	result.EvidenceState = evidenceState
	result.ReasonCodes = append(result.ReasonCodes, reasons...)
	result.NextActions = append(result.NextActions, actions...)
	if len(result.FindingIDs) != 0 {
		result.AutomatedOutcome = OutcomeNotSatisfied
		result.ReasonCodes = append(result.ReasonCodes, ReasonActiveFinding)
		result.NextActions = append(result.NextActions, ActionRemediate)
		if result.DesignState == DesignUnknown {
			result.DesignState = DesignIneffective
		}
		if result.OperatingEffectivenessState == OperatingUnknown {
			result.OperatingEffectivenessState = OperatingIneffective
		}
	} else if evidenceState == EvidenceSufficient && input.CoverageState == CoverageComplete && input.SourceState == SourceSupported {
		result.AutomatedOutcome = OutcomeSatisfied
		result.ReasonCodes = append(result.ReasonCodes, ReasonSatisfied)
		result.NextActions = append(result.NextActions, ActionNone)
		if result.DesignState == DesignUnknown {
			result.DesignState = DesignEffective
		}
		if result.OperatingEffectivenessState == OperatingUnknown {
			result.OperatingEffectivenessState = OperatingEffective
		}
	} else {
		result.AutomatedOutcome = OutcomeIndeterminate
	}
	if input.Inherited {
		result.ReasonCodes = append(result.ReasonCodes, ReasonInheritedResponsibility)
	}
	if input.Sampled {
		result.ReasonCodes = append(result.ReasonCodes, ReasonSampledTesting)
	}
	result.Assurance = deriveAssurance(result, input)
	return validatedResult(applyDisposition(NormalizeResult(result)))
}

func normalizeEvaluateInput(input EvaluateInput) EvaluateInput {
	input.ResultID = strings.TrimSpace(input.ResultID)
	input.ObjectiveID = strings.TrimSpace(input.ObjectiveID)
	input.Control = compliance.NormalizeControlRef(input.Control)
	input.EvaluatorRevision = strings.TrimSpace(input.EvaluatorRevision)
	input.Now = CanonicalTime(input.Now)
	if input.ScopeState == "" {
		input.ScopeState = ScopeUnresolved
	}
	if input.CoverageState == "" {
		input.CoverageState = CoverageUnknown
	}
	if input.SourceState == "" {
		input.SourceState = SourceUnknown
	}
	if input.DesignState == "" {
		input.DesignState = DesignUnknown
	}
	if input.OperatingState == "" {
		input.OperatingState = OperatingUnknown
	}
	if input.DispositionState == "" {
		input.DispositionState = DispositionNone
	}
	return input
}

func ValidateEvaluateInput(input EvaluateInput) error {
	if input.ResultID == "" || input.ObjectiveID == "" || strings.TrimSpace(input.Control.ControlID) == "" || input.EvaluatorRevision == "" || input.Now.IsZero() {
		return fmt.Errorf("%w: result, objective, control, evaluator revision, and now are required", ErrInvalidResult)
	}
	if !knownScopeState(input.ScopeState) || !knownCoverageState(input.CoverageState) || !knownSourceState(input.SourceState) ||
		!knownDesignState(input.DesignState) || !knownOperatingState(input.OperatingState) || !knownDispositionState(input.DispositionState) {
		return fmt.Errorf("%w: evaluation input contains an unknown required state", ErrInvalidResult)
	}
	for _, assessment := range input.RequirementAssessments {
		switch assessment.Status {
		case compliance.ControlEvidenceRequirementSatisfied,
			compliance.ControlEvidenceRequirementManualReview,
			compliance.ControlEvidenceRequirementMissing,
			compliance.ControlEvidenceRequirementMissingField,
			compliance.ControlEvidenceRequirementStale:
		default:
			return fmt.Errorf("%w: evaluation input contains unknown evidence requirement status %q", ErrInvalidResult, assessment.Status)
		}
	}
	return nil
}

func validatedResult(result ObjectiveResult) (ObjectiveResult, error) {
	result = NormalizeResult(result)
	if err := ValidateObjectiveResult(result); err != nil {
		return ObjectiveResult{}, err
	}
	return result, nil
}

func evaluateEvidence(assessments []compliance.ControlEvidenceRequirementAssessment, input EvaluateInput) (EvidenceState, []ReasonCode, []NextAction) {
	if input.ConflictingEvidence || input.SourceState == SourceConflicting {
		return EvidenceConflicting, []ReasonCode{ReasonEvidenceConflicting}, []NextAction{ActionReview}
	}
	if input.InvalidEvidence {
		return EvidenceUntrusted, []ReasonCode{ReasonEvidenceInvalid}, []NextAction{ActionReview}
	}
	switch input.SourceState {
	case SourceUnverified:
		return EvidenceUntrusted, []ReasonCode{ReasonSourceUntrusted}, []NextAction{ActionReview}
	case SourceUnconfigured:
		return EvidenceIncomplete, []ReasonCode{ReasonSourceUnconfigured}, []NextAction{ActionRestoreSource}
	case SourceUnsupported:
		return EvidenceIncomplete, []ReasonCode{ReasonSourceUnsupported}, []NextAction{ActionRestoreSource}
	case SourceFailed:
		return EvidenceIncomplete, []ReasonCode{ReasonSourceFailed}, []NextAction{ActionRestoreSource}
	case SourcePartial:
		return EvidenceIncomplete, []ReasonCode{ReasonSourcePartial}, []NextAction{ActionRestoreSource}
	case SourceStale:
		return EvidenceStale, []ReasonCode{ReasonSourceStale}, []NextAction{ActionRefreshEvidence}
	case SourceUnknown:
		return EvidenceIncomplete, []ReasonCode{ReasonSourceUnknown}, []NextAction{ActionRestoreSource}
	}
	if input.CoverageState == CoverageEmpty {
		return EvidenceIncomplete, []ReasonCode{ReasonPopulationEmpty}, []NextAction{ActionCollectEvidence}
	}
	if input.CoverageState != CoverageComplete {
		return EvidenceIncomplete, []ReasonCode{ReasonCoverageIncomplete}, []NextAction{ActionCollectEvidence}
	}
	if len(assessments) == 0 {
		return EvidenceMissing, []ReasonCode{ReasonEvidenceMissing}, []NextAction{ActionCollectEvidence}
	}
	state := EvidenceSufficient
	var reasons []ReasonCode
	var actions []NextAction
	for _, assessment := range assessments {
		switch assessment.Status {
		case compliance.ControlEvidenceRequirementSatisfied:
		case compliance.ControlEvidenceRequirementManualReview:
			state = strongestEvidenceState(state, EvidenceManualReview)
			reasons = append(reasons, ReasonManualEvidence)
			actions = append(actions, ActionReview)
		case compliance.ControlEvidenceRequirementStale:
			state = strongestEvidenceState(state, EvidenceStale)
			reasons = append(reasons, ReasonEvidenceStale)
			actions = append(actions, ActionRefreshEvidence)
		case compliance.ControlEvidenceRequirementMissingField:
			state = strongestEvidenceState(state, EvidenceIncomplete)
			reasons = append(reasons, ReasonEvidenceInvalid)
			actions = append(actions, ActionCollectEvidence)
		case compliance.ControlEvidenceRequirementMissing:
			state = strongestEvidenceState(state, EvidenceMissing)
			reasons = append(reasons, ReasonEvidenceMissing)
			actions = append(actions, ActionCollectEvidence)
		default:
			state = strongestEvidenceState(state, EvidenceManualReview)
			reasons = append(reasons, ReasonEvidenceInvalid)
			actions = append(actions, ActionReview)
		}
	}
	return state, reasons, actions
}

func strongestEvidenceState(left, right EvidenceState) EvidenceState {
	rank := map[EvidenceState]int{
		EvidenceSufficient: 0, EvidenceManualReview: 1, EvidenceStale: 2,
		EvidenceMissing: 3, EvidenceIncomplete: 4, EvidenceUntrusted: 5, EvidenceConflicting: 6,
	}
	if rank[right] > rank[left] {
		return right
	}
	return left
}

func deriveAssurance(result ObjectiveResult, input EvaluateInput) Assurance {
	if result.AutomatedOutcome == OutcomeSatisfied && result.EvidenceState == EvidenceSufficient {
		if input.Inherited || input.Sampled {
			return AssuranceMedium
		}
		return AssuranceHigh
	}
	if result.AutomatedOutcome == OutcomeNotSatisfied && result.EvidenceState == EvidenceSufficient {
		return AssuranceHigh
	}
	if result.EvidenceState == EvidenceManualReview || result.EvidenceState == EvidenceStale {
		return AssuranceLow
	}
	return AssuranceNone
}

func applyDisposition(result ObjectiveResult) ObjectiveResult {
	switch result.DispositionState {
	case DispositionAcceptedException:
		result.ReasonCodes = append(result.ReasonCodes, ReasonAcceptedException)
		result.NextActions = append(result.NextActions, ActionRetest)
	case DispositionAcceptedRisk:
		result.ReasonCodes = append(result.ReasonCodes, ReasonAcceptedRisk)
		result.NextActions = append(result.NextActions, ActionRetest)
	}
	return NormalizeResult(result)
}
