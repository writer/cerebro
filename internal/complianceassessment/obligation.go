package complianceassessment

import (
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

const (
	// ExecutableObligationVersion identifies the compiler and predicate contract
	// used to turn an immutable assessment plan task into an executable rule.
	ExecutableObligationVersion = "assessment-obligation/v1"

	ObligationPredicateNoActiveFindings = "no_active_findings"
)

// ExecutableObligation is the versioned rule the assessment collector runs for
// one objective. Its digest excludes no runtime state, so the same published
// plan revision always compiles to the same obligation set.
type ExecutableObligation struct {
	ModelVersion      string                `json:"model_version"`
	ID                string                `json:"id"`
	PlanRevisionID    string                `json:"plan_revision_id"`
	TaskID            string                `json:"task_id"`
	ObjectiveID       string                `json:"objective_id"`
	ControlRef        compliance.ControlRef `json:"control_ref"`
	EvidenceKind      string                `json:"evidence_kind"`
	RuleID            string                `json:"rule_id"`
	SourceRuntimeIDs  []string              `json:"source_runtime_ids"`
	MaxAge            string                `json:"max_age"`
	EvaluationMode    string                `json:"evaluation_mode"`
	Predicate         string                `json:"predicate"`
	EvaluatorRevision string                `json:"evaluator_revision"`
	Digest            string                `json:"digest"`
}

// CompileExecutableObligations produces the exact ordered obligation set for a
// published plan. Unsupported task kinds fail closed instead of becoming an
// implied manual pass.
func CompileExecutableObligations(plan AssessmentPlanRevision) ([]ExecutableObligation, error) {
	plan = normalizePlan(plan)
	if err := validatePlan(plan); err != nil {
		return nil, err
	}
	tasks, err := orderedFindingEvaluationTasks(plan.Execution)
	if err != nil {
		return nil, err
	}
	obligations := make([]ExecutableObligation, 0, len(tasks))
	for _, task := range tasks {
		obligation := ExecutableObligation{
			ModelVersion:      ExecutableObligationVersion,
			ID:                plan.RevisionID + ":" + task.ID,
			PlanRevisionID:    plan.RevisionID,
			TaskID:            task.ID,
			ObjectiveID:       task.ObjectiveID,
			ControlRef:        task.ControlRef,
			EvidenceKind:      PlanTaskKindFindingEvaluation,
			RuleID:            task.RuleID,
			SourceRuntimeIDs:  append([]string(nil), task.RuntimeIDs...),
			MaxAge:            task.MaxAge,
			EvaluationMode:    task.EvaluationMode,
			Predicate:         ObligationPredicateNoActiveFindings,
			EvaluatorRevision: findingEvaluationCollectorRevision,
		}
		obligation, err = normalizeExecutableObligation(obligation)
		if err != nil {
			return nil, fmt.Errorf("compile obligation for task %q: %w", task.ID, err)
		}
		obligations = append(obligations, obligation)
	}
	return obligations, nil
}

func normalizeExecutableObligation(value ExecutableObligation) (ExecutableObligation, error) {
	providedDigest := strings.TrimSpace(value.Digest)
	value.ModelVersion = strings.TrimSpace(value.ModelVersion)
	value.ID = strings.TrimSpace(value.ID)
	value.PlanRevisionID = strings.TrimSpace(value.PlanRevisionID)
	value.TaskID = strings.TrimSpace(value.TaskID)
	value.ObjectiveID = strings.TrimSpace(value.ObjectiveID)
	value.ControlRef = compliance.NormalizeControlRef(value.ControlRef)
	value.EvidenceKind = strings.TrimSpace(value.EvidenceKind)
	value.RuleID = strings.TrimSpace(value.RuleID)
	value.SourceRuntimeIDs = normalizedStrings(value.SourceRuntimeIDs)
	value.MaxAge = strings.TrimSpace(value.MaxAge)
	value.EvaluationMode = strings.TrimSpace(value.EvaluationMode)
	value.Predicate = strings.TrimSpace(value.Predicate)
	value.EvaluatorRevision = strings.TrimSpace(value.EvaluatorRevision)
	value.Digest = ""
	if value.ModelVersion != ExecutableObligationVersion || value.ID == "" || value.PlanRevisionID == "" || value.TaskID == "" || value.ObjectiveID == "" ||
		strings.TrimSpace(value.ControlRef.ControlID) == "" || value.EvidenceKind != PlanTaskKindFindingEvaluation || value.RuleID == "" ||
		len(value.SourceRuntimeIDs) == 0 || value.EvaluationMode != EvaluationModePointInTime || value.Predicate != ObligationPredicateNoActiveFindings ||
		value.EvaluatorRevision == "" {
		return ExecutableObligation{}, fmt.Errorf("%w: executable obligation is incomplete", ErrInvalidResult)
	}
	if maxAge, err := time.ParseDuration(value.MaxAge); err != nil || maxAge <= 0 {
		return ExecutableObligation{}, fmt.Errorf("%w: executable obligation max_age is invalid", ErrInvalidResult)
	}
	digest, err := semanticHash(value)
	if err != nil {
		return ExecutableObligation{}, err
	}
	if providedDigest != "" && providedDigest != digest {
		return ExecutableObligation{}, fmt.Errorf("%w: executable obligation digest does not match content", ErrInvalidResult)
	}
	value.Digest = digest
	return value, nil
}

func executableObligationSetDigest(values []ExecutableObligation) (string, error) {
	normalized := make([]ExecutableObligation, 0, len(values))
	for _, value := range values {
		obligation, err := normalizeExecutableObligation(value)
		if err != nil {
			return "", err
		}
		normalized = append(normalized, obligation)
	}
	return semanticHash(normalized)
}

func executeExecutableObligation(obligation ExecutableObligation, cutoff time.Time, state taskCollectionState) (ObjectiveResult, error) {
	obligation, err := normalizeExecutableObligation(obligation)
	if err != nil {
		return ObjectiveResult{}, err
	}
	cutoff = CanonicalTime(cutoff)
	if cutoff.IsZero() {
		return ObjectiveResult{}, fmt.Errorf("%w: obligation execution cutoff is required", ErrInvalidResult)
	}
	identityDigest, err := semanticHash(struct {
		ObligationDigest string    `json:"obligation_digest"`
		EvaluationRunIDs []string  `json:"evaluation_run_ids"`
		Cutoff           time.Time `json:"cutoff"`
	}{
		ObligationDigest: obligation.Digest,
		EvaluationRunIDs: normalizedStrings(state.evaluationRunIDs),
		Cutoff:           cutoff,
	})
	if err != nil {
		return ObjectiveResult{}, err
	}
	result := ObjectiveResult{
		ID:                          "assessment-result-" + strings.TrimPrefix(identityDigest, "sha256:")[:24],
		ControlRef:                  obligation.ControlRef,
		ObjectiveID:                 obligation.ObjectiveID,
		ScopeState:                  ScopeInScope,
		DesignState:                 DesignUnknown,
		OperatingEffectivenessState: OperatingNotTested,
		DispositionState:            DispositionNone,
		AuditorState:                AuditorNotReviewed,
		EvidenceIDs:                 state.evaluationRunIDs,
		FindingIDs:                  state.findingIDs,
		SourceRuntimeIDs:            obligation.SourceRuntimeIDs,
		EvaluatorRevision:           obligation.EvaluatorRevision,
		EvaluatedAt:                 cutoff,
	}
	switch {
	case state.incomplete:
		result.AutomatedOutcome = OutcomeIndeterminate
		result.EvidenceState = state.evidenceState
		result.Assurance = AssuranceNone
		result.ReasonCodes = state.reasons
		result.NextActions = state.actions
	case len(state.findingIDs) != 0:
		result.AutomatedOutcome = OutcomeNotSatisfied
		result.EvidenceState = EvidenceSufficient
		result.Assurance = AssuranceMedium
		result.ReasonCodes = []ReasonCode{ReasonActiveFinding}
		result.NextActions = []NextAction{ActionRemediate}
	default:
		result.AutomatedOutcome = OutcomeSatisfied
		result.EvidenceState = EvidenceSufficient
		result.Assurance = AssuranceMedium
		result.ReasonCodes = []ReasonCode{ReasonSatisfied}
		result.NextActions = []NextAction{ActionNone}
	}
	return NormalizeResult(result), nil
}
