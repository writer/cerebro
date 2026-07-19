package decisionworkflow

import (
	"fmt"

	"github.com/writer/cerebro/internal/telemetry"
)

type Telemetry struct {
	Workflow         Workflow
	Operation        Operation
	DecisionState    DecisionState
	CoverageState    CoverageState
	FreshnessState   FreshnessState
	ConflictState    ConflictState
	ActionState      ActionState
	Outcome          Outcome
	DismissalReason  DismissalReason
	SchemaVersion    string
	EvidenceCount    int
	CoverageGapCount int
	DurationMillis   int64
}

func (value Telemetry) Attributes() (telemetry.Attributes, error) {
	if !value.Workflow.valid() && value.Workflow != WorkflowUnknown {
		return telemetry.Attributes{}, invalid("workflow", string(value.Workflow))
	}
	if !validOperation(value.Operation) {
		return telemetry.Attributes{}, invalid("operation", string(value.Operation))
	}
	if value.DecisionState == "" {
		value.DecisionState = DecisionUnknown
	}
	if value.CoverageState == "" {
		value.CoverageState = CoverageUnknown
	}
	if value.FreshnessState == "" {
		value.FreshnessState = FreshnessUnknown
	}
	if value.ConflictState == "" {
		value.ConflictState = ConflictUnknown
	}
	if value.ActionState == "" {
		value.ActionState = ActionNone
	}
	if value.Outcome == "" {
		value.Outcome = OutcomeNone
	}
	if value.DismissalReason == "" {
		value.DismissalReason = DismissalNone
	}
	if err := value.validateBoundedStates(); err != nil {
		return telemetry.Attributes{}, err
	}
	return telemetry.Attrs(
		telemetry.Field{Key: "decision.workflow", Value: string(value.Workflow)},
		telemetry.Field{Key: "decision.operation", Value: string(value.Operation)},
		telemetry.Field{Key: "decision.state", Value: string(value.DecisionState)},
		telemetry.Field{Key: "decision.coverage_state", Value: string(value.CoverageState)},
		telemetry.Field{Key: "decision.freshness_state", Value: string(value.FreshnessState)},
		telemetry.Field{Key: "decision.conflict_state", Value: string(value.ConflictState)},
		telemetry.Field{Key: "decision.action_state", Value: string(value.ActionState)},
		telemetry.Field{Key: "decision.outcome", Value: string(value.Outcome)},
		telemetry.Field{Key: "decision.dismissal_reason", Value: string(value.DismissalReason)},
		telemetry.Field{Key: "decision.packet.schema_version", Value: value.SchemaVersion},
		telemetry.Field{Key: "decision.evidence.count", Value: nonNegative(value.EvidenceCount)},
		telemetry.Field{Key: "decision.coverage_gap.count", Value: nonNegative(value.CoverageGapCount)},
		telemetry.Field{Key: "decision.duration_ms", Value: max(value.DurationMillis, 0)},
	), nil
}

func (value Telemetry) validateBoundedStates() error {
	if value.DecisionState != DecisionUnknown && !value.DecisionState.valid() {
		return invalid("decision state", string(value.DecisionState))
	}
	if value.CoverageState != CoverageUnknown && !value.CoverageState.valid() {
		return invalid("coverage state", string(value.CoverageState))
	}
	if value.FreshnessState != NormalizeFreshnessState(string(value.FreshnessState)) ||
		value.ActionState != NormalizeActionState(string(value.ActionState)) ||
		!validConflict(value.ConflictState) || !validOutcome(value.Outcome) || !validDismissal(value.DismissalReason) {
		return fmt.Errorf("%w: telemetry contains an unbounded state", ErrInvalidState)
	}
	return nil
}

func validOperation(value Operation) bool {
	switch value {
	case OperationRequested, OperationPacketBuilt, OperationDecisionCompleted, OperationActionRecorded, OperationOutcomeRecorded:
		return true
	default:
		return false
	}
}

func validConflict(value ConflictState) bool {
	return value == ConflictNone || value == ConflictPresent || value == ConflictUnknown
}

func validOutcome(value Outcome) bool {
	switch value {
	case OutcomeNone, OutcomeAccepted, OutcomeRejected, OutcomeDeferred, OutcomeVerifiedClosed, OutcomeAuditPacketDelivered, OutcomeFailed, OutcomeReopened, OutcomeUnknown:
		return true
	default:
		return false
	}
}

func validDismissal(value DismissalReason) bool {
	switch value {
	case DismissalNone, DismissalNotRelevant, DismissalInsufficientEvidence, DismissalDuplicate, DismissalAcceptedRisk, DismissalOther:
		return true
	default:
		return false
	}
}

func nonNegative(value int) int {
	return max(value, 0)
}
