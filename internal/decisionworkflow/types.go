// Package decisionworkflow defines the bounded workflow and outcome vocabulary
// used to measure evidence-backed decisions across transports.
package decisionworkflow

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidState = errors.New("invalid decision workflow state")

type Workflow string

const (
	WorkflowChangeDecision       Workflow = "change_decision"
	WorkflowFindingToVerifiedFix Workflow = "finding_to_verified_fix"
	WorkflowContinuousEvidence   Workflow = "continuous_evidence"
	WorkflowUnknown              Workflow = "unknown"
)

type Operation string

const (
	OperationRequested         Operation = "requested"
	OperationPacketBuilt       Operation = "packet_built"
	OperationDecisionCompleted Operation = "decision_completed"
	OperationActionRecorded    Operation = "action_recorded"
	OperationOutcomeRecorded   Operation = "outcome_recorded"
)

type DecisionState string

const (
	DecisionSupported            DecisionState = "supported"
	DecisionSupportedWithGaps    DecisionState = "supported_with_gaps"
	DecisionBlocked              DecisionState = "blocked"
	DecisionInsufficientEvidence DecisionState = "insufficient_evidence"
	DecisionNotApplicable        DecisionState = "not_applicable"
	DecisionUnknown              DecisionState = "unknown"
)

type CoverageState string

const (
	CoverageComplete     CoverageState = "complete"
	CoveragePartial      CoverageState = "partial"
	CoverageStale        CoverageState = "stale"
	CoverageFailed       CoverageState = "failed"
	CoverageUnconfigured CoverageState = "unconfigured"
	CoverageUnsupported  CoverageState = "unsupported"
	CoverageUnverified   CoverageState = "unverified"
	CoverageUnknown      CoverageState = "unknown"
)

type FreshnessState string

const (
	FreshnessFresh   FreshnessState = "fresh"
	FreshnessStale   FreshnessState = "stale"
	FreshnessMissing FreshnessState = "missing"
	FreshnessFailed  FreshnessState = "failed"
	FreshnessUnknown FreshnessState = "unknown"
)

type ConflictState string

const (
	ConflictNone    ConflictState = "none"
	ConflictPresent ConflictState = "present"
	ConflictUnknown ConflictState = "unknown"
)

type ActionState string

const (
	ActionNone             ActionState = "none"
	ActionInformational    ActionState = "informational"
	ActionProposal         ActionState = "proposal"
	ActionApprovalRequired ActionState = "approval_required"
	ActionApproved         ActionState = "approved"
	ActionStarted          ActionState = "started"
	ActionCompleted        ActionState = "completed"
	ActionVerified         ActionState = "verified"
	ActionUnknown          ActionState = "unknown"
)

type Outcome string

const (
	OutcomeNone                 Outcome = "none"
	OutcomeAccepted             Outcome = "accepted"
	OutcomeRejected             Outcome = "rejected"
	OutcomeDeferred             Outcome = "deferred"
	OutcomeVerifiedClosed       Outcome = "verified_closed"
	OutcomeAuditPacketDelivered Outcome = "audit_packet_delivered"
	OutcomeFailed               Outcome = "failed"
	OutcomeReopened             Outcome = "reopened"
	OutcomeUnknown              Outcome = "unknown"
)

type DismissalReason string

const (
	DismissalNone                 DismissalReason = "none"
	DismissalNotRelevant          DismissalReason = "not_relevant"
	DismissalInsufficientEvidence DismissalReason = "insufficient_evidence"
	DismissalDuplicate            DismissalReason = "duplicate"
	DismissalAcceptedRisk         DismissalReason = "accepted_risk"
	DismissalOther                DismissalReason = "other"
)

func ParseWorkflow(value string) (Workflow, error) {
	workflow := Workflow(strings.ToLower(strings.TrimSpace(value)))
	if workflow.valid() {
		return workflow, nil
	}
	return "", invalid("workflow", value)
}

func NormalizeWorkflow(value string) Workflow {
	workflow, err := ParseWorkflow(value)
	if err != nil {
		return WorkflowUnknown
	}
	return workflow
}

func ParseDecisionState(value string) (DecisionState, error) {
	state := DecisionState(strings.ToLower(strings.TrimSpace(value)))
	if state.valid() {
		return state, nil
	}
	return "", invalid("decision state", value)
}

func NormalizeDecisionState(value string) DecisionState {
	state, err := ParseDecisionState(value)
	if err != nil {
		return DecisionUnknown
	}
	return state
}

func ParseCoverageState(value string) (CoverageState, error) {
	state := CoverageState(strings.ToLower(strings.TrimSpace(value)))
	if state.valid() {
		return state, nil
	}
	return "", invalid("coverage state", value)
}

func NormalizeCoverageState(value string) CoverageState {
	state, err := ParseCoverageState(value)
	if err != nil {
		return CoverageUnknown
	}
	return state
}

func NormalizeFreshnessState(value string) FreshnessState {
	state := FreshnessState(strings.ToLower(strings.TrimSpace(value)))
	switch state {
	case FreshnessFresh, FreshnessStale, FreshnessMissing, FreshnessFailed, FreshnessUnknown:
		return state
	default:
		return FreshnessUnknown
	}
}

func NormalizeActionState(value string) ActionState {
	state := ActionState(strings.ToLower(strings.TrimSpace(value)))
	switch state {
	case ActionNone, ActionInformational, ActionProposal, ActionApprovalRequired, ActionApproved, ActionStarted, ActionCompleted, ActionVerified:
		return state
	default:
		return ActionUnknown
	}
}

func NormalizeOutcome(value string) Outcome {
	outcome := Outcome(strings.ToLower(strings.TrimSpace(value)))
	if validOutcome(outcome) {
		return outcome
	}
	return OutcomeUnknown
}

func (w Workflow) valid() bool {
	switch w {
	case WorkflowChangeDecision, WorkflowFindingToVerifiedFix, WorkflowContinuousEvidence:
		return true
	default:
		return false
	}
}

func (s DecisionState) valid() bool {
	switch s {
	case DecisionSupported, DecisionSupportedWithGaps, DecisionBlocked, DecisionInsufficientEvidence, DecisionNotApplicable:
		return true
	default:
		return false
	}
}

func (s CoverageState) valid() bool {
	switch s {
	case CoverageComplete, CoveragePartial, CoverageStale, CoverageFailed, CoverageUnconfigured, CoverageUnsupported, CoverageUnverified:
		return true
	default:
		return false
	}
}

func invalid(kind, value string) error {
	return fmt.Errorf("%w: %s %q", ErrInvalidState, kind, strings.TrimSpace(value))
}

// Completion identifies a durable terminal result that contributes to the
// completed-decision product metric.
type Completion struct {
	Workflow                   Workflow
	DecisionID                 string
	DecisionState              DecisionState
	Outcome                    Outcome
	AuthenticatedTenant        bool
	Durable                    bool
	Reopened                   bool
	AuditPacketExportReceiptID string
}

func (c Completion) Completed() bool {
	if !c.Workflow.valid() || strings.TrimSpace(c.DecisionID) == "" || !c.AuthenticatedTenant || !c.Durable || c.Reopened {
		return false
	}
	if c.DecisionState != DecisionSupported && c.DecisionState != DecisionSupportedWithGaps {
		return false
	}
	switch c.Workflow {
	case WorkflowChangeDecision:
		return c.Outcome == OutcomeAccepted || c.Outcome == OutcomeRejected || c.Outcome == OutcomeDeferred
	case WorkflowFindingToVerifiedFix:
		return c.Outcome == OutcomeVerifiedClosed
	case WorkflowContinuousEvidence:
		return c.Outcome == OutcomeAuditPacketDelivered && strings.TrimSpace(c.AuditPacketExportReceiptID) != ""
	default:
		return false
	}
}
