package graphactions

import (
	"context"
	"fmt"
	"strings"
)

// ReversibleRemediationPlan is a non-executable review packet for a mutating
// action and its registered reversal. CanExecute remains false because planning
// never confers approval.
type ReversibleRemediationPlan struct {
	Action            ActionMetadata `json:"action"`
	Reversal          ActionMetadata `json:"reversal"`
	DryRun            *GraphAction   `json:"dry_run"`
	FindingID         string         `json:"finding_id"`
	Target            string         `json:"target"`
	ApprovalRequired  bool           `json:"approval_required"`
	HumanApproved     bool           `json:"human_approved"`
	CanExecute        bool           `json:"can_execute"`
	VerificationSteps []string       `json:"verification_steps,omitempty"`
}

// PlanReversibleRemediation performs the same eligibility and target resolution
// as Execute but forces dry-run mode and requires a registered reversal.
func (s Service) PlanReversibleRemediation(ctx context.Context, input Input) (*ReversibleRemediationPlan, error) {
	input.DryRun = true
	input.Approved = false
	result, err := s.Execute(ctx, input)
	if err != nil {
		return nil, err
	}
	spec, err := s.actionSpec(input.Action)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(spec.ReversibleBy) == "" {
		return nil, fmt.Errorf("%w: action %q does not declare a reversal", ErrInvalidRequest, spec.ID)
	}
	reversal, err := s.actionSpec(spec.ReversibleBy)
	if err != nil {
		return nil, err
	}
	if result == nil || result.Action == nil {
		return nil, fmt.Errorf("%w: dry-run plan missing graph action", ErrInvalidRequest)
	}
	return &ReversibleRemediationPlan{
		Action:           spec.Metadata(),
		Reversal:         reversal.Metadata(),
		DryRun:           result.Action,
		FindingID:        strings.TrimSpace(input.FindingID),
		Target:           result.Target,
		ApprovalRequired: true,
		HumanApproved:    false,
		CanExecute:       false,
		VerificationSteps: []string{
			"Review the dry-run target and cited finding evidence.",
			"Approve the mutating action only after the reversal path is understood.",
			"Reconcile the provider action and record the outcome after execution.",
		},
	}, nil
}
