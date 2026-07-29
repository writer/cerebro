// Package verifiedaccessactionexecution bridges durable verified access action
// authority to the existing graph action executor.
package verifiedaccessactionexecution

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/verifiedaccessaction"
)

var (
	ErrNotConfigured        = errors.New("verified access action execution is not configured")
	ErrInvalidRequest       = errors.New("invalid verified access action execution request")
	ErrClaimNotAcquired     = errors.New("verified access action execution claim was not acquired")
	ErrProviderReceipt      = errors.New("verified access action provider receipt was rejected")
	ErrSubmissionUnknown    = errors.New("verified access action provider submission is unknown")
	ErrExecutionPersistence = errors.New(
		"verified access action execution receipt persistence failed",
	)
)

type GraphActionExecutor interface {
	Execute(context.Context, graphactions.Input) (*graphactions.Result, error)
}

type Clock func() time.Time

type Service struct {
	Store          verifiedaccessaction.Store
	Executor       GraphActionExecutor
	Clock          Clock
	ReconcileDelay time.Duration
}

type Input struct {
	TenantID       string
	ActionID       string
	ProposalDigest string
	Worker         verifiedaccessaction.Actor
}

type Result struct {
	Record verifiedaccessaction.Record
	Action *graphactions.GraphAction
}

// Execute claims one approved action before invoking the existing provider
// executor. The legacy Approved field is set only after the durable claim is
// committed; it is transport compatibility, not approval authority.
func (s Service) Execute(ctx context.Context, input Input) (*Result, error) {
	if s.Store == nil || s.Executor == nil {
		return nil, ErrNotConfigured
	}
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ActionID = strings.TrimSpace(input.ActionID)
	input.ProposalDigest = strings.TrimSpace(input.ProposalDigest)
	if input.TenantID == "" || input.ActionID == "" ||
		input.ProposalDigest == "" || !validActor(input.Worker) {
		return nil, ErrInvalidRequest
	}
	record, err := s.Store.GetAccessAction(ctx, input.TenantID, input.ActionID)
	if err != nil {
		return nil, err
	}
	if record.Status != verifiedaccessaction.StatusApproved ||
		record.Preflight == nil || record.Approval == nil {
		return nil, verifiedaccessaction.ErrState
	}
	proposalDigest, err := verifiedaccessaction.ProposalRecordDigest(record)
	if err != nil {
		return nil, err
	}
	if proposalDigest != input.ProposalDigest {
		return nil, verifiedaccessaction.ErrStale
	}
	claimedAt := s.now().UTC().Truncate(time.Second)
	claim, err := verifiedaccessaction.ClaimExecution(record, verifiedaccessaction.ExecutionClaimInput{
		ProposalDigest:    input.ProposalDigest,
		PreflightDigest:   record.Preflight.Digest,
		ApprovalDigest:    record.Approval.Digest,
		ParametersDigest:  verifiedaccessaction.ParametersDigest(record.Parameters),
		Binding:           record.Binding,
		DefinitionVersion: record.Definition.Version,
		Actor:             input.Worker,
		ClaimedAt:         claimedAt,
	})
	if err != nil {
		return nil, err
	}
	applied, err := s.Store.AppendAccessAction(ctx, claim)
	if err != nil {
		if errors.Is(err, verifiedaccessaction.ErrConflict) {
			return nil, ErrClaimNotAcquired
		}
		return nil, err
	}
	if !applied {
		return nil, ErrClaimNotAcquired
	}

	execution, executeErr := s.Executor.Execute(ctx, graphactions.Input{
		FindingID:      record.FindingID,
		Action:         record.Definition.Metadata.ID,
		Target:         record.Binding.TargetID,
		Reason:         record.Reason,
		IdempotencyKey: record.IdempotencyKey,
		Parameters:     cloneParameters(record.Parameters),
		Approved:       true,
	})
	if executeErr != nil {
		return nil, s.recordUnknown(ctx, claim.Record, input.Worker, executeErr)
	}
	if execution == nil || execution.Action == nil {
		return nil, s.recordUnknown(
			ctx,
			claim.Record,
			input.Worker,
			fmt.Errorf("%w: executor returned no action", graphactions.ErrRemote),
		)
	}
	action := cloneGraphAction(execution.Action)
	bindMissingActionMetadata(action, claim.Record)
	occurredAt := time.Unix(action.CompletedAtUnix, 0).UTC()
	executedBy := verifiedaccessaction.Actor{
		Type: strings.TrimSpace(action.ActorType),
		ID:   strings.TrimSpace(action.ActorSubject),
	}
	outcome, err := verifiedaccessaction.IngestExecution(claim.Record, verifiedaccessaction.ExecutionInput{
		GraphAction:           *action,
		ExecutionClaimDigest:  claim.Record.ExecutionClaim.Digest,
		DefinitionVersion:     claim.Record.Definition.Version,
		ProposalDigest:        input.ProposalDigest,
		PreflightDigest:       claim.Record.Preflight.Digest,
		ApprovalDigest:        claim.Record.Approval.Digest,
		ParametersDigest:      verifiedaccessaction.ParametersDigest(claim.Record.Parameters),
		Binding:               claim.Record.Binding,
		ExecutedBy:            executedBy,
		IngestedBy:            input.Worker,
		ProviderReceiptDigest: verifiedaccessaction.GraphActionReceiptDigest(*action),
		OccurredAt:            occurredAt,
	})
	if err != nil {
		return &Result{Record: claim.Record, Action: action}, errors.Join(ErrProviderReceipt, err)
	}
	result := &Result{Record: claim.Record, Action: action}
	applied, err = s.Store.AppendAccessAction(ctx, outcome)
	if err != nil {
		return result, errors.Join(ErrExecutionPersistence, err)
	}
	if !applied {
		return result, errors.Join(ErrExecutionPersistence, ErrClaimNotAcquired)
	}
	return &Result{Record: outcome.Record, Action: action}, nil
}

func (s Service) recordUnknown(
	ctx context.Context,
	record verifiedaccessaction.Record,
	worker verifiedaccessaction.Actor,
	cause error,
) error {
	observedAt := s.now().UTC().Truncate(time.Second)
	if observedAt.Before(record.ExecutionClaim.ClaimedAt) {
		observedAt = record.ExecutionClaim.ClaimedAt
	}
	outcome, err := verifiedaccessaction.RecordSubmissionUnknown(
		record,
		verifiedaccessaction.SubmissionUnknownInput{
			ExecutionClaimDigest: record.ExecutionClaim.Digest,
			ProviderRequestID:    record.IdempotencyKey,
			ErrorClass:           submissionErrorClass(cause),
			Actor:                worker,
			ObservedAt:           observedAt,
			NextReconcileAt:      observedAt.Add(s.reconcileDelay()),
		},
	)
	if err != nil {
		return errors.Join(ErrSubmissionUnknown, cause, err)
	}
	applied, err := s.Store.AppendAccessAction(ctx, outcome)
	if err != nil {
		return errors.Join(ErrSubmissionUnknown, cause, err)
	}
	if !applied {
		return errors.Join(ErrSubmissionUnknown, cause, ErrClaimNotAcquired)
	}
	return errors.Join(ErrSubmissionUnknown, cause)
}

func (s Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

func (s Service) reconcileDelay() time.Duration {
	if s.ReconcileDelay > 0 {
		return s.ReconcileDelay
	}
	return 5 * time.Minute
}

func submissionErrorClass(err error) string {
	var networkError net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return verifiedaccessaction.SubmissionErrorTransportTimeout
	case errors.As(err, &networkError) && networkError.Timeout():
		return verifiedaccessaction.SubmissionErrorTransportTimeout
	case errors.As(err, &networkError):
		return verifiedaccessaction.SubmissionErrorConnectionReset
	default:
		return verifiedaccessaction.SubmissionErrorResponseLost
	}
}

func bindMissingActionMetadata(action *graphactions.GraphAction, record verifiedaccessaction.Record) {
	if action.Metadata == nil {
		action.Metadata = map[string]string{}
	}
	for key, value := range map[string]string{
		"tenant_id":          record.TenantID,
		"subject_urn":        record.Binding.SubjectURN,
		"resource_urn":       record.Binding.ResourceURN,
		"source_runtime_id":  record.Binding.SourceRuntimeID,
		"source_revision":    record.Binding.SourceRevision,
		"definition_version": record.Definition.Version,
	} {
		if strings.TrimSpace(action.Metadata[key]) == "" {
			action.Metadata[key] = value
		}
	}
}

func cloneGraphAction(action *graphactions.GraphAction) *graphactions.GraphAction {
	if action == nil {
		return nil
	}
	result := *action
	result.Metadata = cloneParameters(action.Metadata)
	return &result
}

func cloneParameters(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func validActor(actor verifiedaccessaction.Actor) bool {
	return strings.TrimSpace(actor.Type) != "" && strings.TrimSpace(actor.ID) != ""
}
