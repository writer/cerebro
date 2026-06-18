package graphactions

import (
	"context"
	"fmt"
	"strings"
)

type AccessApprovalsProvider struct {
	Client AccessApprovalsClient
}

func (p AccessApprovalsProvider) ExecuteGraphAction(ctx context.Context, spec ActionSpec, request ProviderActionRequest) (*GraphAction, error) {
	if p.Client == nil {
		return nil, ErrNotConfigured
	}
	actionRequest := AccessApprovalsUserActionRequest{
		EmailOrUserID:  strings.TrimSpace(request.Target),
		Reason:         strings.TrimSpace(request.Reason),
		Source:         strings.TrimSpace(request.Source),
		TicketURL:      strings.TrimSpace(request.TicketURL),
		IdempotencyKey: strings.TrimSpace(request.IdempotencyKey),
		TenantID:       strings.TrimSpace(request.TenantID),
		FindingID:      strings.TrimSpace(request.FindingID),
		FindingRuleID:  strings.TrimSpace(request.FindingRuleID),
		ResourceURN:    strings.TrimSpace(request.ResourceURN),
		SubjectURN:     strings.TrimSpace(request.SubjectURN),
	}
	var (
		externalAction *AccessApprovalsUserAction
		err            error
	)
	switch strings.TrimSpace(spec.ProviderAction) {
	case AccessApprovalsActionSuspend:
		externalAction, err = p.Client.SuspendOktaUser(ctx, actionRequest)
	case AccessApprovalsActionUnsuspend:
		externalAction, err = p.Client.UnsuspendOktaUser(ctx, actionRequest)
	default:
		return nil, fmt.Errorf("%w: unsupported access-approvals action %q", ErrInvalidRequest, spec.ProviderAction)
	}
	if err != nil {
		return nil, err
	}
	if externalAction == nil {
		return nil, fmt.Errorf("%w: response missing action", ErrRemote)
	}
	return GraphActionFromAccessApprovals(spec.ID, externalAction, p.Client.ActionURL(externalAction.ID), request.Target), nil
}

func (p AccessApprovalsProvider) GetGraphAction(ctx context.Context, externalID string) (*GraphAction, error) {
	if p.Client == nil {
		return nil, ErrNotConfigured
	}
	externalAction, err := p.Client.GetOktaUserAction(ctx, externalID)
	if err != nil {
		return nil, err
	}
	if externalAction == nil || strings.TrimSpace(externalAction.ID) == "" {
		return nil, fmt.Errorf("%w: response missing action", ErrRemote)
	}
	action, err := graphActionIDFromAccessApprovals(externalAction.Action)
	if err != nil {
		return nil, err
	}
	return GraphActionFromAccessApprovals(action, externalAction, p.Client.ActionURL(externalAction.ID), ""), nil
}
