package api

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/cerrors"
	"github.com/writer/cerebro/internal/graph"
)

type orgPolicyWriteRequest struct {
	TemplateID string `json:"template_id,omitempty"`
	graph.OrganizationalPolicyWriteRequest
}

type orgPolicyService interface {
	ListTemplates(ctx context.Context, framework string) ([]graph.OrganizationalPolicyTemplate, error)
	UpsertPolicy(ctx context.Context, req orgPolicyWriteRequest) (graph.OrganizationalPolicyWriteResult, error)
	AcknowledgePolicy(ctx context.Context, req graph.OrganizationalPolicyAcknowledgmentRequest) (graph.OrganizationalPolicyAcknowledgmentResult, error)
	ProgramStatus(ctx context.Context, framework string) (*graph.OrganizationalPolicyProgramStatusReport, error)
	PolicyStatus(ctx context.Context, policyID string) (*graph.OrganizationalPolicyAcknowledgmentReport, error)
	PolicyAssignees(ctx context.Context, policyID string) (*graph.OrganizationalPolicyAssigneeRosterReport, error)
	PolicyReminders(ctx context.Context, policyID string) (*graph.OrganizationalPolicyReminderReport, error)
	PolicyVersionHistory(ctx context.Context, policyID string) ([]graph.OrganizationalPolicyVersionHistoryEntry, error)
	ReviewSchedule(ctx context.Context, asOf time.Time) (*graph.OrganizationalPolicyReviewSchedule, error)
}

type serverOrgPolicyService struct {
	deps *serverDependencies
}

var orgPolicyReadSubgraphOptions = graph.ExtractSubgraphOptions{
	MaxDepth:  2,
	Direction: graph.ExtractSubgraphDirectionBoth,
}

func newOrgPolicyService(deps *serverDependencies) orgPolicyService {
	return serverOrgPolicyService{deps: deps}
}

func (s serverOrgPolicyService) ListTemplates(_ context.Context, framework string) ([]graph.OrganizationalPolicyTemplate, error) {
	framework = strings.TrimSpace(framework)
	if framework == "" {
		return graph.OrganizationalPolicyTemplates(), nil
	}
	return graph.OrganizationalPolicyTemplatesForFramework(framework), nil
}

func (s serverOrgPolicyService) UpsertPolicy(ctx context.Context, req orgPolicyWriteRequest) (graph.OrganizationalPolicyWriteResult, error) {
	if s.deps == nil || s.deps.graphMutator == nil {
		return graph.OrganizationalPolicyWriteResult{}, cerrors.E(cerrors.Op("api.orgPolicies.UpsertPolicy"), graph.ErrStoreUnavailable)
	}

	writeReq := req.OrganizationalPolicyWriteRequest
	if templateID := strings.TrimSpace(req.TemplateID); templateID != "" {
		templateReq, err := graph.OrganizationalPolicyWriteRequestFromTemplate(templateID, graph.OrganizationalPolicyTemplateWriteOptions{
			ID:                    strings.TrimSpace(writeReq.ID),
			PolicyVersion:         strings.TrimSpace(writeReq.PolicyVersion),
			OwnerID:               strings.TrimSpace(writeReq.OwnerID),
			Summary:               strings.TrimSpace(writeReq.Summary),
			Content:               strings.TrimSpace(writeReq.Content),
			ReviewCycleDays:       writeReq.ReviewCycleDays,
			FrameworkMappings:     append([]string(nil), writeReq.FrameworkMappings...),
			RequiredDepartmentIDs: append([]string(nil), writeReq.RequiredDepartmentIDs...),
			RequiredPersonIDs:     append([]string(nil), writeReq.RequiredPersonIDs...),
			SourceSystem:          strings.TrimSpace(writeReq.SourceSystem),
			SourceEventID:         strings.TrimSpace(writeReq.SourceEventID),
			ObservedAt:            writeReq.ObservedAt,
			ValidFrom:             writeReq.ValidFrom,
			ValidTo:               writeReq.ValidTo,
			RecordedAt:            writeReq.RecordedAt,
			TransactionFrom:       writeReq.TransactionFrom,
			TransactionTo:         writeReq.TransactionTo,
			Confidence:            writeReq.Confidence,
			Metadata:              writeReq.Metadata,
		})
		if err != nil {
			return graph.OrganizationalPolicyWriteResult{}, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.UpsertPolicy"), err)
		}
		writeReq = templateReq
	}

	var result graph.OrganizationalPolicyWriteResult
	_, err := s.deps.graphMutator.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		current, err := graph.WriteOrganizationalPolicy(g, writeReq)
		if err != nil {
			return err
		}
		result = current
		return nil
	})
	if err != nil {
		return graph.OrganizationalPolicyWriteResult{}, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.UpsertPolicy"), err)
	}
	return result, nil
}

func (s serverOrgPolicyService) AcknowledgePolicy(ctx context.Context, req graph.OrganizationalPolicyAcknowledgmentRequest) (graph.OrganizationalPolicyAcknowledgmentResult, error) {
	if s.deps == nil || s.deps.graphMutator == nil {
		return graph.OrganizationalPolicyAcknowledgmentResult{}, cerrors.E(cerrors.Op("api.orgPolicies.AcknowledgePolicy"), graph.ErrStoreUnavailable)
	}

	var result graph.OrganizationalPolicyAcknowledgmentResult
	_, err := s.deps.graphMutator.MutateSecurityGraph(ctx, func(g *graph.Graph) error {
		current, err := graph.AcknowledgeOrganizationalPolicy(g, req)
		if err != nil {
			return err
		}
		result = current
		return nil
	})
	if err != nil {
		return graph.OrganizationalPolicyAcknowledgmentResult{}, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.AcknowledgePolicy"), err)
	}
	return result, nil
}

func (s serverOrgPolicyService) ProgramStatus(ctx context.Context, framework string) (*graph.OrganizationalPolicyProgramStatusReport, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return nil, err
	}
	report, err := graph.OrganizationalPolicyProgramStatus(g, graph.OrganizationalPolicyProgramStatusOptions{Framework: strings.TrimSpace(framework)})
	return report, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.ProgramStatus"), err)
}

func (s serverOrgPolicyService) PolicyStatus(ctx context.Context, policyID string) (*graph.OrganizationalPolicyAcknowledgmentReport, error) {
	g, err := s.policyGraph(ctx, policyID)
	if err != nil {
		return nil, err
	}
	report, err := graph.OrganizationalPolicyAcknowledgmentStatus(g, policyID)
	return report, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.PolicyStatus"), err)
}

func (s serverOrgPolicyService) PolicyAssignees(ctx context.Context, policyID string) (*graph.OrganizationalPolicyAssigneeRosterReport, error) {
	g, err := s.policyGraph(ctx, policyID)
	if err != nil {
		return nil, err
	}
	report, err := graph.OrganizationalPolicyAssigneeRoster(g, policyID)
	return report, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.PolicyAssignees"), err)
}

func (s serverOrgPolicyService) PolicyReminders(ctx context.Context, policyID string) (*graph.OrganizationalPolicyReminderReport, error) {
	g, err := s.policyGraph(ctx, policyID)
	if err != nil {
		return nil, err
	}
	report, err := graph.OrganizationalPolicyAcknowledgmentReminders(g, policyID)
	return report, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.PolicyReminders"), err)
}

func (s serverOrgPolicyService) PolicyVersionHistory(ctx context.Context, policyID string) ([]graph.OrganizationalPolicyVersionHistoryEntry, error) {
	g, err := s.policyGraph(ctx, policyID)
	if err != nil {
		return nil, err
	}
	history, err := graph.OrganizationalPolicyVersionHistory(g, policyID)
	return history, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.PolicyVersionHistory"), err)
}

func (s serverOrgPolicyService) ReviewSchedule(ctx context.Context, asOf time.Time) (*graph.OrganizationalPolicyReviewSchedule, error) {
	g, err := s.tenantGraph(ctx)
	if err != nil {
		return nil, err
	}
	report, err := graph.OrganizationalPolicyReviewScheduleAt(g, asOf)
	return report, wrapOrgPolicyError(cerrors.Op("api.orgPolicies.ReviewSchedule"), err)
}

func (s serverOrgPolicyService) tenantGraph(ctx context.Context) (*graph.Graph, error) {
	return currentOrStoredTenantGraphView(ctx, s.deps)
}

func (s serverOrgPolicyService) policyGraph(ctx context.Context, policyID string) (*graph.Graph, error) {
	if s.deps == nil {
		return nil, graph.ErrStoreUnavailable
	}
	tenantID := currentTenantScopeID(ctx)
	if current := s.deps.CurrentSecurityGraphForTenant(tenantID); current != nil {
		return graph.ExtractSubgraph(current, strings.TrimSpace(policyID), orgPolicyReadSubgraphOptions), nil
	}
	store := s.deps.CurrentSecurityGraphStoreForTenant(tenantID)
	if store == nil {
		return nil, graph.ErrStoreUnavailable
	}
	view, err := store.ExtractSubgraph(ctx, strings.TrimSpace(policyID), orgPolicyReadSubgraphOptions)
	if err != nil {
		return nil, err
	}
	if view == nil {
		return nil, graph.ErrStoreUnavailable
	}
	return view, nil
}

func wrapOrgPolicyError(op cerrors.Op, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found:"):
		return cerrors.E(op, cerrors.ErrNotFound, err)
	case strings.Contains(msg, "is required"), strings.Contains(msg, "must be"), strings.Contains(msg, "unknown policy template"), strings.Contains(msg, "unable to derive"):
		return cerrors.E(op, cerrors.ErrInvalidInput, err)
	default:
		return err
	}
}

var _ orgPolicyService = serverOrgPolicyService{}
