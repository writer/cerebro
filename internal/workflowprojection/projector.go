package workflowprojection

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const (
	decisionEntityType    = "decision"
	actionEntityType      = "action"
	outcomeEntityType     = "outcome"
	evidenceEntityType    = "evidence"
	relationTargets       = "targets"
	relationBasedOn       = "based_on"
	relationExecutedBy    = "executed_by"
	relationEvaluates     = "evaluates"
	graphEntityLabelLimit = 160
)

// Service projects durable workflow events into graph entities and links.
type Service struct {
	graph ports.ProjectionGraphStore
}

// New constructs one workflow graph projector.
func New(graph ports.ProjectionGraphStore) *Service {
	return &Service{graph: graph}
}

// Project applies one workflow event to the configured graph store.
func (s *Service) Project(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	if event == nil {
		return ports.ProjectionResult{}, fmt.Errorf("workflow event is required")
	}
	if s == nil || s.graph == nil {
		return ports.ProjectionResult{}, fmt.Errorf("workflow graph projection store is required")
	}
	switch strings.TrimSpace(event.GetKind()) {
	case workflowevents.EventKindKnowledgeDecisionRecorded:
		return s.projectDecision(ctx, event)
	case workflowevents.EventKindKnowledgeActionRecorded:
		return s.projectAction(ctx, event)
	case workflowevents.EventKindKnowledgeOutcomeRecorded:
		return s.projectOutcome(ctx, event)
	default:
		return ports.ProjectionResult{}, nil
	}
}

func (s *Service) projectDecision(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeDecisionRecorded(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        payload.DecisionID,
		TenantID:   payload.TenantID,
		SourceID:   payload.SourceSystem,
		EntityType: decisionEntityType,
		Label:      decisionLabel(payload.DecisionType, payload.Status, payload.Rationale),
		Attributes: decisionAttributes(payload),
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, targetID := range normalizeIDs(payload.TargetIDs) {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.TenantID,
			SourceID: payload.SourceSystem,
			FromURN:  payload.DecisionID,
			ToURN:    targetID,
			Relation: relationTargets,
			Attributes: map[string]string{
				"decision_id": payload.DecisionID,
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	for _, evidenceID := range normalizeIDs(payload.EvidenceIDs) {
		referenceURN, err := s.ensureReferenceEntity(ctx, payload.TenantID, payload.SourceSystem, evidenceEntityType, evidenceID, &result)
		if err != nil {
			return ports.ProjectionResult{}, err
		}
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.TenantID,
			SourceID: payload.SourceSystem,
			FromURN:  payload.DecisionID,
			ToURN:    referenceURN,
			Relation: relationBasedOn,
			Attributes: map[string]string{
				"decision_id": payload.DecisionID,
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	for _, actionID := range normalizeIDs(payload.ActionIDs) {
		referenceURN, err := s.ensureReferenceEntity(ctx, payload.TenantID, payload.SourceSystem, actionEntityType, actionID, &result)
		if err != nil {
			return ports.ProjectionResult{}, err
		}
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.TenantID,
			SourceID: payload.SourceSystem,
			FromURN:  payload.DecisionID,
			ToURN:    referenceURN,
			Relation: relationExecutedBy,
			Attributes: map[string]string{
				"decision_id": payload.DecisionID,
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	return result, nil
}

func (s *Service) projectAction(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeActionRecorded(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        payload.ActionID,
		TenantID:   payload.TenantID,
		SourceID:   payload.SourceSystem,
		EntityType: actionEntityType,
		Label:      actionLabel(payload.Title, payload.Summary, payload.ActionType),
		Attributes: actionAttributes(payload),
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, targetID := range normalizeIDs(payload.TargetIDs) {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.TenantID,
			SourceID: payload.SourceSystem,
			FromURN:  payload.ActionID,
			ToURN:    targetID,
			Relation: relationTargets,
			Attributes: map[string]string{
				"action_id": payload.ActionID,
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	if strings.TrimSpace(payload.DecisionID) != "" {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.TenantID,
			SourceID: payload.SourceSystem,
			FromURN:  payload.DecisionID,
			ToURN:    payload.ActionID,
			Relation: relationExecutedBy,
			Attributes: map[string]string{
				"decision_id": payload.DecisionID,
				"action_id":   payload.ActionID,
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	return result, nil
}

func (s *Service) projectOutcome(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeOutcomeRecorded(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        payload.OutcomeID,
		TenantID:   payload.TenantID,
		SourceID:   payload.SourceSystem,
		EntityType: outcomeEntityType,
		Label:      outcomeLabel(payload.OutcomeType, payload.Verdict),
		Attributes: outcomeAttributes(payload),
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	if err := s.upsertLink(ctx, &ports.ProjectedLink{
		TenantID: payload.TenantID,
		SourceID: payload.SourceSystem,
		FromURN:  payload.OutcomeID,
		ToURN:    payload.DecisionID,
		Relation: relationEvaluates,
		Attributes: map[string]string{
			"outcome_id":  payload.OutcomeID,
			"decision_id": payload.DecisionID,
		},
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, targetID := range normalizeIDs(payload.TargetIDs) {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.TenantID,
			SourceID: payload.SourceSystem,
			FromURN:  payload.OutcomeID,
			ToURN:    targetID,
			Relation: relationTargets,
			Attributes: map[string]string{
				"outcome_id": payload.OutcomeID,
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	return result, nil
}

func (s *Service) upsertEntity(ctx context.Context, entity *ports.ProjectedEntity, result *ports.ProjectionResult) error {
	if err := s.graph.UpsertProjectedEntity(ctx, entity); err != nil {
		return err
	}
	result.EntitiesProjected++
	return nil
}

func (s *Service) upsertLink(ctx context.Context, link *ports.ProjectedLink, result *ports.ProjectionResult) error {
	if err := s.graph.UpsertProjectedLink(ctx, link); err != nil {
		return err
	}
	result.LinksProjected++
	return nil
}

func (s *Service) ensureReferenceEntity(ctx context.Context, tenantID string, sourceSystem string, entityType string, value string, result *ports.ProjectionResult) (string, error) {
	referenceID := strings.TrimSpace(value)
	if referenceID == "" {
		return "", fmt.Errorf("reference id is required")
	}
	if strings.HasPrefix(referenceID, "urn:") {
		return referenceID, nil
	}
	urn := workflowevents.CanonicalWorkflowID(tenantID, entityType, referenceID, entityType, nil, time.Time{})
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceSystem,
		EntityType: entityType,
		Label:      graphEntityLabel(referenceID),
		Attributes: map[string]string{
			"reference_id": referenceID,
		},
	}, result); err != nil {
		return "", err
	}
	return urn, nil
}

func decisionAttributes(payload *workflowevents.DecisionRecorded) map[string]string {
	attributes := map[string]string{
		"decision_type":   strings.TrimSpace(payload.DecisionType),
		"status":          strings.TrimSpace(payload.Status),
		"made_by":         strings.TrimSpace(payload.MadeBy),
		"rationale":       strings.TrimSpace(payload.Rationale),
		"source_system":   strings.TrimSpace(payload.SourceSystem),
		"source_event_id": strings.TrimSpace(payload.SourceEventID),
		"observed_at":     strings.TrimSpace(payload.ObservedAt),
		"valid_from":      strings.TrimSpace(payload.ValidFrom),
		"metadata_json":   metadataJSON(payload.Metadata),
	}
	if strings.TrimSpace(payload.ValidTo) != "" {
		attributes["valid_to"] = strings.TrimSpace(payload.ValidTo)
	}
	if payload.Confidence != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", payload.Confidence)
	}
	return attributes
}

func actionAttributes(payload *workflowevents.ActionRecorded) map[string]string {
	attributes := map[string]string{
		"action_type":       strings.TrimSpace(payload.ActionType),
		"status":            strings.TrimSpace(payload.Status),
		"title":             strings.TrimSpace(payload.Title),
		"summary":           strings.TrimSpace(payload.Summary),
		"decision_id":       strings.TrimSpace(payload.DecisionID),
		"recommendation_id": strings.TrimSpace(payload.RecommendationID),
		"insight_type":      strings.TrimSpace(payload.InsightType),
		"source_system":     strings.TrimSpace(payload.SourceSystem),
		"source_event_id":   strings.TrimSpace(payload.SourceEventID),
		"observed_at":       strings.TrimSpace(payload.ObservedAt),
		"valid_from":        strings.TrimSpace(payload.ValidFrom),
		"auto_generated":    fmt.Sprintf("%t", payload.AutoGenerated),
		"metadata_json":     metadataJSON(payload.Metadata),
	}
	if strings.TrimSpace(payload.ValidTo) != "" {
		attributes["valid_to"] = strings.TrimSpace(payload.ValidTo)
	}
	if payload.Confidence != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", payload.Confidence)
	}
	return attributes
}

func outcomeAttributes(payload *workflowevents.OutcomeRecorded) map[string]string {
	attributes := map[string]string{
		"decision_id":     strings.TrimSpace(payload.DecisionID),
		"outcome_type":    strings.TrimSpace(payload.OutcomeType),
		"verdict":         strings.TrimSpace(payload.Verdict),
		"source_system":   strings.TrimSpace(payload.SourceSystem),
		"source_event_id": strings.TrimSpace(payload.SourceEventID),
		"observed_at":     strings.TrimSpace(payload.ObservedAt),
		"valid_from":      strings.TrimSpace(payload.ValidFrom),
		"metadata_json":   metadataJSON(payload.Metadata),
	}
	if strings.TrimSpace(payload.ValidTo) != "" {
		attributes["valid_to"] = strings.TrimSpace(payload.ValidTo)
	}
	if payload.ImpactScore != 0 {
		attributes["impact_score"] = fmt.Sprintf("%.6g", payload.ImpactScore)
	}
	if payload.Confidence != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", payload.Confidence)
	}
	return attributes
}

func decisionLabel(decisionType string, status string, rationale string) string {
	if trimmed := graphEntityLabel(strings.TrimSpace(rationale)); trimmed != "" {
		return trimmed
	}
	return graphEntityLabel(strings.TrimSpace(decisionType) + " " + strings.TrimSpace(status))
}

func actionLabel(title string, summary string, actionType string) string {
	if trimmed := graphEntityLabel(strings.TrimSpace(title)); trimmed != "" {
		return trimmed
	}
	if trimmed := graphEntityLabel(strings.TrimSpace(summary)); trimmed != "" {
		return trimmed
	}
	return graphEntityLabel(strings.TrimSpace(actionType))
}

func outcomeLabel(outcomeType string, verdict string) string {
	return graphEntityLabel(strings.TrimSpace(outcomeType) + " " + strings.TrimSpace(verdict))
}

func graphEntityLabel(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= graphEntityLabelLimit {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:graphEntityLabelLimit-1]) + "…"
}

func metadataJSON(value map[string]any) string {
	if len(value) == 0 {
		return `{}`
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return `{}`
	}
	return string(payload)
}

func normalizeIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}
