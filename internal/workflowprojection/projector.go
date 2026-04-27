package workflowprojection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	findingEntityType     = "finding"
	annotationEntityType  = "annotation"
	ticketEntityType      = "ticket"
	relationTargets       = "targets"
	relationBasedOn       = "based_on"
	relationExecutedBy    = "executed_by"
	relationEvaluates     = "evaluates"
	relationHasFinding    = "has_finding"
	relationAnnotatedWith = "annotated_with"
	relationTrackedBy     = "tracked_by"
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
	case workflowevents.EventKindFindingNoteAdded:
		return s.projectFindingNote(ctx, event)
	case workflowevents.EventKindFindingTicketLinked:
		return s.projectFindingTicket(ctx, event)
	case workflowevents.EventKindFindingStatusChanged:
		return s.projectFindingStatus(ctx, event)
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

func (s *Service) projectFindingNote(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingNoteAdded(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	targetURNs, err := s.ensureFindingAnchor(ctx, payload.Finding, &result)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	annotationURN := findingAnnotationURN(payload.Finding.TenantID, payload.Finding.FindingID, payload.NoteID, payload.Body, payload.CreatedAt)
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        annotationURN,
		TenantID:   payload.Finding.TenantID,
		SourceID:   payload.Finding.SourceSystem,
		EntityType: annotationEntityType,
		Label:      graphEntityLabel(payload.Body),
		Attributes: map[string]string{
			"finding_id":           strings.TrimSpace(payload.Finding.FindingID),
			"note_id":              strings.TrimSpace(payload.NoteID),
			"body":                 strings.TrimSpace(payload.Body),
			"created_at":           strings.TrimSpace(payload.CreatedAt),
			"workflow":             "finding_note",
			"runtime_id":           strings.TrimSpace(payload.Finding.RuntimeID),
			"primary_resource_urn": strings.TrimSpace(payload.Finding.PrimaryResourceURN),
		},
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, targetURN := range targetURNs {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.Finding.TenantID,
			SourceID: payload.Finding.SourceSystem,
			FromURN:  targetURN,
			ToURN:    annotationURN,
			Relation: relationAnnotatedWith,
			Attributes: map[string]string{
				"finding_id": strings.TrimSpace(payload.Finding.FindingID),
				"note_id":    strings.TrimSpace(payload.NoteID),
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	return result, nil
}

func (s *Service) projectFindingTicket(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingTicketLinked(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	targetURNs, err := s.ensureFindingAnchor(ctx, payload.Finding, &result)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	ticketURN := findingTicketURN(payload.Finding.TenantID, payload.URL)
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        ticketURN,
		TenantID:   payload.Finding.TenantID,
		SourceID:   payload.Finding.SourceSystem,
		EntityType: ticketEntityType,
		Label:      findingTicketLabel(payload.Name, payload.ExternalID, payload.URL),
		Attributes: map[string]string{
			"finding_id":           strings.TrimSpace(payload.Finding.FindingID),
			"url":                  strings.TrimSpace(payload.URL),
			"name":                 strings.TrimSpace(payload.Name),
			"external_id":          strings.TrimSpace(payload.ExternalID),
			"linked_at":            strings.TrimSpace(payload.LinkedAt),
			"workflow":             "finding_ticket",
			"runtime_id":           strings.TrimSpace(payload.Finding.RuntimeID),
			"primary_resource_urn": strings.TrimSpace(payload.Finding.PrimaryResourceURN),
		},
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, targetURN := range targetURNs {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.Finding.TenantID,
			SourceID: payload.Finding.SourceSystem,
			FromURN:  targetURN,
			ToURN:    ticketURN,
			Relation: relationTrackedBy,
			Attributes: map[string]string{
				"finding_id":  strings.TrimSpace(payload.Finding.FindingID),
				"ticket_url":  strings.TrimSpace(payload.URL),
				"external_id": strings.TrimSpace(payload.ExternalID),
			},
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	return result, nil
}

func (s *Service) projectFindingStatus(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingStatusChanged(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	if _, err := s.ensureFindingAnchor(ctx, payload.Finding, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	return result, nil
}

func (s *Service) ensureFindingAnchor(ctx context.Context, finding workflowevents.FindingSnapshot, result *ports.ProjectionResult) ([]string, error) {
	tenantID := strings.TrimSpace(finding.TenantID)
	sourceID := strings.TrimSpace(finding.SourceSystem)
	anchorURN := findingURN(tenantID, finding.FindingID)
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        anchorURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: findingEntityType,
		Label:      graphEntityLabel(finding.Title),
		Attributes: map[string]string{
			"finding_id":           strings.TrimSpace(finding.FindingID),
			"rule_id":              strings.TrimSpace(finding.RuleID),
			"severity":             strings.TrimSpace(finding.Severity),
			"status":               strings.TrimSpace(finding.Status),
			"runtime_id":           strings.TrimSpace(finding.RuntimeID),
			"policy_id":            strings.TrimSpace(finding.PolicyID),
			"check_id":             strings.TrimSpace(finding.CheckID),
			"primary_resource_urn": strings.TrimSpace(finding.PrimaryResourceURN),
		},
	}, result); err != nil {
		return nil, err
	}
	resourceURNs := normalizeIDs(finding.ResourceURNs)
	for _, resourceURN := range resourceURNs {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceID,
			FromURN:  resourceURN,
			ToURN:    anchorURN,
			Relation: relationHasFinding,
			Attributes: map[string]string{
				"finding_id": strings.TrimSpace(finding.FindingID),
			},
		}, result); err != nil {
			return nil, err
		}
	}
	return normalizeIDs(append(resourceURNs, anchorURN)), nil
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

func findingURN(tenantID string, findingID string) string {
	return fmt.Sprintf("urn:cerebro:%s:finding:%s", strings.TrimSpace(tenantID), strings.TrimSpace(findingID))
}

func findingAnnotationURN(tenantID string, findingID string, noteID string, body string, createdAt string) string {
	normalizedNoteID := strings.TrimSpace(noteID)
	if normalizedNoteID == "" {
		normalizedNoteID = graphHash(strings.TrimSpace(findingID), strings.TrimSpace(body), strings.TrimSpace(createdAt))
	}
	return fmt.Sprintf("urn:cerebro:%s:annotation:finding-note:%s:%s", strings.TrimSpace(tenantID), strings.TrimSpace(findingID), normalizedNoteID)
}

func findingTicketURN(tenantID string, ticketURL string) string {
	return fmt.Sprintf("urn:cerebro:%s:ticket:linked:%s", strings.TrimSpace(tenantID), graphHash(strings.TrimSpace(ticketURL)))
}

func findingTicketLabel(name string, externalID string, url string) string {
	if label := graphEntityLabel(strings.TrimSpace(name)); label != "" {
		return label
	}
	if label := graphEntityLabel(strings.TrimSpace(externalID)); label != "" {
		return label
	}
	return graphEntityLabel(strings.TrimSpace(url))
}

func graphHash(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:8])
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
