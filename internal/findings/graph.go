package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
)

const (
	findingGraphEntityType           = "finding"
	findingGraphAnnotationEntityType = "annotation"
	findingGraphTicketEntityType     = "ticket"
	findingGraphFindingRelation      = "has_finding"
	findingGraphAnnotationRelation   = "annotated_with"
	findingGraphTicketRelation       = "tracked_by"
	findingGraphLabelLimit           = 160
	findingDecisionStatusCompleted   = "completed"
)

func (s *Service) projectFindingNote(ctx context.Context, finding *ports.FindingRecord, note ports.FindingNote) error {
	if s == nil || s.graph == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	body := strings.TrimSpace(note.Body)
	if body == "" {
		return nil
	}
	createdAt := note.CreatedAt.UTC()
	if createdAt.IsZero() {
		return nil
	}
	tenantID, sourceID := findingGraphScope(finding)
	targetURNs, err := s.ensureFindingGraphAnchor(ctx, finding)
	if err != nil {
		return err
	}
	annotationURN := findingGraphAnnotationURN(tenantID, finding, note)
	if err := s.graph.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        annotationURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: findingGraphAnnotationEntityType,
		Label:      findingGraphLabel(body),
		Attributes: map[string]string{
			"finding_id":           strings.TrimSpace(finding.ID),
			"note_id":              strings.TrimSpace(note.ID),
			"body":                 body,
			"created_at":           createdAt.Format(time.RFC3339Nano),
			"workflow":             "finding_note",
			"runtime_id":           strings.TrimSpace(finding.RuntimeID),
			"primary_resource_urn": findingPrimaryResourceURN(finding),
		},
	}); err != nil {
		return fmt.Errorf("upsert finding note annotation %q: %w", annotationURN, err)
	}
	for _, targetURN := range targetURNs {
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceID,
			FromURN:  targetURN,
			ToURN:    annotationURN,
			Relation: findingGraphAnnotationRelation,
			Attributes: map[string]string{
				"finding_id": strings.TrimSpace(finding.ID),
				"note_id":    strings.TrimSpace(note.ID),
			},
		}); err != nil {
			return fmt.Errorf("upsert finding note annotation link %q -> %q: %w", targetURN, annotationURN, err)
		}
	}
	return nil
}

func (s *Service) projectFindingTicket(ctx context.Context, finding *ports.FindingRecord, ticket ports.FindingTicket) error {
	if s == nil || s.graph == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	normalizedURL := strings.TrimSpace(ticket.URL)
	if normalizedURL == "" {
		return nil
	}
	linkedAt := ticket.LinkedAt.UTC()
	if linkedAt.IsZero() {
		return nil
	}
	tenantID, sourceID := findingGraphScope(finding)
	targetURNs, err := s.ensureFindingGraphAnchor(ctx, finding)
	if err != nil {
		return err
	}
	ticketURN := findingGraphTicketURN(tenantID, normalizedURL)
	if err := s.graph.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        ticketURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: findingGraphTicketEntityType,
		Label:      findingGraphTicketLabel(ticket),
		Attributes: map[string]string{
			"finding_id":           strings.TrimSpace(finding.ID),
			"url":                  normalizedURL,
			"name":                 strings.TrimSpace(ticket.Name),
			"external_id":          strings.TrimSpace(ticket.ExternalID),
			"linked_at":            linkedAt.Format(time.RFC3339Nano),
			"workflow":             "finding_ticket",
			"runtime_id":           strings.TrimSpace(finding.RuntimeID),
			"primary_resource_urn": findingPrimaryResourceURN(finding),
		},
	}); err != nil {
		return fmt.Errorf("upsert finding ticket %q: %w", ticketURN, err)
	}
	for _, targetURN := range targetURNs {
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceID,
			FromURN:  targetURN,
			ToURN:    ticketURN,
			Relation: findingGraphTicketRelation,
			Attributes: map[string]string{
				"finding_id":  strings.TrimSpace(finding.ID),
				"ticket_url":  normalizedURL,
				"external_id": strings.TrimSpace(ticket.ExternalID),
			},
		}); err != nil {
			return fmt.Errorf("upsert finding ticket link %q -> %q: %w", targetURN, ticketURN, err)
		}
	}
	return nil
}

func (s *Service) ensureFindingGraphAnchor(ctx context.Context, finding *ports.FindingRecord) ([]string, error) {
	if s == nil || s.graph == nil {
		return nil, nil
	}
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	tenantID, sourceID := findingGraphScope(finding)
	anchorURN := findingGraphFindingURN(tenantID, finding)
	if err := s.graph.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        anchorURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: findingGraphEntityType,
		Label:      findingGraphLabel(strings.TrimSpace(finding.Title)),
		Attributes: map[string]string{
			"finding_id":           strings.TrimSpace(finding.ID),
			"rule_id":              strings.TrimSpace(finding.RuleID),
			"severity":             strings.TrimSpace(finding.Severity),
			"status":               strings.TrimSpace(finding.Status),
			"runtime_id":           strings.TrimSpace(finding.RuntimeID),
			"policy_id":            strings.TrimSpace(finding.PolicyID),
			"check_id":             strings.TrimSpace(finding.CheckID),
			"primary_resource_urn": findingPrimaryResourceURN(finding),
		},
	}); err != nil {
		return nil, fmt.Errorf("upsert finding graph anchor %q: %w", anchorURN, err)
	}
	resourceURNs := uniqueSortedStrings(finding.ResourceURNs)
	for _, resourceURN := range resourceURNs {
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceID,
			FromURN:  resourceURN,
			ToURN:    anchorURN,
			Relation: findingGraphFindingRelation,
			Attributes: map[string]string{
				"finding_id": strings.TrimSpace(finding.ID),
			},
		}); err != nil {
			return nil, fmt.Errorf("upsert finding graph anchor link %q -> %q: %w", resourceURN, anchorURN, err)
		}
	}
	return uniqueSortedStrings(append(resourceURNs, anchorURN)), nil
}

func (s *Service) recordFindingStatusWorkflow(ctx context.Context, finding *ports.FindingRecord) error {
	if s == nil || s.graph == nil || s.graphQuery == nil || finding == nil {
		return nil
	}
	status := strings.TrimSpace(finding.Status)
	if status != findingStatusResolved && status != findingStatusSuppressed {
		return nil
	}
	if _, err := s.ensureFindingGraphAnchor(ctx, finding); err != nil {
		return err
	}
	tenantID, _ := findingGraphScope(finding)
	targetURNs := []string{findingGraphFindingURN(tenantID, finding)}
	if len(targetURNs) == 0 {
		return nil
	}
	decisionType := "finding-resolution"
	if status == findingStatusSuppressed {
		decisionType = "finding-suppression"
	}
	workflowMetadata := map[string]any{
		"tenant_id":            strings.TrimSpace(finding.TenantID),
		"finding_id":           strings.TrimSpace(finding.ID),
		"finding_status":       status,
		"runtime_id":           strings.TrimSpace(finding.RuntimeID),
		"rule_id":              strings.TrimSpace(finding.RuleID),
		"policy_id":            strings.TrimSpace(finding.PolicyID),
		"check_id":             strings.TrimSpace(finding.CheckID),
		"primary_resource_urn": findingPrimaryResourceURN(finding),
	}
	if rationale := strings.TrimSpace(finding.StatusReason); rationale != "" {
		workflowMetadata["rationale"] = rationale
	}
	service := knowledge.New(s.graphQuery, s.graph)
	decision, err := service.WriteDecision(ctx, knowledge.DecisionWriteRequest{
		ID:            findingStatusDecisionID(finding),
		DecisionType:  decisionType,
		Status:        findingDecisionStatusCompleted,
		Rationale:     strings.TrimSpace(finding.StatusReason),
		TargetIDs:     targetURNs,
		SourceSystem:  "findings",
		SourceEventID: strings.TrimSpace(finding.ID),
		ObservedAt:    finding.StatusUpdatedAt,
		ValidFrom:     finding.StatusUpdatedAt,
		Metadata:      workflowMetadata,
	})
	if err != nil {
		return err
	}
	_, err = service.WriteOutcome(ctx, knowledge.OutcomeWriteRequest{
		ID:            findingStatusOutcomeID(finding),
		DecisionID:    decision.DecisionID,
		OutcomeType:   decisionType,
		Verdict:       status,
		TargetIDs:     targetURNs,
		SourceSystem:  "findings",
		SourceEventID: strings.TrimSpace(finding.ID),
		ObservedAt:    finding.StatusUpdatedAt,
		ValidFrom:     finding.StatusUpdatedAt,
		Metadata:      workflowMetadata,
	})
	return err
}

func findingGraphScope(finding *ports.FindingRecord) (string, string) {
	tenantID := strings.TrimSpace(finding.TenantID)
	sourceID := strings.TrimSpace(finding.RuntimeID)
	if sourceID == "" {
		sourceID = "finding:" + strings.TrimSpace(finding.ID)
	}
	return tenantID, sourceID
}

func findingGraphFindingURN(tenantID string, finding *ports.FindingRecord) string {
	return fmt.Sprintf("urn:cerebro:%s:finding:%s", strings.TrimSpace(tenantID), strings.TrimSpace(finding.ID))
}

func findingGraphAnnotationURN(tenantID string, finding *ports.FindingRecord, note ports.FindingNote) string {
	noteID := strings.TrimSpace(note.ID)
	if noteID == "" {
		noteID = findingGraphHash(strings.TrimSpace(finding.ID), strings.TrimSpace(note.Body), note.CreatedAt.UTC().Format(time.RFC3339Nano))
	}
	return fmt.Sprintf("urn:cerebro:%s:annotation:finding-note:%s:%s", strings.TrimSpace(tenantID), strings.TrimSpace(finding.ID), noteID)
}

func findingGraphTicketURN(tenantID string, ticketURL string) string {
	return fmt.Sprintf("urn:cerebro:%s:ticket:linked:%s", strings.TrimSpace(tenantID), findingGraphHash(strings.TrimSpace(ticketURL)))
}

func findingGraphTicketLabel(ticket ports.FindingTicket) string {
	if label := findingGraphLabel(strings.TrimSpace(ticket.Name)); label != "" {
		return label
	}
	if label := findingGraphLabel(strings.TrimSpace(ticket.ExternalID)); label != "" {
		return label
	}
	return findingGraphLabel(strings.TrimSpace(ticket.URL))
}

func findingPrimaryResourceURN(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if resourceURN := strings.TrimSpace(finding.Attributes["primary_resource_urn"]); resourceURN != "" {
		return resourceURN
	}
	for _, resourceURN := range finding.ResourceURNs {
		if trimmed := strings.TrimSpace(resourceURN); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func findingGraphLabel(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= findingGraphLabelLimit {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:findingGraphLabelLimit-1]) + "…"
}

func findingGraphHash(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:8])
}

func findingStatusDecisionID(finding *ports.FindingRecord) string {
	return "finding-" + strings.TrimSpace(finding.ID) + "-decision-" + strings.TrimSpace(finding.Status)
}

func findingStatusOutcomeID(finding *ports.FindingRecord) string {
	return "finding-" + strings.TrimSpace(finding.ID) + "-outcome-" + strings.TrimSpace(finding.Status)
}
