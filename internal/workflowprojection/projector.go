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
	externalRefEntityType = "external_ref"
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
			Attributes: workflowEdgeAttributes(payload.SourceSystem, payload.SourceEventID, payload.ObservedAt, payload.ValidFrom, payload.Confidence, map[string]string{
				"decision_id": payload.DecisionID,
			}),
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
			Attributes: workflowEdgeAttributes(payload.SourceSystem, payload.SourceEventID, payload.ObservedAt, payload.ValidFrom, payload.Confidence, map[string]string{
				"action_id": payload.ActionID,
			}),
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
		Attributes: workflowEdgeAttributes(payload.SourceSystem, payload.SourceEventID, payload.ObservedAt, payload.ValidFrom, payload.Confidence, map[string]string{
			"outcome_id":  payload.OutcomeID,
			"decision_id": payload.DecisionID,
		}),
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
			Attributes: workflowEdgeAttributes(payload.SourceSystem, payload.SourceEventID, payload.ObservedAt, payload.ValidFrom, payload.Confidence, map[string]string{
				"outcome_id": payload.OutcomeID,
			}),
		}, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
	}
	return result, nil
}

func (s *Service) projectFindingRecorded(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingRecorded(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	if !findingStatusProjectsToGraph(payload.Finding.Status) {
		return result, nil
	}
	if _, err := s.ensureFindingAnchor(ctx, payload.Finding, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	return result, nil
}

func (s *Service) projectFindingNote(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingNoteAdded(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	targetURNs, err := s.ensureFindingForWorkflow(ctx, payload.Finding, &result)
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
	targetURNs, err := s.ensureFindingForWorkflow(ctx, payload.Finding, &result)
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

func (s *Service) projectFindingExternalRef(ctx context.Context, event *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	payload, err := workflowevents.DecodeFindingExternalRefLinked(event)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{}
	targetURNs, err := s.ensureFindingForWorkflow(ctx, payload.Finding, &result)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	refURN := findingExternalRefURN(payload.Finding.TenantID, payload.System, payload.Kind, payload.ExternalID)
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        refURN,
		TenantID:   payload.Finding.TenantID,
		SourceID:   payload.Finding.SourceSystem,
		EntityType: externalRefEntityType,
		Label:      findingExternalRefLabel(payload.System, payload.Kind, payload.ExternalID),
		Attributes: map[string]string{
			"finding_id":             strings.TrimSpace(payload.Finding.FindingID),
			"system":                 strings.TrimSpace(payload.System),
			"kind":                   strings.TrimSpace(payload.Kind),
			"external_id":            strings.TrimSpace(payload.ExternalID),
			"url":                    strings.TrimSpace(payload.URL),
			"external_status":        strings.TrimSpace(payload.ExternalStatus),
			"external_status_reason": strings.TrimSpace(payload.ExternalStatusReason),
			"lifecycle_owner":        strings.TrimSpace(payload.LifecycleOwner),
			"linked_at":              strings.TrimSpace(payload.LinkedAt),
			"workflow":               "finding_external_ref",
			"runtime_id":             strings.TrimSpace(payload.Finding.RuntimeID),
			"primary_resource_urn":   strings.TrimSpace(payload.Finding.PrimaryResourceURN),
		},
	}, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	for _, targetURN := range targetURNs {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID: payload.Finding.TenantID,
			SourceID: payload.Finding.SourceSystem,
			FromURN:  targetURN,
			ToURN:    refURN,
			Relation: relationTrackedBy,
			Attributes: map[string]string{
				"finding_id":      strings.TrimSpace(payload.Finding.FindingID),
				"external_system": strings.TrimSpace(payload.System),
				"external_kind":   strings.TrimSpace(payload.Kind),
				"external_id":     strings.TrimSpace(payload.ExternalID),
				"lifecycle_owner": strings.TrimSpace(payload.LifecycleOwner),
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
	if workflowevents.FindingStatusPrunesGraph(payload.Finding.Status, payload.Source) ||
		workflowevents.LegacyFindingStatusPrunesGraph(payload.Finding.Status, payload.Source, payload.Reason, payload.DecisionID, payload.OutcomeID) {
		return s.deleteFindingAnchor(ctx, payload.Finding)
	}
	if err := s.ensureFindingEntity(ctx, payload.Finding, &result); err != nil {
		return ports.ProjectionResult{}, err
	}
	if findingStatusProjectsToGraph(payload.Finding.Status) {
		if err := s.ensureFindingActiveLinks(ctx, payload.Finding, &result); err != nil {
			return ports.ProjectionResult{}, err
		}
		return result, nil
	}
	deleted, err := s.deleteFindingActiveLinks(ctx, payload.Finding)
	if err != nil {
		return ports.ProjectionResult{}, err
	}
	result.LinksDeleted += deleted
	return result, nil
}

func (s *Service) deleteFindingAnchor(ctx context.Context, finding workflowevents.FindingSnapshot) (ports.ProjectionResult, error) {
	deleter, ok := s.graph.(ports.ProjectionEntityDeleter)
	if !ok {
		return ports.ProjectionResult{}, nil
	}
	if err := deleter.DeleteProjectedEntity(ctx, findingURN(strings.TrimSpace(finding.TenantID), strings.TrimSpace(finding.FindingID))); err != nil {
		return ports.ProjectionResult{}, err
	}
	result := ports.ProjectionResult{EntitiesDeleted: 1}
	if cleaner, ok := s.graph.(ports.ProjectionCleaner); ok {
		cleanup, err := cleaner.CleanupProjectedEntities(ctx, ports.ProjectionCleanupRequest{
			TenantID:     strings.TrimSpace(finding.TenantID),
			SourceID:     strings.TrimSpace(finding.SourceSystem),
			FindingID:    strings.TrimSpace(finding.FindingID),
			EntityTypes:  []string{annotationEntityType, ticketEntityType, externalRefEntityType, evidenceEntityType, decisionEntityType, actionEntityType, outcomeEntityType},
			OnlyIsolated: true,
			Limit:        1000,
		})
		if err != nil {
			return ports.ProjectionResult{}, err
		}
		result.EntitiesDeleted += cleanup.EntitiesDeleted
		result.LinksDeleted += cleanup.LinksDeleted
	}
	return result, nil
}

func findingStatusProjectsToGraph(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	return normalized == "" || normalized == "open"
}

func (s *Service) ensureFindingAnchor(ctx context.Context, finding workflowevents.FindingSnapshot, result *ports.ProjectionResult) ([]string, error) {
	if err := s.ensureFindingEntity(ctx, finding, result); err != nil {
		return nil, err
	}
	if err := s.ensureFindingActiveLinks(ctx, finding, result); err != nil {
		return nil, err
	}
	return findingTargetURNs(finding), nil
}

func (s *Service) ensureFindingForWorkflow(ctx context.Context, finding workflowevents.FindingSnapshot, result *ports.ProjectionResult) ([]string, error) {
	if err := s.ensureFindingEntity(ctx, finding, result); err != nil {
		return nil, err
	}
	if findingStatusProjectsToGraph(finding.Status) {
		if err := s.ensureFindingActiveLinks(ctx, finding, result); err != nil {
			return nil, err
		}
	}
	return findingTargetURNs(finding), nil
}

func (s *Service) ensureFindingEntity(ctx context.Context, finding workflowevents.FindingSnapshot, result *ports.ProjectionResult) error {
	tenantID := strings.TrimSpace(finding.TenantID)
	sourceID := strings.TrimSpace(finding.SourceSystem)
	anchorURN := findingURN(tenantID, finding.FindingID)
	if err := s.upsertEntity(ctx, &ports.ProjectedEntity{
		URN:        anchorURN,
		TenantID:   tenantID,
		SourceID:   sourceID,
		EntityType: findingEntityType,
		Label:      graphEntityLabel(finding.Title),
		Attributes: findingAnchorAttributes(finding),
	}, result); err != nil {
		return err
	}
	return nil
}

func (s *Service) ensureFindingActiveLinks(ctx context.Context, finding workflowevents.FindingSnapshot, result *ports.ProjectionResult) error {
	tenantID := strings.TrimSpace(finding.TenantID)
	sourceID := strings.TrimSpace(finding.SourceSystem)
	anchorURN := findingURN(tenantID, finding.FindingID)
	targetURNs := findingActiveTargetURNs(finding)
	for _, targetURN := range targetURNs {
		if err := s.upsertLink(ctx, &ports.ProjectedLink{
			TenantID:   tenantID,
			SourceID:   sourceID,
			FromURN:    targetURN,
			ToURN:      anchorURN,
			Relation:   relationHasFinding,
			Attributes: findingAnchorLinkAttributes(finding),
		}, result); err != nil {
			return err
		}
	}
	if err := s.pruneFindingActiveLinks(ctx, tenantID, sourceID, anchorURN, targetURNs, result); err != nil {
		return err
	}
	return nil
}

type findingActiveLinkReader interface {
	ExecuteReadCypher(context.Context, ports.CypherQueryRequest) ([]ports.CypherRow, error)
}

func (s *Service) pruneFindingActiveLinks(ctx context.Context, tenantID string, sourceID string, anchorURN string, currentResourceURNs []string, result *ports.ProjectionResult) error {
	reader, ok := s.graph.(findingActiveLinkReader)
	if !ok {
		return nil
	}
	deleter, ok := s.graph.(ports.ProjectionLinkDeleter)
	if !ok {
		return nil
	}
	current := make(map[string]struct{}, len(currentResourceURNs))
	for _, resourceURN := range currentResourceURNs {
		if resourceURN = strings.TrimSpace(resourceURN); resourceURN != "" {
			current[resourceURN] = struct{}{}
		}
	}
	lastSeen := ""
	for {
		rows, err := reader.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
			Query: `MATCH (resource:Entity {tenant_id: $tenant_id})-[r:RELATION {relation: 'has_finding'}]->(:Entity {tenant_id: $tenant_id, urn: $finding_urn})
WHERE resource.urn > $last_seen
RETURN resource.urn AS resource_urn
ORDER BY resource.urn
LIMIT $row_limit`,
			Params: map[string]any{
				"tenant_id":   tenantID,
				"finding_urn": anchorURN,
				"last_seen":   lastSeen,
				"row_limit":   int64(ports.MaxCypherQueryRows),
			},
			RowLimit: ports.MaxCypherQueryRows,
		})
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			resourceURN := strings.TrimSpace(fmt.Sprintf("%v", row.Values["resource_urn"]))
			if resourceURN == "" || resourceURN == "<nil>" {
				continue
			}
			lastSeen = resourceURN
			if _, keep := current[resourceURN]; keep {
				continue
			}
			if err := deleter.DeleteProjectedLink(ctx, &ports.ProjectedLink{
				TenantID: tenantID,
				SourceID: sourceID,
				FromURN:  resourceURN,
				ToURN:    anchorURN,
				Relation: relationHasFinding,
			}); err != nil {
				return err
			}
			result.LinksDeleted++
		}
		if len(rows) < ports.MaxCypherQueryRows {
			return nil
		}
	}
}

func (s *Service) deleteFindingActiveLinks(ctx context.Context, finding workflowevents.FindingSnapshot) (uint32, error) {
	deleter, ok := s.graph.(ports.ProjectionLinkDeleter)
	if !ok {
		return 0, nil
	}
	tenantID := strings.TrimSpace(finding.TenantID)
	sourceID := strings.TrimSpace(finding.SourceSystem)
	anchorURN := findingURN(tenantID, finding.FindingID)
	var deleted uint32
	for _, resourceURN := range findingActiveTargetURNs(finding) {
		if err := deleter.DeleteProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceID,
			FromURN:  resourceURN,
			ToURN:    anchorURN,
			Relation: relationHasFinding,
		}); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func findingTargetURNs(finding workflowevents.FindingSnapshot) []string {
	return normalizeIDs(append(findingActiveTargetURNs(finding), findingURN(strings.TrimSpace(finding.TenantID), finding.FindingID)))
}

func findingActiveTargetURNs(finding workflowevents.FindingSnapshot) []string {
	return normalizeIDs(append(findingResourceURNs(finding), findingActorURNs(finding)...))
}

func findingResourceURNs(finding workflowevents.FindingSnapshot) []string {
	return normalizeIDs(append([]string{strings.TrimSpace(finding.PrimaryResourceURN)}, finding.ResourceURNs...))
}

func findingActorURNs(finding workflowevents.FindingSnapshot) []string {
	if len(finding.Metadata) == 0 {
		return nil
	}
	candidates := []string{
		finding.Metadata["actor_urn"],
		finding.Metadata["primary_actor_urn"],
	}
	urns := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if urn := canonicalFindingActorURN(strings.TrimSpace(finding.TenantID), candidate); urn != "" {
			urns = append(urns, urn)
		}
	}
	return normalizeIDs(urns)
}

func canonicalFindingActorURN(tenantID string, urn string) string {
	value := strings.TrimSpace(urn)
	if value == "" || !strings.HasPrefix(value, "urn:cerebro:") {
		return ""
	}
	parts := strings.SplitN(value, ":", 6)
	if len(parts) == 6 && parts[0] == "urn" && parts[1] == "cerebro" && parts[3] == "okta_actor" && parts[4] == "user" && strings.TrimSpace(parts[5]) != "" {
		if tenant := strings.TrimSpace(tenantID); tenant == "" || tenant == parts[2] {
			return fmt.Sprintf("urn:cerebro:%s:okta_user:%s", parts[2], strings.TrimSpace(parts[5]))
		}
	}
	return value
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

func workflowEdgeAttributes(sourceSystem string, sourceEventID string, observedAt string, validFrom string, confidence float64, attributes map[string]string) map[string]string {
	if attributes == nil {
		attributes = map[string]string{}
	}
	attributes["source_system"] = strings.TrimSpace(sourceSystem)
	attributes["source_event_id"] = strings.TrimSpace(sourceEventID)
	attributes["observed_at"] = strings.TrimSpace(observedAt)
	attributes["valid_from"] = strings.TrimSpace(validFrom)
	if confidence != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", confidence)
	}
	trimEmptyProjectionAttributes(attributes)
	return attributes
}

func findingAnchorAttributes(finding workflowevents.FindingSnapshot) map[string]string {
	attributes := map[string]string{
		"finding_id":           strings.TrimSpace(finding.FindingID),
		"fingerprint":          strings.TrimSpace(finding.Fingerprint),
		"summary":              graphEntityLabel(finding.Summary),
		"rule_id":              strings.TrimSpace(finding.RuleID),
		"severity":             strings.TrimSpace(finding.Severity),
		"status":               strings.TrimSpace(finding.Status),
		"runtime_id":           strings.TrimSpace(finding.RuntimeID),
		"policy_id":            strings.TrimSpace(finding.PolicyID),
		"check_id":             strings.TrimSpace(finding.CheckID),
		"primary_resource_urn": strings.TrimSpace(finding.PrimaryResourceURN),
		"first_observed_at":    strings.TrimSpace(finding.FirstObservedAt),
		"last_observed_at":     strings.TrimSpace(finding.LastObservedAt),
	}
	if finding.ResourceCount != 0 {
		attributes["resource_count"] = fmt.Sprintf("%d", finding.ResourceCount)
	}
	if finding.EventCount != 0 {
		attributes["event_count"] = fmt.Sprintf("%d", finding.EventCount)
	}
	if finding.RiskScore != 0 {
		attributes["risk_score"] = fmt.Sprintf("%d", finding.RiskScore)
	}
	if strings.TrimSpace(finding.EffectiveSeverity) != "" {
		attributes["effective_severity"] = strings.TrimSpace(finding.EffectiveSeverity)
	}
	if finding.LikelihoodScore != 0 {
		attributes["likelihood_score"] = fmt.Sprintf("%d", finding.LikelihoodScore)
	}
	if finding.ImpactScore != 0 {
		attributes["impact_score"] = fmt.Sprintf("%d", finding.ImpactScore)
	}
	if finding.ConfidenceScore != 0 {
		attributes["confidence_score"] = fmt.Sprintf("%d", finding.ConfidenceScore)
	}
	if strings.TrimSpace(finding.LikelihoodLevel) != "" {
		attributes["likelihood_level"] = strings.TrimSpace(finding.LikelihoodLevel)
	}
	if strings.TrimSpace(finding.ImpactLevel) != "" {
		attributes["impact_level"] = strings.TrimSpace(finding.ImpactLevel)
	}
	if strings.TrimSpace(finding.RiskModelVersion) != "" {
		attributes["risk_model_version"] = strings.TrimSpace(finding.RiskModelVersion)
	}
	if len(finding.EventIDs) != 0 {
		attributes["event_ids"] = strings.Join(normalizeIDs(finding.EventIDs), ",")
	}
	if len(finding.RiskReasons) != 0 {
		attributes["risk_reasons"] = strings.Join(normalizeIDs(finding.RiskReasons), ",")
	}
	if refs := findingControlRefsAttribute(finding.ControlRefs); refs != "" {
		attributes["control_refs"] = refs
	}
	for key, value := range finding.Metadata {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if _, exists := attributes[trimmedKey]; exists {
			attributes["context_"+trimmedKey] = strings.TrimSpace(value)
			continue
		}
		attributes[trimmedKey] = strings.TrimSpace(value)
	}
	trimEmptyProjectionAttributes(attributes)
	return attributes
}

func findingAnchorLinkAttributes(finding workflowevents.FindingSnapshot) map[string]string {
	attributes := map[string]string{
		"finding_id":           strings.TrimSpace(finding.FindingID),
		"rule_id":              strings.TrimSpace(finding.RuleID),
		"severity":             strings.TrimSpace(finding.Severity),
		"status":               strings.TrimSpace(finding.Status),
		"primary_resource_urn": strings.TrimSpace(finding.PrimaryResourceURN),
		"source_system":        strings.TrimSpace(finding.SourceSystem),
		"source_event_id":      findingSourceEventID(finding),
		"observed_at":          strings.TrimSpace(finding.LastObservedAt),
		"valid_from":           strings.TrimSpace(finding.FirstObservedAt),
		"last_observed_at":     strings.TrimSpace(finding.LastObservedAt),
	}
	if finding.RiskScore != 0 {
		attributes["risk_score"] = fmt.Sprintf("%d", finding.RiskScore)
	}
	if strings.TrimSpace(finding.EffectiveSeverity) != "" {
		attributes["effective_severity"] = strings.TrimSpace(finding.EffectiveSeverity)
	}
	if finding.LikelihoodScore != 0 {
		attributes["likelihood_score"] = fmt.Sprintf("%d", finding.LikelihoodScore)
	}
	if finding.ImpactScore != 0 {
		attributes["impact_score"] = fmt.Sprintf("%d", finding.ImpactScore)
	}
	if finding.ConfidenceScore != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", float64(finding.ConfidenceScore)/100)
		attributes["confidence_score"] = fmt.Sprintf("%d", finding.ConfidenceScore)
	}
	if finding.EventCount != 0 {
		attributes["event_count"] = fmt.Sprintf("%d", finding.EventCount)
	}
	trimEmptyProjectionAttributes(attributes)
	return attributes
}

func findingSourceEventID(finding workflowevents.FindingSnapshot) string {
	for _, eventID := range normalizeIDs(finding.EventIDs) {
		if strings.TrimSpace(eventID) != "" {
			return strings.TrimSpace(eventID)
		}
	}
	return strings.TrimSpace(finding.FindingID)
}

func findingControlRefsAttribute(refs []workflowevents.FindingControlRefSnapshot) string {
	if len(refs) == 0 {
		return ""
	}
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		frameworkName := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if frameworkName == "" && controlID == "" {
			continue
		}
		values = append(values, frameworkName+":"+controlID)
	}
	return strings.Join(normalizeIDs(values), ",")
}

func trimEmptyProjectionAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
			continue
		}
		attributes[key] = strings.TrimSpace(value)
	}
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

func findingExternalRefURN(tenantID string, system string, kind string, externalID string) string {
	return fmt.Sprintf("urn:cerebro:%s:external_ref:%s", strings.TrimSpace(tenantID), graphHash(strings.TrimSpace(system), strings.TrimSpace(kind), strings.TrimSpace(externalID)))
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

func findingExternalRefLabel(system string, kind string, externalID string) string {
	return graphEntityLabel(strings.Join([]string{strings.TrimSpace(system), strings.TrimSpace(kind), strings.TrimSpace(externalID)}, " "))
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
