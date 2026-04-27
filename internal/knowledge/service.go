package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultSourceSystem     = "platform.knowledge"
	defaultDecisionStatus   = "proposed"
	defaultGraphLookupLimit = 1
	decisionEntityType      = "decision"
	outcomeEntityType       = "outcome"
	evidenceEntityType      = "evidence"
	actionEntityType        = "action"
	relationTargets         = "targets"
	relationBasedOn         = "based_on"
	relationExecutedBy      = "executed_by"
	relationEvaluates       = "evaluates"
	graphEntityLabelLimit   = 160
	defaultPlatformTenant   = "platform"
)

// ErrRuntimeUnavailable indicates that the graph read/write boundaries are unavailable.
var ErrRuntimeUnavailable = errors.New("knowledge runtime is unavailable")

// Service records workflow primitives onto the graph-backed platform layer.
type Service struct {
	query ports.GraphQueryStore
	graph ports.ProjectionGraphStore
}

// DecisionWriteRequest scopes one platform decision write.
type DecisionWriteRequest struct {
	ID            string
	DecisionType  string
	Status        string
	MadeBy        string
	Rationale     string
	TargetIDs     []string
	EvidenceIDs   []string
	ActionIDs     []string
	SourceSystem  string
	SourceEventID string
	ObservedAt    time.Time
	ValidFrom     time.Time
	ValidTo       time.Time
	Confidence    float64
	Metadata      map[string]any
}

// DecisionWriteResult reports one recorded platform decision.
type DecisionWriteResult struct {
	DecisionID  string
	TargetCount uint32
}

// OutcomeWriteRequest scopes one outcome write tied back to one decision.
type OutcomeWriteRequest struct {
	ID            string
	DecisionID    string
	OutcomeType   string
	Verdict       string
	ImpactScore   float64
	TargetIDs     []string
	SourceSystem  string
	SourceEventID string
	ObservedAt    time.Time
	ValidFrom     time.Time
	ValidTo       time.Time
	Confidence    float64
	Metadata      map[string]any
}

// OutcomeWriteResult reports one recorded outcome.
type OutcomeWriteResult struct {
	OutcomeID   string
	DecisionID  string
	TargetCount uint32
}

// New constructs one platform knowledge write service.
func New(query ports.GraphQueryStore, graph ports.ProjectionGraphStore) *Service {
	return &Service{query: query, graph: graph}
}

// WriteDecision records one decision node plus its target, evidence, and action links.
func (s *Service) WriteDecision(ctx context.Context, request DecisionWriteRequest) (*DecisionWriteResult, error) {
	if s == nil || s.query == nil || s.graph == nil {
		return nil, ErrRuntimeUnavailable
	}
	decisionType := strings.TrimSpace(request.DecisionType)
	if decisionType == "" {
		return nil, errors.New("decision type is required")
	}
	targetIDs := normalizeIDs(request.TargetIDs)
	if len(targetIDs) == 0 {
		return nil, errors.New("decision target ids are required")
	}
	tenantID := inferTenantID(request.Metadata, targetIDs...)
	sourceSystem := firstNonEmpty(strings.TrimSpace(request.SourceSystem), defaultSourceSystem)
	decisionID := canonicalWorkflowID(tenantID, decisionEntityType, request.ID, decisionType, targetIDs, request.ObservedAt)
	observedAt := normalizeObservedAt(request.ObservedAt)
	validFrom := normalizeValidFrom(request.ValidFrom, observedAt)
	status := firstNonEmpty(strings.TrimSpace(request.Status), defaultDecisionStatus)
	attributes, err := decisionAttributes(request, observedAt, validFrom)
	if err != nil {
		return nil, err
	}
	if err := s.graph.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        decisionID,
		TenantID:   tenantID,
		SourceID:   sourceSystem,
		EntityType: decisionEntityType,
		Label:      decisionLabel(decisionType, status, request.Rationale),
		Attributes: attributes,
	}); err != nil {
		return nil, fmt.Errorf("upsert decision %q: %w", decisionID, err)
	}
	for _, targetID := range targetIDs {
		if err := s.requireEntity(ctx, targetID); err != nil {
			return nil, err
		}
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceSystem,
			FromURN:  decisionID,
			ToURN:    targetID,
			Relation: relationTargets,
			Attributes: map[string]string{
				"decision_id": decisionID,
			},
		}); err != nil {
			return nil, fmt.Errorf("link decision %q to target %q: %w", decisionID, targetID, err)
		}
	}
	for _, evidenceID := range normalizeIDs(request.EvidenceIDs) {
		referenceURN, err := s.ensureReferenceEntity(ctx, tenantID, sourceSystem, evidenceEntityType, evidenceID)
		if err != nil {
			return nil, err
		}
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceSystem,
			FromURN:  decisionID,
			ToURN:    referenceURN,
			Relation: relationBasedOn,
			Attributes: map[string]string{
				"decision_id": decisionID,
			},
		}); err != nil {
			return nil, fmt.Errorf("link decision %q to evidence %q: %w", decisionID, referenceURN, err)
		}
	}
	for _, actionID := range normalizeIDs(request.ActionIDs) {
		referenceURN, err := s.ensureReferenceEntity(ctx, tenantID, sourceSystem, actionEntityType, actionID)
		if err != nil {
			return nil, err
		}
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceSystem,
			FromURN:  decisionID,
			ToURN:    referenceURN,
			Relation: relationExecutedBy,
			Attributes: map[string]string{
				"decision_id": decisionID,
			},
		}); err != nil {
			return nil, fmt.Errorf("link decision %q to action %q: %w", decisionID, referenceURN, err)
		}
	}
	return &DecisionWriteResult{
		DecisionID:  decisionID,
		TargetCount: uint32(len(targetIDs)),
	}, nil
}

// WriteOutcome records one outcome node tied back to one decision.
func (s *Service) WriteOutcome(ctx context.Context, request OutcomeWriteRequest) (*OutcomeWriteResult, error) {
	if s == nil || s.query == nil || s.graph == nil {
		return nil, ErrRuntimeUnavailable
	}
	outcomeType := strings.TrimSpace(request.OutcomeType)
	if outcomeType == "" {
		return nil, errors.New("outcome type is required")
	}
	verdict := strings.TrimSpace(request.Verdict)
	if verdict == "" {
		return nil, errors.New("outcome verdict is required")
	}
	targetIDs := normalizeIDs(request.TargetIDs)
	tenantID := inferTenantID(request.Metadata, append(targetIDs, request.DecisionID)...)
	sourceSystem := firstNonEmpty(strings.TrimSpace(request.SourceSystem), defaultSourceSystem)
	decisionID := canonicalWorkflowID(tenantID, decisionEntityType, request.DecisionID, decisionEntityType, targetIDs, request.ValidFrom)
	if strings.TrimSpace(request.DecisionID) == "" {
		return nil, errors.New("outcome decision id is required")
	}
	if err := s.requireEntity(ctx, decisionID); err != nil {
		return nil, err
	}
	observedAt := normalizeObservedAt(request.ObservedAt)
	validFrom := normalizeValidFrom(request.ValidFrom, observedAt)
	outcomeID := canonicalWorkflowID(tenantID, outcomeEntityType, request.ID, outcomeType, append([]string{decisionID}, targetIDs...), request.ObservedAt)
	attributes, err := outcomeAttributes(request, decisionID, observedAt, validFrom)
	if err != nil {
		return nil, err
	}
	if err := s.graph.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        outcomeID,
		TenantID:   tenantID,
		SourceID:   sourceSystem,
		EntityType: outcomeEntityType,
		Label:      outcomeLabel(outcomeType, verdict),
		Attributes: attributes,
	}); err != nil {
		return nil, fmt.Errorf("upsert outcome %q: %w", outcomeID, err)
	}
	if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
		TenantID: tenantID,
		SourceID: sourceSystem,
		FromURN:  outcomeID,
		ToURN:    decisionID,
		Relation: relationEvaluates,
		Attributes: map[string]string{
			"outcome_id":  outcomeID,
			"decision_id": decisionID,
		},
	}); err != nil {
		return nil, fmt.Errorf("link outcome %q to decision %q: %w", outcomeID, decisionID, err)
	}
	for _, targetID := range targetIDs {
		if err := s.requireEntity(ctx, targetID); err != nil {
			return nil, err
		}
		if err := s.graph.UpsertProjectedLink(ctx, &ports.ProjectedLink{
			TenantID: tenantID,
			SourceID: sourceSystem,
			FromURN:  outcomeID,
			ToURN:    targetID,
			Relation: relationTargets,
			Attributes: map[string]string{
				"outcome_id": outcomeID,
			},
		}); err != nil {
			return nil, fmt.Errorf("link outcome %q to target %q: %w", outcomeID, targetID, err)
		}
	}
	return &OutcomeWriteResult{
		OutcomeID:   outcomeID,
		DecisionID:  decisionID,
		TargetCount: uint32(len(targetIDs)),
	}, nil
}

func (s *Service) requireEntity(ctx context.Context, id string) error {
	if s == nil || s.query == nil {
		return ErrRuntimeUnavailable
	}
	entityID := strings.TrimSpace(id)
	if entityID == "" {
		return errors.New("graph entity id is required")
	}
	if _, err := s.query.GetEntityNeighborhood(ctx, entityID, defaultGraphLookupLimit); err != nil {
		if errors.Is(err, ports.ErrGraphEntityNotFound) {
			return fmt.Errorf("%w: %s", ports.ErrGraphEntityNotFound, entityID)
		}
		return fmt.Errorf("load graph entity %q: %w", entityID, err)
	}
	return nil
}

func (s *Service) ensureReferenceEntity(ctx context.Context, tenantID string, sourceSystem string, entityType string, value string) (string, error) {
	referenceID := strings.TrimSpace(value)
	if referenceID == "" {
		return "", errors.New("reference id is required")
	}
	if strings.HasPrefix(referenceID, "urn:") {
		return referenceID, nil
	}
	urn := canonicalWorkflowID(tenantID, entityType, referenceID, entityType, nil, time.Time{})
	if err := s.graph.UpsertProjectedEntity(ctx, &ports.ProjectedEntity{
		URN:        urn,
		TenantID:   tenantID,
		SourceID:   sourceSystem,
		EntityType: entityType,
		Label:      graphEntityLabel(referenceID),
		Attributes: map[string]string{
			"reference_id": referenceID,
		},
	}); err != nil {
		return "", fmt.Errorf("upsert %s reference %q: %w", entityType, urn, err)
	}
	return urn, nil
}

func decisionAttributes(request DecisionWriteRequest, observedAt time.Time, validFrom time.Time) (map[string]string, error) {
	attributes := map[string]string{
		"decision_type":   strings.TrimSpace(request.DecisionType),
		"status":          firstNonEmpty(strings.TrimSpace(request.Status), defaultDecisionStatus),
		"made_by":         strings.TrimSpace(request.MadeBy),
		"rationale":       strings.TrimSpace(request.Rationale),
		"source_system":   firstNonEmpty(strings.TrimSpace(request.SourceSystem), defaultSourceSystem),
		"source_event_id": strings.TrimSpace(request.SourceEventID),
		"observed_at":     observedAt.Format(time.RFC3339Nano),
		"valid_from":      validFrom.Format(time.RFC3339Nano),
	}
	if !request.ValidTo.UTC().IsZero() {
		attributes["valid_to"] = request.ValidTo.UTC().Format(time.RFC3339Nano)
	}
	if request.Confidence != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", request.Confidence)
	}
	metadataJSON, err := metadataJSON(request.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal decision metadata: %w", err)
	}
	attributes["metadata_json"] = metadataJSON
	return attributes, nil
}

func outcomeAttributes(request OutcomeWriteRequest, decisionID string, observedAt time.Time, validFrom time.Time) (map[string]string, error) {
	attributes := map[string]string{
		"decision_id":     decisionID,
		"outcome_type":    strings.TrimSpace(request.OutcomeType),
		"verdict":         strings.TrimSpace(request.Verdict),
		"source_system":   firstNonEmpty(strings.TrimSpace(request.SourceSystem), defaultSourceSystem),
		"source_event_id": strings.TrimSpace(request.SourceEventID),
		"observed_at":     observedAt.Format(time.RFC3339Nano),
		"valid_from":      validFrom.Format(time.RFC3339Nano),
	}
	if !request.ValidTo.UTC().IsZero() {
		attributes["valid_to"] = request.ValidTo.UTC().Format(time.RFC3339Nano)
	}
	if request.ImpactScore != 0 {
		attributes["impact_score"] = fmt.Sprintf("%.6g", request.ImpactScore)
	}
	if request.Confidence != 0 {
		attributes["confidence"] = fmt.Sprintf("%.6g", request.Confidence)
	}
	metadataJSON, err := metadataJSON(request.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal outcome metadata: %w", err)
	}
	attributes["metadata_json"] = metadataJSON
	return attributes, nil
}

func inferTenantID(metadata map[string]any, ids ...string) string {
	if value, ok := metadata["tenant_id"].(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if !strings.HasPrefix(trimmed, "urn:cerebro:") {
			continue
		}
		parts := strings.Split(trimmed, ":")
		if len(parts) >= 4 && strings.TrimSpace(parts[2]) != "" {
			return strings.TrimSpace(parts[2])
		}
	}
	return defaultPlatformTenant
}

func canonicalWorkflowID(tenantID string, entityType string, providedID string, kind string, relatedIDs []string, at time.Time) string {
	value := strings.TrimSpace(providedID)
	if strings.HasPrefix(value, "urn:") {
		return value
	}
	if value == "" {
		payload := append([]string{entityType, kind}, relatedIDs...)
		if !at.UTC().IsZero() {
			payload = append(payload, at.UTC().Format(time.RFC3339Nano))
		}
		value = shortHash(strings.Join(payload, "\n"))
	}
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	return fmt.Sprintf("urn:cerebro:%s:%s:%s", strings.TrimSpace(tenantID), entityType, replacer.Replace(value))
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

func normalizeObservedAt(value time.Time) time.Time {
	observedAt := value.UTC()
	if observedAt.IsZero() {
		return time.Now().UTC()
	}
	return observedAt
}

func normalizeValidFrom(value time.Time, observedAt time.Time) time.Time {
	validFrom := value.UTC()
	if validFrom.IsZero() {
		return observedAt
	}
	return validFrom
}

func decisionLabel(decisionType string, status string, rationale string) string {
	if trimmed := graphEntityLabel(strings.TrimSpace(rationale)); trimmed != "" {
		return trimmed
	}
	return graphEntityLabel(strings.TrimSpace(decisionType) + " " + strings.TrimSpace(status))
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

func metadataJSON(value map[string]any) (string, error) {
	if len(value) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
