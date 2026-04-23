package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceprojection"
)

const (
	defaultEventLimit = 100
	maxEventLimit     = 1000

	oktaPolicyRuleLifecycleTamperingRuleID   = "identity-okta-policy-rule-lifecycle-tampering"
	oktaPolicyRuleLifecycleTamperingTitle    = "Okta Policy Rule Lifecycle Tampering"
	oktaPolicyRuleLifecycleTamperingSeverity = "HIGH"
	oktaPolicyRuleLifecycleTamperingStatus   = "open"
)

var (
	// ErrRuntimeUnavailable indicates that the runtime, replay, or finding store boundary is unavailable.
	ErrRuntimeUnavailable = errors.New("finding runtime is unavailable")

	oktaPolicyRuleLifecycleTamperingEventTypes = map[string]struct{}{
		"policy.rule.update":     {},
		"policy.rule.deactivate": {},
		"policy.rule.delete":     {},
	}
	oktaPolicyRuleLifecycleTamperingOutcomes = map[string]struct{}{
		"success": {},
		"allow":   {},
		"allowed": {},
	}
)

// Service replays runtime events through a fixed finding evaluator and persists emitted findings.
type Service struct {
	runtimeStore ports.SourceRuntimeStore
	replayer     ports.EventReplayer
	store        ports.FindingStore
}

// EvaluateRequest scopes one replay-backed finding evaluation.
type EvaluateRequest struct {
	RuntimeID  string
	EventLimit uint32
}

// EvaluateResult reports the persisted findings emitted for one runtime evaluation.
type EvaluateResult struct {
	Runtime         *cerebrov1.SourceRuntime
	Rule            *cerebrov1.RuleSpec
	EventsEvaluated uint32
	Findings        []*ports.FindingRecord
}

// New constructs a replay-backed finding service.
func New(runtimeStore ports.SourceRuntimeStore, replayer ports.EventReplayer, store ports.FindingStore) *Service {
	return &Service{
		runtimeStore: runtimeStore,
		replayer:     replayer,
		store:        store,
	}
}

// EvaluateSourceRuntime replays one runtime and persists findings for matching Okta audit events.
func (s *Service) EvaluateSourceRuntime(ctx context.Context, request EvaluateRequest) (*EvaluateResult, error) {
	if s == nil || s.runtimeStore == nil || s.replayer == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, errors.New("source runtime id is required")
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	events, err := s.replayer.Replay(ctx, ports.ReplayRequest{
		RuntimeID: runtimeID,
		Limit:     normalizeEventLimit(request.EventLimit),
	})
	if err != nil {
		return nil, fmt.Errorf("replay runtime %q events: %w", runtimeID, err)
	}
	result := &EvaluateResult{
		Runtime:         runtime,
		Rule:            oktaPolicyRuleLifecycleTamperingRuleSpec(),
		EventsEvaluated: uint32(len(events)),
	}
	for _, event := range events {
		if !matchesOktaPolicyRuleLifecycleTampering(event) {
			continue
		}
		record, err := oktaPolicyRuleLifecycleTamperingFinding(ctx, event, runtimeID)
		if err != nil {
			return nil, err
		}
		stored, err := s.store.UpsertFinding(ctx, record)
		if err != nil {
			return nil, fmt.Errorf("persist finding for event %q: %w", event.GetId(), err)
		}
		result.Findings = append(result.Findings, stored)
	}
	return result, nil
}

func normalizeEventLimit(limit uint32) uint32 {
	switch {
	case limit == 0:
		return defaultEventLimit
	case limit > maxEventLimit:
		return maxEventLimit
	default:
		return limit
	}
}

func oktaPolicyRuleLifecycleTamperingRuleSpec() *cerebrov1.RuleSpec {
	return &cerebrov1.RuleSpec{
		Id:          oktaPolicyRuleLifecycleTamperingRuleID,
		Name:        oktaPolicyRuleLifecycleTamperingTitle,
		Description: "Detect successful Okta policy rule update, deactivate, or delete events replayed from one source runtime.",
		InputStreamIds: []string{
			"source-runtime-replay",
		},
		OutputKinds: []string{
			"finding.okta_policy_rule_lifecycle_tampering",
		},
	}
}

func matchesOktaPolicyRuleLifecycleTampering(event *cerebrov1.EventEnvelope) bool {
	if event == nil || !strings.EqualFold(strings.TrimSpace(event.GetKind()), "okta.audit") {
		return false
	}
	attributes := event.GetAttributes()
	eventType := strings.ToLower(strings.TrimSpace(attributes["event_type"]))
	if _, ok := oktaPolicyRuleLifecycleTamperingEventTypes[eventType]; !ok {
		return false
	}
	outcome := strings.ToLower(strings.TrimSpace(attributes["outcome_result"]))
	if outcome == "" {
		outcome = "success"
	}
	_, ok := oktaPolicyRuleLifecycleTamperingOutcomes[outcome]
	return ok
}

func oktaPolicyRuleLifecycleTamperingFinding(ctx context.Context, event *cerebrov1.EventEnvelope, runtimeID string) (*ports.FindingRecord, error) {
	resourceURNs, actorURN, resourceURN, actorLabel, resourceLabel, err := projectedEntityContext(ctx, event)
	if err != nil {
		return nil, fmt.Errorf("project finding context for event %q: %w", event.GetId(), err)
	}
	attributes := map[string]string{
		"event_id":             strings.TrimSpace(event.GetId()),
		"event_type":           strings.TrimSpace(event.GetAttributes()["event_type"]),
		"outcome_result":       strings.TrimSpace(event.GetAttributes()["outcome_result"]),
		"source_runtime_id":    strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]),
		"primary_actor_urn":    actorURN,
		"primary_resource_urn": resourceURN,
	}
	trimEmptyAttributes(attributes)
	observedAt := time.Time{}
	if timestamp := event.GetOccurredAt(); timestamp != nil {
		observedAt = timestamp.AsTime().UTC()
	}
	fingerprint := hashFindingFingerprint(oktaPolicyRuleLifecycleTamperingRuleID, event.GetId())
	return &ports.FindingRecord{
		ID:              fingerprint,
		Fingerprint:     fingerprint,
		TenantID:        strings.TrimSpace(event.GetTenantId()),
		RuntimeID:       strings.TrimSpace(runtimeID),
		RuleID:          oktaPolicyRuleLifecycleTamperingRuleID,
		Title:           oktaPolicyRuleLifecycleTamperingTitle,
		Severity:        oktaPolicyRuleLifecycleTamperingSeverity,
		Status:          oktaPolicyRuleLifecycleTamperingStatus,
		Summary:         findingSummary(event, actorLabel, resourceLabel),
		ResourceURNs:    resourceURNs,
		EventIDs:        []string{strings.TrimSpace(event.GetId())},
		Attributes:      attributes,
		FirstObservedAt: observedAt,
		LastObservedAt:  observedAt,
	}, nil
}

func projectedEntityContext(ctx context.Context, event *cerebrov1.EventEnvelope) ([]string, string, string, string, string, error) {
	recorder := &projectionRecorder{
		entities: make(map[string]*ports.ProjectedEntity),
		links:    make(map[string]*ports.ProjectedLink),
	}
	if ctx == nil {
		return nil, "", "", "", "", errors.New("context is required")
	}
	if _, err := sourceprojection.New(nil, recorder).Project(ctx, event); err != nil {
		return nil, "", "", "", "", err
	}
	resourceURNs := make([]string, 0, len(recorder.entities))
	seenURNs := make(map[string]struct{}, len(recorder.entities))
	var actorURN string
	var resourceURN string
	for _, link := range recorder.links {
		if !strings.EqualFold(strings.TrimSpace(link.Relation), "acted_on") {
			continue
		}
		if actorURN == "" {
			actorURN = strings.TrimSpace(link.FromURN)
		}
		if resourceURN == "" {
			resourceURN = strings.TrimSpace(link.ToURN)
		}
		if candidate := strings.TrimSpace(link.FromURN); candidate != "" {
			if _, ok := seenURNs[candidate]; !ok {
				seenURNs[candidate] = struct{}{}
				resourceURNs = append(resourceURNs, candidate)
			}
		}
		if candidate := strings.TrimSpace(link.ToURN); candidate != "" {
			if _, ok := seenURNs[candidate]; !ok {
				seenURNs[candidate] = struct{}{}
				resourceURNs = append(resourceURNs, candidate)
			}
		}
	}
	slices.Sort(resourceURNs)
	actorLabel := entityLabel(recorder.entities[actorURN], event.GetAttributes()["actor_alternate_id"], event.GetAttributes()["actor_display_name"], event.GetAttributes()["actor_id"])
	resourceLabel := entityLabel(recorder.entities[resourceURN], event.GetAttributes()["resource_id"], event.GetAttributes()["resource_type"])
	return resourceURNs, actorURN, resourceURN, actorLabel, resourceLabel, nil
}

func entityLabel(entity *ports.ProjectedEntity, fallbacks ...string) string {
	if entity != nil && strings.TrimSpace(entity.Label) != "" {
		return strings.TrimSpace(entity.Label)
	}
	for _, fallback := range fallbacks {
		if strings.TrimSpace(fallback) != "" {
			return strings.TrimSpace(fallback)
		}
	}
	return ""
}

func findingSummary(event *cerebrov1.EventEnvelope, actorLabel string, resourceLabel string) string {
	eventType := strings.TrimSpace(event.GetAttributes()["event_type"])
	actor := firstNonEmpty(actorLabel, event.GetAttributes()["actor_alternate_id"], event.GetAttributes()["actor_display_name"], event.GetAttributes()["actor_id"], "unknown actor")
	resource := firstNonEmpty(resourceLabel, event.GetAttributes()["resource_id"], event.GetAttributes()["resource_type"], "unknown resource")
	return fmt.Sprintf("%s performed %s on %s", actor, eventType, resource)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func trimEmptyAttributes(attributes map[string]string) {
	for key, value := range attributes {
		if strings.TrimSpace(value) == "" {
			delete(attributes, key)
		}
	}
}

func hashFindingFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strings.TrimSpace(part)))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type projectionRecorder struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (r *projectionRecorder) Ping(context.Context) error {
	return nil
}

func (r *projectionRecorder) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	r.entities[entity.URN] = cloneEntity(entity)
	return nil
}

func (r *projectionRecorder) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	key := strings.TrimSpace(link.FromURN) + "|" + strings.TrimSpace(link.Relation) + "|" + strings.TrimSpace(link.ToURN)
	r.links[key] = cloneLink(link)
	return nil
}

func cloneEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	if entity == nil {
		return nil
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
}

func cloneLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}
