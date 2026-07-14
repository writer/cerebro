package workflowevents

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	eventregistry "github.com/WriterInternal/event-registry/clients/go"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const (
	EventKindKnowledgeDecisionRecorded = "workflow.v1.knowledge.decision_recorded"
	EventKindKnowledgeActionRecorded   = "workflow.v1.knowledge.action_recorded"
	EventKindKnowledgeOutcomeRecorded  = "workflow.v1.knowledge.outcome_recorded"
	EventKindFindingRecorded           = "workflow.v1.finding.recorded"
	EventKindFindingNoteAdded          = "workflow.v1.finding.note_added"
	EventKindFindingTicketLinked       = "workflow.v1.finding.ticket_linked"
	EventKindFindingStatusChanged      = "workflow.v1.finding.status_changed"

	EventAttributeTenantID     = "tenant_id"
	EventAttributeSourceSystem = "source_system"
	EventAttributeWorkflowKind = "workflow_kind"
	EventAttributeDecisionID   = "decision_id"
	EventAttributeActionID     = "action_id"
	EventAttributeObservation  = "observation_digest"
	EventAttributeOutcomeID    = "outcome_id"
	EventAttributeFindingID    = "finding_id"
	EventAttributeSourceEvent  = "source_event_id"
	EventAttributeStatusSource = "status_source"
)

const (
	FindingStatusReasonNoLongerEmitted      = "No longer emitted by latest rule evaluation."
	FindingStatusReasonClosedByCounterEvent = "closed_by_counter_event"
	FindingStatusReasonTTLExpired           = "ttl_expired"
	FindingStatusSourceManual               = "manual"
	FindingStatusSourceStaleEvaluation      = "stale_rule_evaluation"
)

const (
	SchemaKnowledgeDecisionRecorded = "urn:cerebro:events/workflow.knowledge.decision_recorded/v1"
	SchemaKnowledgeActionRecorded   = "urn:cerebro:events/workflow.knowledge.action_recorded/v1"
	SchemaKnowledgeOutcomeRecorded  = "urn:cerebro:events/workflow.knowledge.outcome_recorded/v1"
	SchemaFindingRecorded           = "urn:cerebro:events/workflow.finding.recorded/v1"
	SchemaFindingNoteAdded          = "urn:cerebro:events/workflow.finding.note_added/v1"
	SchemaFindingTicketLinked       = "urn:cerebro:events/workflow.finding.ticket_linked/v1"
	SchemaFindingStatusChanged      = "urn:cerebro:events/workflow.finding.status_changed/v1"
)

// DecisionRecorded captures one durable workflow decision event payload.
type DecisionRecorded struct {
	TenantID      string         `json:"tenant_id"`
	DecisionID    string         `json:"decision_id"`
	DecisionType  string         `json:"decision_type"`
	Status        string         `json:"status"`
	MadeBy        string         `json:"made_by,omitempty"`
	Rationale     string         `json:"rationale,omitempty"`
	TargetIDs     []string       `json:"target_ids"`
	EvidenceIDs   []string       `json:"evidence_ids,omitempty"`
	ActionIDs     []string       `json:"action_ids,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID string         `json:"source_event_id,omitempty"`
	ObservedAt    string         `json:"observed_at"`
	ValidFrom     string         `json:"valid_from"`
	ValidTo       string         `json:"valid_to,omitempty"`
	Confidence    float64        `json:"confidence,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// FindingStatusPrunesGraph reports whether one status transition should remove ephemeral finding graph anchors.
func FindingStatusPrunesGraph(status string, source string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "resolved") &&
		strings.EqualFold(strings.TrimSpace(source), FindingStatusSourceStaleEvaluation)
}

// LegacyFindingStatusPrunesGraph preserves replay behavior for stale-resolution events emitted before status source existed.
func LegacyFindingStatusPrunesGraph(status string, source string, reason string, decisionID string, outcomeID string) bool {
	return strings.TrimSpace(source) == "" &&
		strings.TrimSpace(decisionID) == "" &&
		strings.TrimSpace(outcomeID) == "" &&
		strings.EqualFold(strings.TrimSpace(status), "resolved") &&
		strings.EqualFold(strings.TrimSpace(reason), FindingStatusReasonNoLongerEmitted)
}

// ActionRecorded captures one durable workflow action event payload.
type ActionRecorded struct {
	TenantID         string         `json:"tenant_id"`
	ActionID         string         `json:"action_id"`
	ActionType       string         `json:"action_type"`
	Status           string         `json:"status"`
	RecommendationID string         `json:"recommendation_id,omitempty"`
	InsightType      string         `json:"insight_type,omitempty"`
	Title            string         `json:"title"`
	Summary          string         `json:"summary,omitempty"`
	DecisionID       string         `json:"decision_id,omitempty"`
	TargetIDs        []string       `json:"target_ids"`
	SourceSystem     string         `json:"source_system"`
	SourceEventID    string         `json:"source_event_id,omitempty"`
	ObservedAt       string         `json:"observed_at"`
	ValidFrom        string         `json:"valid_from"`
	ValidTo          string         `json:"valid_to,omitempty"`
	Confidence       float64        `json:"confidence,omitempty"`
	AutoGenerated    bool           `json:"auto_generated"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// OutcomeRecorded captures one durable workflow outcome event payload.
type OutcomeRecorded struct {
	TenantID      string         `json:"tenant_id"`
	OutcomeID     string         `json:"outcome_id"`
	DecisionID    string         `json:"decision_id"`
	OutcomeType   string         `json:"outcome_type"`
	Verdict       string         `json:"verdict"`
	ImpactScore   float64        `json:"impact_score,omitempty"`
	TargetIDs     []string       `json:"target_ids,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID string         `json:"source_event_id,omitempty"`
	ObservedAt    string         `json:"observed_at"`
	ValidFrom     string         `json:"valid_from"`
	ValidTo       string         `json:"valid_to,omitempty"`
	Confidence    float64        `json:"confidence,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// FindingSnapshot captures the finding fields needed to rebuild workflow graph projections.
type FindingSnapshot struct {
	TenantID           string                      `json:"tenant_id"`
	SourceSystem       string                      `json:"source_system"`
	FindingID          string                      `json:"finding_id"`
	Fingerprint        string                      `json:"fingerprint,omitempty"`
	Title              string                      `json:"title,omitempty"`
	Summary            string                      `json:"summary,omitempty"`
	RuleID             string                      `json:"rule_id,omitempty"`
	Severity           string                      `json:"severity,omitempty"`
	Status             string                      `json:"status,omitempty"`
	RuntimeID          string                      `json:"runtime_id,omitempty"`
	PolicyID           string                      `json:"policy_id,omitempty"`
	CheckID            string                      `json:"check_id,omitempty"`
	PrimaryResourceURN string                      `json:"primary_resource_urn,omitempty"`
	ResourceURNs       []string                    `json:"resource_urns,omitempty"`
	EventIDs           []string                    `json:"event_ids,omitempty"`
	FirstObservedAt    string                      `json:"first_observed_at,omitempty"`
	LastObservedAt     string                      `json:"last_observed_at,omitempty"`
	ResourceCount      int                         `json:"resource_count,omitempty"`
	EventCount         int                         `json:"event_count,omitempty"`
	ControlRefs        []FindingControlRefSnapshot `json:"control_refs,omitempty"`
	FindingRiskSnapshot
	Metadata map[string]string `json:"metadata,omitempty"`
}

// FindingRiskSnapshot captures normalized finding risk scoring metadata in workflow events.
type FindingRiskSnapshot struct {
	RiskScore         int      `json:"risk_score,omitempty"`
	EffectiveSeverity string   `json:"effective_severity,omitempty"`
	LikelihoodScore   int      `json:"likelihood_score,omitempty"`
	ImpactScore       int      `json:"impact_score,omitempty"`
	ConfidenceScore   int      `json:"confidence_score,omitempty"`
	LikelihoodLevel   string   `json:"likelihood_level,omitempty"`
	ImpactLevel       string   `json:"impact_level,omitempty"`
	RiskModelVersion  string   `json:"risk_model_version,omitempty"`
	RiskReasons       []string `json:"risk_reasons,omitempty"`
}

// FindingControlRefSnapshot captures one generic compliance/control reference for graph projection.
type FindingControlRefSnapshot struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

// FindingRecorded captures one durable finding graph anchor event.
type FindingRecorded struct {
	Finding    FindingSnapshot `json:"finding"`
	RecordedAt string          `json:"recorded_at"`
}

// FindingNoteAdded captures one durable finding note event payload.
type FindingNoteAdded struct {
	Finding   FindingSnapshot `json:"finding"`
	NoteID    string          `json:"note_id"`
	Body      string          `json:"body"`
	CreatedAt string          `json:"created_at"`
}

// FindingTicketLinked captures one durable finding ticket event payload.
type FindingTicketLinked struct {
	Finding    FindingSnapshot `json:"finding"`
	URL        string          `json:"url"`
	Name       string          `json:"name,omitempty"`
	ExternalID string          `json:"external_id,omitempty"`
	LinkedAt   string          `json:"linked_at"`
}

// FindingStatusChanged captures one durable finding status event payload.
type FindingStatusChanged struct {
	Finding     FindingSnapshot `json:"finding"`
	Status      string          `json:"status"`
	Reason      string          `json:"reason,omitempty"`
	Source      string          `json:"source,omitempty"`
	UpdatedAt   string          `json:"updated_at"`
	DecisionID  string          `json:"decision_id,omitempty"`
	OutcomeID   string          `json:"outcome_id,omitempty"`
	OutcomeType string          `json:"outcome_type,omitempty"`
}

// NewDecisionRecordedEvent builds the durable event envelope for one recorded decision.
func NewDecisionRecordedEvent(payload DecisionRecorded) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryDecisionRecorded(payload), SchemaKnowledgeDecisionRecorded, payload.TenantID, payload.SourceSystem, payload.DecisionID, payload.ObservedAt, map[string]string{
		EventAttributeWorkflowKind: "knowledge_decision",
		EventAttributeDecisionID:   payload.DecisionID,
		EventAttributeSourceEvent:  payload.SourceEventID,
	})
}

// NewActionRecordedEvent builds the durable event envelope for one recorded action.
func NewActionRecordedEvent(payload ActionRecorded) (*cerebrov1.EventEnvelope, error) {
	return newActionRecordedEvent(payload, payload.ActionID, "")
}

// NewActionRecordedObservationEvent builds an immutable lifecycle observation for one stable action.
// Reusing the same observation digest is idempotent while a material provider transition receives a
// distinct event identity. The action entity remains addressed by payload.ActionID.
func NewActionRecordedObservationEvent(payload ActionRecorded, observationDigest string) (*cerebrov1.EventEnvelope, error) {
	observationDigest = strings.TrimSpace(observationDigest)
	if observationDigest == "" {
		return nil, fmt.Errorf("workflow action observation digest is required")
	}
	return newActionRecordedEvent(payload, payload.ActionID+"\x00"+observationDigest, observationDigest)
}

func newActionRecordedEvent(payload ActionRecorded, eventIdentity string, observationDigest string) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryActionRecorded(payload), SchemaKnowledgeActionRecorded, payload.TenantID, payload.SourceSystem, eventIdentity, payload.ObservedAt, map[string]string{
		EventAttributeWorkflowKind: "knowledge_action",
		EventAttributeActionID:     payload.ActionID,
		EventAttributeObservation:  observationDigest,
		EventAttributeDecisionID:   payload.DecisionID,
		EventAttributeSourceEvent:  payload.SourceEventID,
	})
}

// NewOutcomeRecordedEvent builds the durable event envelope for one recorded outcome.
func NewOutcomeRecordedEvent(payload OutcomeRecorded) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryOutcomeRecorded(payload), SchemaKnowledgeOutcomeRecorded, payload.TenantID, payload.SourceSystem, payload.OutcomeID, payload.ObservedAt, map[string]string{
		EventAttributeWorkflowKind: "knowledge_outcome",
		EventAttributeOutcomeID:    payload.OutcomeID,
		EventAttributeDecisionID:   payload.DecisionID,
		EventAttributeSourceEvent:  payload.SourceEventID,
	})
}

// NewFindingRecordedEvent builds the durable event envelope for one upserted finding.
func NewFindingRecordedEvent(payload FindingRecorded) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryFindingRecorded(payload), SchemaFindingRecorded, payload.Finding.TenantID, payload.Finding.SourceSystem, payload.Finding.FindingID, payload.RecordedAt, map[string]string{
		EventAttributeWorkflowKind: "finding_record",
		EventAttributeFindingID:    payload.Finding.FindingID,
	})
}

// NewFindingRecordedRevisionEvent builds a non-deduplicated finding record event.
func NewFindingRecordedRevisionEvent(payload FindingRecorded, revision string, occurredAt time.Time) (*cerebrov1.EventEnvelope, error) {
	primaryID := payload.Finding.FindingID
	if trimmed := strings.TrimSpace(revision); trimmed != "" {
		primaryID += "|" + trimmed
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	return newEvent(registryFindingRecorded(payload), SchemaFindingRecorded, payload.Finding.TenantID, payload.Finding.SourceSystem, primaryID, occurredAt.UTC().Format(time.RFC3339Nano), map[string]string{
		EventAttributeWorkflowKind: "finding_record",
		EventAttributeFindingID:    payload.Finding.FindingID,
	})
}

// NewFindingNoteAddedEvent builds the durable event envelope for one finding note.
func NewFindingNoteAddedEvent(payload FindingNoteAdded) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryFindingNoteAdded(payload), SchemaFindingNoteAdded, payload.Finding.TenantID, payload.Finding.SourceSystem, payload.Finding.FindingID+"|"+payload.NoteID, payload.CreatedAt, map[string]string{
		EventAttributeWorkflowKind: "finding_note",
		EventAttributeFindingID:    payload.Finding.FindingID,
	})
}

// NewFindingTicketLinkedEvent builds the durable event envelope for one finding ticket link.
func NewFindingTicketLinkedEvent(payload FindingTicketLinked) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryFindingTicketLinked(payload), SchemaFindingTicketLinked, payload.Finding.TenantID, payload.Finding.SourceSystem, payload.Finding.FindingID+"|"+payload.URL, payload.LinkedAt, map[string]string{
		EventAttributeWorkflowKind: "finding_ticket",
		EventAttributeFindingID:    payload.Finding.FindingID,
	})
}

// NewFindingStatusChangedEvent builds the durable event envelope for one finding status change.
func NewFindingStatusChangedEvent(payload FindingStatusChanged) (*cerebrov1.EventEnvelope, error) {
	return newEvent(registryFindingStatusChanged(payload), SchemaFindingStatusChanged, payload.Finding.TenantID, payload.Finding.SourceSystem, payload.Finding.FindingID+"|"+payload.Status+"|"+payload.UpdatedAt, payload.UpdatedAt, map[string]string{
		EventAttributeWorkflowKind: "finding_status",
		EventAttributeFindingID:    payload.Finding.FindingID,
		EventAttributeDecisionID:   payload.DecisionID,
		EventAttributeOutcomeID:    payload.OutcomeID,
		EventAttributeStatusSource: payload.Source,
	})
}

// DecodeDecisionRecorded decodes a decision event payload.
func DecodeDecisionRecorded(event *cerebrov1.EventEnvelope) (*DecisionRecorded, error) {
	payload := &DecisionRecorded{}
	if err := decodePayload(event, EventKindKnowledgeDecisionRecorded, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeActionRecorded decodes an action event payload.
func DecodeActionRecorded(event *cerebrov1.EventEnvelope) (*ActionRecorded, error) {
	payload := &ActionRecorded{}
	if err := decodePayload(event, EventKindKnowledgeActionRecorded, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeOutcomeRecorded decodes an outcome event payload.
func DecodeOutcomeRecorded(event *cerebrov1.EventEnvelope) (*OutcomeRecorded, error) {
	payload := &OutcomeRecorded{}
	if err := decodePayload(event, EventKindKnowledgeOutcomeRecorded, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeFindingRecorded decodes a finding recorded event payload.
func DecodeFindingRecorded(event *cerebrov1.EventEnvelope) (*FindingRecorded, error) {
	payload := &FindingRecorded{}
	if err := decodePayload(event, EventKindFindingRecorded, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeFindingNoteAdded decodes a finding note event payload.
func DecodeFindingNoteAdded(event *cerebrov1.EventEnvelope) (*FindingNoteAdded, error) {
	payload := &FindingNoteAdded{}
	if err := decodePayload(event, EventKindFindingNoteAdded, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeFindingTicketLinked decodes a finding ticket event payload.
func DecodeFindingTicketLinked(event *cerebrov1.EventEnvelope) (*FindingTicketLinked, error) {
	payload := &FindingTicketLinked{}
	if err := decodePayload(event, EventKindFindingTicketLinked, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// DecodeFindingStatusChanged decodes a finding status event payload.
func DecodeFindingStatusChanged(event *cerebrov1.EventEnvelope) (*FindingStatusChanged, error) {
	payload := &FindingStatusChanged{}
	if err := decodePayload(event, EventKindFindingStatusChanged, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// CanonicalWorkflowID returns the stable URN for a workflow entity.
func CanonicalWorkflowID(tenantID string, entityType string, providedID string, kind string, relatedIDs []string, at time.Time) string {
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

func newEvent(contract eventregistry.Event, schema string, tenantID string, sourceSystem string, primaryID string, observedAt string, attributes map[string]string) (*cerebrov1.EventEnvelope, error) {
	tenantID = strings.TrimSpace(tenantID)
	sourceSystem = strings.TrimSpace(sourceSystem)
	primaryID = strings.TrimSpace(primaryID)
	if contract == nil {
		return nil, fmt.Errorf("workflow event contract is required")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("workflow event tenant id is required")
	}
	if sourceSystem == "" {
		return nil, fmt.Errorf("workflow event source system is required")
	}
	if primaryID == "" {
		return nil, fmt.Errorf("workflow event primary id is required")
	}
	occurredAt, err := parseEventTime(observedAt)
	if err != nil {
		return nil, err
	}
	eventAttributes := map[string]string{
		EventAttributeTenantID:     tenantID,
		EventAttributeSourceSystem: sourceSystem,
	}
	for key, value := range attributes {
		if strings.TrimSpace(value) != "" {
			eventAttributes[key] = strings.TrimSpace(value)
		}
	}
	encoded, err := (eventregistry.Encoder{}).Encode(contract, eventregistry.EncodeOptions{
		EventID:    eventID(tenantID, contract.Subject(), primaryID),
		EmittedAt:  occurredAt,
		Attributes: eventAttributes,
	})
	if err != nil {
		return nil, fmt.Errorf("encode workflow event payload: %w", err)
	}
	return &cerebrov1.EventEnvelope{
		Id:         encoded.EventID,
		TenantId:   tenantID,
		SourceId:   sourceSystem,
		Kind:       contract.Subject(),
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  schema,
		Payload:    encoded.EnvelopeBytes,
		Attributes: encoded.Attributes,
	}, nil
}

func decodePayload(event *cerebrov1.EventEnvelope, kind string, payload any) error {
	if event == nil {
		return fmt.Errorf("workflow event is required")
	}
	if strings.TrimSpace(event.GetKind()) != kind {
		return fmt.Errorf("workflow event kind = %q, want %q", event.GetKind(), kind)
	}
	if len(event.GetPayload()) == 0 {
		return fmt.Errorf("workflow event %q payload is required", event.GetId())
	}
	return decodeWorkflowPayload(event, kind, payload)
}

func parseEventTime(value string) (time.Time, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Now().UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("workflow event observed_at is invalid: %w", err)
	}
	return parsed.UTC(), nil
}

func eventID(tenantID string, kind string, primaryID string) string {
	return fmt.Sprintf("urn:cerebro:%s:workflow_event:%s:%s", strings.TrimSpace(tenantID), slug(kind), shortHash(primaryID))
}

func slug(value string) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ":", "-", ".", "-")
	return replacer.Replace(strings.TrimSpace(value))
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
