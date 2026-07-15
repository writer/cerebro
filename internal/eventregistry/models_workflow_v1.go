package eventregistry

const (
	WorkflowV1KnowledgeDecisionRecorded = "workflow.v1.knowledge.decision_recorded"
	WorkflowV1KnowledgeActionRecorded   = "workflow.v1.knowledge.action_recorded"
	WorkflowV1KnowledgeOutcomeRecorded  = "workflow.v1.knowledge.outcome_recorded"
	WorkflowV1FindingRecorded           = "workflow.v1.finding.recorded"
	WorkflowV1FindingNoteAdded          = "workflow.v1.finding.note_added"
	WorkflowV1FindingTicketLinked       = "workflow.v1.finding.ticket_linked"
	WorkflowV1FindingExternalRefLinked  = "workflow.v1.finding.external_ref_linked"
	WorkflowV1FindingStatusChanged      = "workflow.v1.finding.status_changed"
	WorkflowV1FindingTombstoned         = "workflow.v1.finding.tombstoned"
	WorkflowV1CompliancePrefix          = "workflow.v1.compliance."
)

const (
	workflowV1DecisionFingerprint    = "ad17ef7945989b0d"
	workflowV1ActionFingerprint      = "d98357bbe915500a"
	workflowV1OutcomeFingerprint     = "88d8f65a315bfd27"
	workflowV1FindingRecordedFP      = "3dbf30c6af81b0c0"
	workflowV1FindingNoteAddedFP     = "cfb67fac77b66669"
	workflowV1FindingTicketLinkedFP  = "aba532fc1a85e76a"
	workflowV1FindingExternalRefFP   = "27b8e9fa76d210c4"
	workflowV1FindingStatusChangedFP = "8af95aec880d1c3a"
	workflowV1FindingTombstonedFP    = "bc92d8a4e5c7d5c3"
	workflowV1ComplianceAggregateFP  = "e5ce86187cf139f8"
)

type Event interface {
	Subject() string
	Version() int
	SchemaFingerprint() string
	EncodeAvro() ([]byte, error)
}

// ComplianceAggregateV1 carries one immutable compliance-domain revision or
// transition. Kind is constrained to workflow.v1.compliance.* and selects the
// subject while the payload schema remains shared across aggregate families.
type ComplianceAggregateV1 struct {
	Kind             string `json:"kind"`
	TenantID         string `json:"tenant_id"`
	AggregateType    string `json:"aggregate_type"`
	AggregateID      string `json:"aggregate_id"`
	RevisionID       string `json:"revision_id,omitempty"`
	AggregateVersion int64  `json:"aggregate_version"`
	Operation        string `json:"operation"`
	ContentDigest    string `json:"content_digest,omitempty"`
	PayloadJSON      string `json:"payload_json,omitempty"`
	ActorID          string `json:"actor_id,omitempty"`
	RecordedAt       string `json:"recorded_at"`
}

func (e ComplianceAggregateV1) Subject() string         { return e.Kind }
func (ComplianceAggregateV1) Version() int              { return 1 }
func (ComplianceAggregateV1) SchemaFingerprint() string { return workflowV1ComplianceAggregateFP }
func (e ComplianceAggregateV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	w.string(e.TenantID)
	w.string(e.AggregateType)
	w.string(e.AggregateID)
	w.string(e.RevisionID)
	w.long(e.AggregateVersion)
	w.string(e.Operation)
	w.string(e.ContentDigest)
	w.string(e.PayloadJSON)
	w.string(e.ActorID)
	w.string(e.RecordedAt)
	return w.bytes()
}

type DecisionRecordedV1 struct {
	TenantID      string         `json:"tenant_id"`
	DecisionID    string         `json:"decision_id"`
	DecisionType  string         `json:"decision_type"`
	Status        string         `json:"status"`
	MadeBy        *string        `json:"made_by,omitempty"`
	Rationale     *string        `json:"rationale,omitempty"`
	TargetIDs     []string       `json:"target_ids"`
	EvidenceIDs   []string       `json:"evidence_ids,omitempty"`
	ActionIDs     []string       `json:"action_ids,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID *string        `json:"source_event_id,omitempty"`
	ObservedAt    string         `json:"observed_at"`
	ValidFrom     string         `json:"valid_from"`
	ValidTo       *string        `json:"valid_to,omitempty"`
	Confidence    *float64       `json:"confidence,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

func (DecisionRecordedV1) Subject() string           { return WorkflowV1KnowledgeDecisionRecorded }
func (DecisionRecordedV1) Version() int              { return 1 }
func (DecisionRecordedV1) SchemaFingerprint() string { return workflowV1DecisionFingerprint }
func (e DecisionRecordedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	w.string(e.TenantID)
	w.string(e.DecisionID)
	w.string(e.DecisionType)
	w.string(e.Status)
	w.nullableString(e.MadeBy)
	w.nullableString(e.Rationale)
	w.stringArray(e.TargetIDs)
	w.stringArray(e.EvidenceIDs)
	w.stringArray(e.ActionIDs)
	w.string(e.SourceSystem)
	w.nullableString(e.SourceEventID)
	w.string(e.ObservedAt)
	w.string(e.ValidFrom)
	w.nullableString(e.ValidTo)
	w.nullableDouble(e.Confidence)
	w.metadataMap(e.Metadata)
	return w.bytes()
}

type ActionRecordedV1 struct {
	TenantID         string         `json:"tenant_id"`
	ActionID         string         `json:"action_id"`
	ActionType       string         `json:"action_type"`
	Status           string         `json:"status"`
	RecommendationID *string        `json:"recommendation_id,omitempty"`
	InsightType      *string        `json:"insight_type,omitempty"`
	Title            string         `json:"title"`
	Summary          *string        `json:"summary,omitempty"`
	DecisionID       *string        `json:"decision_id,omitempty"`
	TargetIDs        []string       `json:"target_ids"`
	SourceSystem     string         `json:"source_system"`
	SourceEventID    *string        `json:"source_event_id,omitempty"`
	ObservedAt       string         `json:"observed_at"`
	ValidFrom        string         `json:"valid_from"`
	ValidTo          *string        `json:"valid_to,omitempty"`
	Confidence       *float64       `json:"confidence,omitempty"`
	AutoGenerated    bool           `json:"auto_generated"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

func (ActionRecordedV1) Subject() string           { return WorkflowV1KnowledgeActionRecorded }
func (ActionRecordedV1) Version() int              { return 1 }
func (ActionRecordedV1) SchemaFingerprint() string { return workflowV1ActionFingerprint }
func (e ActionRecordedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	w.string(e.TenantID)
	w.string(e.ActionID)
	w.string(e.ActionType)
	w.string(e.Status)
	w.nullableString(e.RecommendationID)
	w.nullableString(e.InsightType)
	w.string(e.Title)
	w.nullableString(e.Summary)
	w.nullableString(e.DecisionID)
	w.stringArray(e.TargetIDs)
	w.string(e.SourceSystem)
	w.nullableString(e.SourceEventID)
	w.string(e.ObservedAt)
	w.string(e.ValidFrom)
	w.nullableString(e.ValidTo)
	w.nullableDouble(e.Confidence)
	w.boolean(e.AutoGenerated)
	w.metadataMap(e.Metadata)
	return w.bytes()
}

type OutcomeRecordedV1 struct {
	TenantID      string         `json:"tenant_id"`
	OutcomeID     string         `json:"outcome_id"`
	DecisionID    string         `json:"decision_id"`
	OutcomeType   string         `json:"outcome_type"`
	Verdict       string         `json:"verdict"`
	ImpactScore   *float64       `json:"impact_score,omitempty"`
	TargetIDs     []string       `json:"target_ids,omitempty"`
	SourceSystem  string         `json:"source_system"`
	SourceEventID *string        `json:"source_event_id,omitempty"`
	ObservedAt    string         `json:"observed_at"`
	ValidFrom     string         `json:"valid_from"`
	ValidTo       *string        `json:"valid_to,omitempty"`
	Confidence    *float64       `json:"confidence,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

func (OutcomeRecordedV1) Subject() string           { return WorkflowV1KnowledgeOutcomeRecorded }
func (OutcomeRecordedV1) Version() int              { return 1 }
func (OutcomeRecordedV1) SchemaFingerprint() string { return workflowV1OutcomeFingerprint }
func (e OutcomeRecordedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	w.string(e.TenantID)
	w.string(e.OutcomeID)
	w.string(e.DecisionID)
	w.string(e.OutcomeType)
	w.string(e.Verdict)
	w.nullableDouble(e.ImpactScore)
	w.stringArray(e.TargetIDs)
	w.string(e.SourceSystem)
	w.nullableString(e.SourceEventID)
	w.string(e.ObservedAt)
	w.string(e.ValidFrom)
	w.nullableString(e.ValidTo)
	w.nullableDouble(e.Confidence)
	w.metadataMap(e.Metadata)
	return w.bytes()
}

type FindingControlRefSnapshot struct {
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
}

type FindingSnapshot struct {
	TenantID           string                      `json:"tenant_id"`
	SourceSystem       string                      `json:"source_system"`
	FindingID          string                      `json:"finding_id"`
	Fingerprint        *string                     `json:"fingerprint,omitempty"`
	Title              *string                     `json:"title,omitempty"`
	Summary            *string                     `json:"summary,omitempty"`
	RuleID             *string                     `json:"rule_id,omitempty"`
	Severity           *string                     `json:"severity,omitempty"`
	Status             *string                     `json:"status,omitempty"`
	RuntimeID          *string                     `json:"runtime_id,omitempty"`
	PolicyID           *string                     `json:"policy_id,omitempty"`
	CheckID            *string                     `json:"check_id,omitempty"`
	PrimaryResourceURN *string                     `json:"primary_resource_urn,omitempty"`
	ResourceURNs       []string                    `json:"resource_urns,omitempty"`
	EventIDs           []string                    `json:"event_ids,omitempty"`
	FirstObservedAt    *string                     `json:"first_observed_at,omitempty"`
	LastObservedAt     *string                     `json:"last_observed_at,omitempty"`
	ResourceCount      int                         `json:"resource_count,omitempty"`
	EventCount         int                         `json:"event_count,omitempty"`
	ControlRefs        []FindingControlRefSnapshot `json:"control_refs,omitempty"`
	RiskScore          int                         `json:"risk_score,omitempty"`
	EffectiveSeverity  *string                     `json:"effective_severity,omitempty"`
	LikelihoodScore    int                         `json:"likelihood_score,omitempty"`
	ImpactScore        int                         `json:"impact_score,omitempty"`
	ConfidenceScore    int                         `json:"confidence_score,omitempty"`
	LikelihoodLevel    *string                     `json:"likelihood_level,omitempty"`
	ImpactLevel        *string                     `json:"impact_level,omitempty"`
	RiskModelVersion   *string                     `json:"risk_model_version,omitempty"`
	RiskReasons        []string                    `json:"risk_reasons,omitempty"`
	Metadata           map[string]string           `json:"metadata,omitempty"`
}

func (f FindingSnapshot) encodeAvro(w *avroWriter) {
	w.string(f.TenantID)
	w.string(f.SourceSystem)
	w.string(f.FindingID)
	w.nullableString(f.Fingerprint)
	w.nullableString(f.Title)
	w.nullableString(f.Summary)
	w.nullableString(f.RuleID)
	w.nullableString(f.Severity)
	w.nullableString(f.Status)
	w.nullableString(f.RuntimeID)
	w.nullableString(f.PolicyID)
	w.nullableString(f.CheckID)
	w.nullableString(f.PrimaryResourceURN)
	w.stringArray(f.ResourceURNs)
	w.stringArray(f.EventIDs)
	w.nullableString(f.FirstObservedAt)
	w.nullableString(f.LastObservedAt)
	w.integer(f.ResourceCount)
	w.integer(f.EventCount)
	w.findingControlRefArray(f.ControlRefs)
	w.integer(f.RiskScore)
	w.nullableString(f.EffectiveSeverity)
	w.integer(f.LikelihoodScore)
	w.integer(f.ImpactScore)
	w.integer(f.ConfidenceScore)
	w.nullableString(f.LikelihoodLevel)
	w.nullableString(f.ImpactLevel)
	w.nullableString(f.RiskModelVersion)
	w.stringArray(f.RiskReasons)
	w.stringMap(f.Metadata)
}

type FindingRecordedV1 struct {
	Finding    FindingSnapshot `json:"finding"`
	RecordedAt string          `json:"recorded_at"`
}

func (FindingRecordedV1) Subject() string           { return WorkflowV1FindingRecorded }
func (FindingRecordedV1) Version() int              { return 1 }
func (FindingRecordedV1) SchemaFingerprint() string { return workflowV1FindingRecordedFP }
func (e FindingRecordedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	e.Finding.encodeAvro(w)
	w.string(e.RecordedAt)
	return w.bytes()
}

type FindingNoteAddedV1 struct {
	Finding   FindingSnapshot `json:"finding"`
	NoteID    string          `json:"note_id"`
	Body      string          `json:"body"`
	CreatedAt string          `json:"created_at"`
}

func (FindingNoteAddedV1) Subject() string           { return WorkflowV1FindingNoteAdded }
func (FindingNoteAddedV1) Version() int              { return 1 }
func (FindingNoteAddedV1) SchemaFingerprint() string { return workflowV1FindingNoteAddedFP }
func (e FindingNoteAddedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	e.Finding.encodeAvro(w)
	w.string(e.NoteID)
	w.string(e.Body)
	w.string(e.CreatedAt)
	return w.bytes()
}

type FindingTicketLinkedV1 struct {
	Finding    FindingSnapshot `json:"finding"`
	URL        string          `json:"url"`
	Name       *string         `json:"name,omitempty"`
	ExternalID *string         `json:"external_id,omitempty"`
	LinkedAt   string          `json:"linked_at"`
}

func (FindingTicketLinkedV1) Subject() string           { return WorkflowV1FindingTicketLinked }
func (FindingTicketLinkedV1) Version() int              { return 1 }
func (FindingTicketLinkedV1) SchemaFingerprint() string { return workflowV1FindingTicketLinkedFP }
func (e FindingTicketLinkedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	e.Finding.encodeAvro(w)
	w.string(e.URL)
	w.nullableString(e.Name)
	w.nullableString(e.ExternalID)
	w.string(e.LinkedAt)
	return w.bytes()
}

type FindingExternalRefLinkedV1 struct {
	Finding              FindingSnapshot `json:"finding"`
	System               string          `json:"system"`
	Kind                 string          `json:"kind"`
	ExternalID           string          `json:"external_id"`
	URL                  *string         `json:"url,omitempty"`
	ExternalStatus       *string         `json:"external_status,omitempty"`
	ExternalStatusReason *string         `json:"external_status_reason,omitempty"`
	LifecycleOwner       *string         `json:"lifecycle_owner,omitempty"`
	LinkedAt             string          `json:"linked_at"`
}

func (FindingExternalRefLinkedV1) Subject() string {
	return WorkflowV1FindingExternalRefLinked
}

func (FindingExternalRefLinkedV1) Version() int { return 1 }

func (FindingExternalRefLinkedV1) SchemaFingerprint() string {
	return workflowV1FindingExternalRefFP
}

func (e FindingExternalRefLinkedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	e.Finding.encodeAvro(w)
	w.string(e.System)
	w.string(e.Kind)
	w.string(e.ExternalID)
	w.nullableString(e.URL)
	w.nullableString(e.ExternalStatus)
	w.nullableString(e.ExternalStatusReason)
	w.nullableString(e.LifecycleOwner)
	w.string(e.LinkedAt)
	return w.bytes()
}

type FindingStatusChangedV1 struct {
	Finding     FindingSnapshot `json:"finding"`
	Status      string          `json:"status"`
	Reason      *string         `json:"reason,omitempty"`
	Source      *string         `json:"source,omitempty"`
	UpdatedAt   string          `json:"updated_at"`
	DecisionID  *string         `json:"decision_id,omitempty"`
	OutcomeID   *string         `json:"outcome_id,omitempty"`
	OutcomeType *string         `json:"outcome_type,omitempty"`
}

func (FindingStatusChangedV1) Subject() string           { return WorkflowV1FindingStatusChanged }
func (FindingStatusChangedV1) Version() int              { return 1 }
func (FindingStatusChangedV1) SchemaFingerprint() string { return workflowV1FindingStatusChangedFP }
func (e FindingStatusChangedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	e.Finding.encodeAvro(w)
	w.string(e.Status)
	w.nullableString(e.Reason)
	w.nullableString(e.Source)
	w.string(e.UpdatedAt)
	w.nullableString(e.DecisionID)
	w.nullableString(e.OutcomeID)
	w.nullableString(e.OutcomeType)
	return w.bytes()
}

type FindingTombstonedV1 struct {
	Finding      FindingSnapshot `json:"finding"`
	PriorStatus  string          `json:"prior_status"`
	Reason       string          `json:"reason"`
	Actor        string          `json:"actor"`
	RunID        string          `json:"run_id"`
	TombstonedAt string          `json:"tombstoned_at"`
}

func (FindingTombstonedV1) Subject() string           { return WorkflowV1FindingTombstoned }
func (FindingTombstonedV1) Version() int              { return 1 }
func (FindingTombstonedV1) SchemaFingerprint() string { return workflowV1FindingTombstonedFP }
func (e FindingTombstonedV1) EncodeAvro() ([]byte, error) {
	w := newAvroWriter()
	e.Finding.encodeAvro(w)
	w.string(e.PriorStatus)
	w.string(e.Reason)
	w.string(e.Actor)
	w.string(e.RunID)
	w.string(e.TombstonedAt)
	return w.bytes()
}
