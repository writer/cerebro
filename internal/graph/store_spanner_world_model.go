package graph

import (
	"embed"
	"fmt"
	"strings"
	"sync"
	"time"
)

//go:embed schema/spanner_world_model.sql
var spannerWorldModelSchemaFS embed.FS

var (
	spannerWorldModelSchemaOnce       sync.Once
	spannerWorldModelSchemaStatements []string
	spannerWorldModelSchemaErr        error
)

// SpannerWorldModelSchemaStatements exposes the proposed world-model-native
// Spanner schema and property-graph projection used for migration planning.
func SpannerWorldModelSchemaStatements() ([]string, error) {
	spannerWorldModelSchemaOnce.Do(func() {
		raw, err := spannerWorldModelSchemaFS.ReadFile("schema/spanner_world_model.sql")
		if err != nil {
			spannerWorldModelSchemaErr = err
			return
		}
		for _, statement := range strings.Split(string(raw), ";") {
			statement = strings.TrimSpace(statement)
			if statement == "" {
				continue
			}
			spannerWorldModelSchemaStatements = append(spannerWorldModelSchemaStatements, statement)
		}
	})
	if spannerWorldModelSchemaErr != nil {
		return nil, spannerWorldModelSchemaErr
	}
	return append([]string(nil), spannerWorldModelSchemaStatements...), nil
}

type spannerWorldModelTemporalColumns struct {
	ObservedAt      time.Time
	ValidFrom       time.Time
	ValidTo         *time.Time
	RecordedAt      time.Time
	TransactionFrom time.Time
	TransactionTo   *time.Time
	SourceSystem    string
	SourceEventID   string
	Confidence      float64
}

type SpannerWorldModelEntityRecord struct {
	EntityID           string
	Kind               NodeKind
	Name               string
	TenantID           string
	Provider           string
	Account            string
	Region             string
	CanonicalRef       string
	Properties         map[string]any
	Tags               map[string]string
	Findings           []string
	Risk               RiskLevel
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeletedAt          *time.Time
	Version            int
	PreviousProperties map[string]any
	PropertyHistory    map[string][]PropertySnapshot
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelEntityRecordFromNode(node *Node) (SpannerWorldModelEntityRecord, error) {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return SpannerWorldModelEntityRecord{}, fmt.Errorf("entity node is required")
	}
	if strings.TrimSpace(string(node.Kind)) == "" {
		return SpannerWorldModelEntityRecord{}, fmt.Errorf("node kind is required")
	}
	if node.Kind == NodeKindClaim || node.Kind == NodeKindSource || node.Kind == NodeKindEvidence || node.Kind == NodeKindObservation {
		return SpannerWorldModelEntityRecord{}, fmt.Errorf("node kind %q is modeled by a specialized world-model table", node.Kind)
	}
	temporal := spannerWorldModelTemporalFromNode(node)
	return SpannerWorldModelEntityRecord{
		EntityID:                         strings.TrimSpace(node.ID),
		Kind:                             node.Kind,
		Name:                             node.Name,
		TenantID:                         node.TenantID,
		Provider:                         node.Provider,
		Account:                          node.Account,
		Region:                           node.Region,
		CanonicalRef:                     nodePropertyString(node, "canonical_ref"),
		Properties:                       cloneAnyMap(node.PropertyMap()),
		Tags:                             cloneStringMap(node.Tags),
		Findings:                         append([]string(nil), node.Findings...),
		Risk:                             node.Risk,
		CreatedAt:                        spannerWorldModelTimestamp(node.CreatedAt, temporal.ObservedAt),
		UpdatedAt:                        spannerWorldModelTimestamp(node.UpdatedAt, temporal.RecordedAt),
		DeletedAt:                        spannerWorldModelOptionalTimestamp(node.DeletedAt),
		Version:                          spannerWorldModelVersion(node.Version),
		PreviousProperties:               cloneAnyMap(node.PreviousProperties),
		PropertyHistory:                  clonePropertyHistoryMap(node.PropertyHistory),
		spannerWorldModelTemporalColumns: temporal,
	}, nil
}

func (r SpannerWorldModelEntityRecord) ToNode() *Node {
	properties := cloneAnyMap(r.Properties)
	if properties == nil {
		properties = make(map[string]any)
	}
	if r.CanonicalRef != "" {
		properties["canonical_ref"] = r.CanonicalRef
	}
	r.writeMetadata().ApplyTo(properties)
	return &Node{
		ID:                 r.EntityID,
		Kind:               r.Kind,
		Name:               r.Name,
		TenantID:           r.TenantID,
		Provider:           r.Provider,
		Account:            r.Account,
		Region:             r.Region,
		Properties:         properties,
		Tags:               cloneStringMap(r.Tags),
		Findings:           append([]string(nil), r.Findings...),
		Risk:               r.Risk,
		CreatedAt:          spannerWorldModelTimestamp(r.CreatedAt, r.ObservedAt),
		UpdatedAt:          spannerWorldModelTimestamp(r.UpdatedAt, r.RecordedAt),
		DeletedAt:          spannerWorldModelOptionalTimestamp(r.DeletedAt),
		Version:            spannerWorldModelVersion(r.Version),
		PreviousProperties: cloneAnyMap(r.PreviousProperties),
		PropertyHistory:    clonePropertyHistoryMap(r.PropertyHistory),
	}
}

type SpannerWorldModelSourceRecord struct {
	SourceID         string
	SourceType       string
	CanonicalName    string
	SourceURL        string
	TrustTier        string
	ReliabilityScore float64
	Properties       map[string]any
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
	Version          int
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelSourceRecordFromNode(node *Node) (SpannerWorldModelSourceRecord, error) {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return SpannerWorldModelSourceRecord{}, fmt.Errorf("source node is required")
	}
	if node.Kind != NodeKindSource {
		return SpannerWorldModelSourceRecord{}, fmt.Errorf("node kind %q is not a source", node.Kind)
	}
	temporal := spannerWorldModelTemporalFromNode(node)
	return SpannerWorldModelSourceRecord{
		SourceID:                         strings.TrimSpace(node.ID),
		SourceType:                       nodePropertyString(node, "source_type"),
		CanonicalName:                    firstNonEmpty(nodePropertyString(node, "canonical_name"), node.Name),
		SourceURL:                        nodePropertyString(node, "source_url"),
		TrustTier:                        firstNonEmpty(nodePropertyString(node, "trust_tier"), nodePropertyString(node, "source_trust_tier")),
		ReliabilityScore:                 firstNonZero(nodePropertyFloat(node, "reliability_score"), nodePropertyFloat(node, "source_reliability_score")),
		Properties:                       cloneAnyMap(node.PropertyMap()),
		CreatedAt:                        spannerWorldModelTimestamp(node.CreatedAt, temporal.ObservedAt),
		UpdatedAt:                        spannerWorldModelTimestamp(node.UpdatedAt, temporal.RecordedAt),
		DeletedAt:                        spannerWorldModelOptionalTimestamp(node.DeletedAt),
		Version:                          spannerWorldModelVersion(node.Version),
		spannerWorldModelTemporalColumns: temporal,
	}, nil
}

func (r SpannerWorldModelSourceRecord) ToNode() *Node {
	properties := cloneAnyMap(r.Properties)
	if properties == nil {
		properties = make(map[string]any)
	}
	if r.SourceType != "" {
		properties["source_type"] = r.SourceType
	}
	if r.CanonicalName != "" {
		properties["canonical_name"] = r.CanonicalName
	}
	if r.SourceURL != "" {
		properties["source_url"] = r.SourceURL
	}
	if r.TrustTier != "" {
		properties["trust_tier"] = r.TrustTier
	}
	if r.ReliabilityScore > 0 {
		properties["reliability_score"] = r.ReliabilityScore
	}
	r.writeMetadata().ApplyTo(properties)
	return &Node{
		ID:         r.SourceID,
		Kind:       NodeKindSource,
		Name:       firstNonEmpty(r.CanonicalName, r.SourceType, r.SourceID),
		Provider:   r.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
		CreatedAt:  spannerWorldModelTimestamp(r.CreatedAt, r.ObservedAt),
		UpdatedAt:  spannerWorldModelTimestamp(r.UpdatedAt, r.RecordedAt),
		DeletedAt:  spannerWorldModelOptionalTimestamp(r.DeletedAt),
		Version:    spannerWorldModelVersion(r.Version),
	}
}

type SpannerWorldModelClaimRecord struct {
	ClaimID     string
	ClaimType   string
	SubjectID   string
	Predicate   string
	ObjectID    string
	ObjectValue string
	Status      string
	Summary     string
	Metadata    map[string]any
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
	Version     int
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelClaimRecordFromNode(node *Node) (SpannerWorldModelClaimRecord, error) {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return SpannerWorldModelClaimRecord{}, fmt.Errorf("claim node is required")
	}
	if node.Kind != NodeKindClaim {
		return SpannerWorldModelClaimRecord{}, fmt.Errorf("node kind %q is not a claim", node.Kind)
	}
	temporal := spannerWorldModelTemporalFromNode(node)
	return SpannerWorldModelClaimRecord{
		ClaimID:                          strings.TrimSpace(node.ID),
		ClaimType:                        nodePropertyString(node, "claim_type"),
		SubjectID:                        nodePropertyString(node, "subject_id"),
		Predicate:                        nodePropertyString(node, "predicate"),
		ObjectID:                         nodePropertyString(node, "object_id"),
		ObjectValue:                      nodePropertyString(node, "object_value"),
		Status:                           nodePropertyString(node, "status"),
		Summary:                          firstNonEmpty(nodePropertyString(node, "summary"), node.Name),
		Metadata:                         cloneAnyMap(node.PropertyMap()),
		CreatedAt:                        spannerWorldModelTimestamp(node.CreatedAt, temporal.ObservedAt),
		UpdatedAt:                        spannerWorldModelTimestamp(node.UpdatedAt, temporal.RecordedAt),
		DeletedAt:                        spannerWorldModelOptionalTimestamp(node.DeletedAt),
		Version:                          spannerWorldModelVersion(node.Version),
		spannerWorldModelTemporalColumns: temporal,
	}, nil
}

func (r SpannerWorldModelClaimRecord) ToNode() *Node {
	properties := cloneAnyMap(r.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	if r.ClaimType != "" {
		properties["claim_type"] = r.ClaimType
	}
	properties["subject_id"] = r.SubjectID
	properties["predicate"] = r.Predicate
	if r.ObjectID != "" {
		properties["object_id"] = r.ObjectID
	}
	if r.ObjectValue != "" {
		properties["object_value"] = r.ObjectValue
	}
	if r.Status != "" {
		properties["status"] = r.Status
	}
	if r.Summary != "" {
		properties["summary"] = r.Summary
	}
	r.writeMetadata().ApplyTo(properties)
	return &Node{
		ID:         r.ClaimID,
		Kind:       NodeKindClaim,
		Name:       firstNonEmpty(r.Summary, r.Predicate, r.ClaimID),
		Provider:   r.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
		CreatedAt:  spannerWorldModelTimestamp(r.CreatedAt, r.ObservedAt),
		UpdatedAt:  spannerWorldModelTimestamp(r.UpdatedAt, r.RecordedAt),
		DeletedAt:  spannerWorldModelOptionalTimestamp(r.DeletedAt),
		Version:    spannerWorldModelVersion(r.Version),
	}
}

type SpannerWorldModelEvidenceRecord struct {
	EvidenceID   string
	EvidenceType string
	SubjectID    string
	Detail       string
	Metadata     map[string]any
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
	Version      int
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelEvidenceRecordFromNode(node *Node) (SpannerWorldModelEvidenceRecord, error) {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return SpannerWorldModelEvidenceRecord{}, fmt.Errorf("evidence node is required")
	}
	if node.Kind != NodeKindEvidence {
		return SpannerWorldModelEvidenceRecord{}, fmt.Errorf("node kind %q is not evidence", node.Kind)
	}
	temporal := spannerWorldModelTemporalFromNode(node)
	return SpannerWorldModelEvidenceRecord{
		EvidenceID:                       strings.TrimSpace(node.ID),
		EvidenceType:                     nodePropertyString(node, "evidence_type"),
		SubjectID:                        nodePropertyString(node, "subject_id"),
		Detail:                           firstNonEmpty(nodePropertyString(node, "detail"), node.Name),
		Metadata:                         cloneAnyMap(node.PropertyMap()),
		CreatedAt:                        spannerWorldModelTimestamp(node.CreatedAt, temporal.ObservedAt),
		UpdatedAt:                        spannerWorldModelTimestamp(node.UpdatedAt, temporal.RecordedAt),
		DeletedAt:                        spannerWorldModelOptionalTimestamp(node.DeletedAt),
		Version:                          spannerWorldModelVersion(node.Version),
		spannerWorldModelTemporalColumns: temporal,
	}, nil
}

func (r SpannerWorldModelEvidenceRecord) ToNode() *Node {
	properties := cloneAnyMap(r.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	if r.EvidenceType != "" {
		properties["evidence_type"] = r.EvidenceType
	}
	if r.SubjectID != "" {
		properties["subject_id"] = r.SubjectID
	}
	if r.Detail != "" {
		properties["detail"] = r.Detail
	}
	r.writeMetadata().ApplyTo(properties)
	return &Node{
		ID:         r.EvidenceID,
		Kind:       NodeKindEvidence,
		Name:       firstNonEmpty(r.EvidenceType, r.Detail, r.EvidenceID),
		Provider:   r.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
		CreatedAt:  spannerWorldModelTimestamp(r.CreatedAt, r.ObservedAt),
		UpdatedAt:  spannerWorldModelTimestamp(r.UpdatedAt, r.RecordedAt),
		DeletedAt:  spannerWorldModelOptionalTimestamp(r.DeletedAt),
		Version:    spannerWorldModelVersion(r.Version),
	}
}

type SpannerWorldModelObservationRecord struct {
	ObservationID   string
	ObservationType string
	SubjectID       string
	Detail          string
	Metadata        map[string]any
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time
	Version         int
	spannerWorldModelTemporalColumns
}

func SpannerWorldModelObservationRecordFromNode(node *Node) (SpannerWorldModelObservationRecord, error) {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return SpannerWorldModelObservationRecord{}, fmt.Errorf("observation node is required")
	}
	if node.Kind != NodeKindObservation {
		return SpannerWorldModelObservationRecord{}, fmt.Errorf("node kind %q is not an observation", node.Kind)
	}
	temporal := spannerWorldModelTemporalFromNode(node)
	return SpannerWorldModelObservationRecord{
		ObservationID:                    strings.TrimSpace(node.ID),
		ObservationType:                  nodePropertyString(node, "observation_type"),
		SubjectID:                        nodePropertyString(node, "subject_id"),
		Detail:                           firstNonEmpty(nodePropertyString(node, "detail"), node.Name),
		Metadata:                         cloneAnyMap(node.PropertyMap()),
		CreatedAt:                        spannerWorldModelTimestamp(node.CreatedAt, temporal.ObservedAt),
		UpdatedAt:                        spannerWorldModelTimestamp(node.UpdatedAt, temporal.RecordedAt),
		DeletedAt:                        spannerWorldModelOptionalTimestamp(node.DeletedAt),
		Version:                          spannerWorldModelVersion(node.Version),
		spannerWorldModelTemporalColumns: temporal,
	}, nil
}

func (r SpannerWorldModelObservationRecord) ToNode() *Node {
	properties := cloneAnyMap(r.Metadata)
	if properties == nil {
		properties = make(map[string]any)
	}
	if r.ObservationType != "" {
		properties["observation_type"] = r.ObservationType
	}
	if r.SubjectID != "" {
		properties["subject_id"] = r.SubjectID
	}
	if r.Detail != "" {
		properties["detail"] = r.Detail
	}
	r.writeMetadata().ApplyTo(properties)
	return &Node{
		ID:         r.ObservationID,
		Kind:       NodeKindObservation,
		Name:       firstNonEmpty(r.ObservationType, r.Detail, r.ObservationID),
		Provider:   r.SourceSystem,
		Properties: properties,
		Risk:       RiskNone,
		CreatedAt:  spannerWorldModelTimestamp(r.CreatedAt, r.ObservedAt),
		UpdatedAt:  spannerWorldModelTimestamp(r.UpdatedAt, r.RecordedAt),
		DeletedAt:  spannerWorldModelOptionalTimestamp(r.DeletedAt),
		Version:    spannerWorldModelVersion(r.Version),
	}
}

func (c spannerWorldModelTemporalColumns) writeMetadata() WriteMetadata {
	return NormalizeWriteMetadata(
		c.ObservedAt,
		c.ValidFrom,
		c.ValidTo,
		c.SourceSystem,
		c.SourceEventID,
		c.Confidence,
		WriteMetadataDefaults{
			Now:             c.RecordedAt,
			RecordedAt:      c.RecordedAt,
			TransactionFrom: c.TransactionFrom,
			TransactionTo:   c.TransactionTo,
			SourceSystem:    c.SourceSystem,
			SourceEventID:   c.SourceEventID,
		},
	)
}

func spannerWorldModelTemporalFromNode(node *Node) spannerWorldModelTemporalColumns {
	now := spannerWorldModelTimestamp(node.UpdatedAt, node.CreatedAt)
	if now.IsZero() {
		now = temporalNowUTC()
	}
	observedAt, ok := nodePropertyTime(node, "observed_at")
	if !ok || observedAt.IsZero() {
		observedAt = spannerWorldModelTimestamp(node.UpdatedAt, node.CreatedAt)
		if observedAt.IsZero() {
			observedAt = now
		}
	}
	validFrom, ok := nodePropertyTime(node, "valid_from")
	if !ok || validFrom.IsZero() {
		validFrom = observedAt
	}
	validTo, _ := nodePropertyTime(node, "valid_to")
	recordedAt, ok := nodePropertyTime(node, "recorded_at")
	if !ok || recordedAt.IsZero() {
		recordedAt = spannerWorldModelTimestamp(node.UpdatedAt, node.CreatedAt)
		if recordedAt.IsZero() {
			recordedAt = observedAt
		}
	}
	transactionFrom, ok := nodePropertyTime(node, "transaction_from")
	if !ok || transactionFrom.IsZero() {
		transactionFrom = recordedAt
	}
	transactionTo, _ := nodePropertyTime(node, "transaction_to")
	sourceSystem := firstNonEmpty(nodePropertyString(node, "source_system"), strings.TrimSpace(node.Provider), "unknown")
	sourceEventID := firstNonEmpty(nodePropertyString(node, "source_event_id"), fmt.Sprintf("graph:%s:%d", strings.TrimSpace(node.ID), recordedAt.UnixNano()))
	columns := spannerWorldModelTemporalColumns{
		ObservedAt:      observedAt.UTC(),
		ValidFrom:       validFrom.UTC(),
		RecordedAt:      recordedAt.UTC(),
		TransactionFrom: transactionFrom.UTC(),
		SourceSystem:    sourceSystem,
		SourceEventID:   sourceEventID,
		Confidence:      nodePropertyFloat(node, "confidence"),
	}
	if !validTo.IsZero() {
		columns.ValidTo = spannerWorldModelTimePtr(validTo.UTC())
	}
	if !transactionTo.IsZero() {
		columns.TransactionTo = spannerWorldModelTimePtr(transactionTo.UTC())
	}
	metadata := columns.writeMetadata()
	return spannerWorldModelTemporalColumns(metadata)
}

func spannerWorldModelTimestamp(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Time{}
}

func spannerWorldModelOptionalTimestamp(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func spannerWorldModelTimePtr(value time.Time) *time.Time {
	copy := value.UTC()
	return &copy
}

func spannerWorldModelVersion(version int) int {
	if version > 0 {
		return version
	}
	return 1
}

func firstNonZero(values ...float64) float64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}
