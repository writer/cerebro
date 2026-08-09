package graphfacts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultListLimit uint32 = 100
	maxListLimit     uint32 = 500
)

var (
	// ErrRuntimeUnavailable means the service has no claim-store capability.
	ErrRuntimeUnavailable = errors.New("graph facts runtime is unavailable")
	// ErrInvalidRequest means a selector, cursor, or limit is malformed.
	ErrInvalidRequest = errors.New("invalid graph facts request")
	// ErrFactNotFound means no claim matched an otherwise valid selector.
	ErrFactNotFound = errors.New("graph fact not found")
)

// Service provides read-only fact views over a ClaimStore.
type Service struct {
	store ports.ClaimStore
}

// ListRequest selects a page of facts. TenantID or RuntimeID is required.
// Filters are combined, not unioned. Compact and OmitAttributes only change
// response shape; IncludeEvidence adds evidence parsed from claim attributes.
type ListRequest struct {
	TenantID        string
	RuntimeID       string
	FactID          string
	SubjectURN      string
	Predicate       string
	ObjectURN       string
	ObjectValue     string
	ClaimType       string
	Status          string
	SourceEventID   string
	Limit           uint32
	Cursor          string
	OmitAttributes  bool
	IncludeEvidence bool
	EvidenceLimit   uint32
	Compact         bool
}

// ExplainRequest identifies exactly one fact by FactID or by a complete edge
// selector consisting of subject, predicate, and object URN or scalar value.
type ExplainRequest struct {
	TenantID    string
	RuntimeID   string
	FactID      string
	SubjectURN  string
	Predicate   string
	ObjectURN   string
	ObjectValue string
}

// TraceRequest selects an anchor fact and controls the bounded set of sibling
// facts returned for the same subject. Trace is not a recursive graph walk.
type TraceRequest struct {
	TenantID        string
	RuntimeID       string
	FactID          string
	SubjectURN      string
	Predicate       string
	ObjectURN       string
	ObjectValue     string
	Limit           uint32
	OmitAttributes  bool
	IncludeEvidence bool
	EvidenceLimit   uint32
}

// ListResponse contains one stable page of facts and an opaque continuation
// cursor. NextCursor is set only when HasMore is true.
type ListResponse struct {
	Facts      []Fact `json:"facts"`
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// ExplainResponse combines the stored fact with views derived from it. Edge is
// present only for object-URN facts; scalar facts still include freshness,
// evidence, and a textual explanation.
type ExplainResponse struct {
	Fact        Fact       `json:"fact"`
	Edge        *FactEdge  `json:"edge,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Freshness   Freshness  `json:"freshness"`
	Explanation string     `json:"explanation"`
}

// TraceResponse contains the explained anchor and other facts that share its
// subject. RelatedMore reflects truncation of that sibling set.
type TraceResponse struct {
	Anchor       ExplainResponse `json:"anchor"`
	RelatedFacts []Fact          `json:"related_facts,omitempty"`
	Steps        []TraceStep     `json:"steps"`
	RelatedMore  bool            `json:"related_more"`
}

// TraceStep is a presentation-ready statement in the explanation sequence.
type TraceStep struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	FactID      string `json:"fact_id,omitempty"`
}

// Fact is the API representation of a stored claim. ObjectURN and ObjectValue
// are distinct because a relationship and a scalar assertion have different
// graph semantics even when their serialized text happens to match.
type Fact struct {
	ID            string            `json:"id"`
	RuntimeID     string            `json:"runtime_id,omitempty"`
	TenantID      string            `json:"tenant_id,omitempty"`
	SubjectURN    string            `json:"subject_urn"`
	Predicate     string            `json:"predicate"`
	ObjectURN     string            `json:"object_urn,omitempty"`
	ObjectValue   string            `json:"object_value,omitempty"`
	ClaimType     string            `json:"claim_type"`
	Status        string            `json:"status"`
	SourceEventID string            `json:"source_event_id,omitempty"`
	ObservedAt    string            `json:"observed_at,omitempty"`
	ValidFrom     string            `json:"valid_from,omitempty"`
	ValidTo       string            `json:"valid_to,omitempty"`
	Confidence    string            `json:"confidence,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	Evidence      []Evidence        `json:"evidence,omitempty"`
}

// FactEdge is the relationship view derived from a fact with an ObjectURN.
type FactEdge struct {
	FromURN  string            `json:"from_urn"`
	Relation string            `json:"relation"`
	ToURN    string            `json:"to_urn"`
	Status   string            `json:"status"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Evidence identifies a source record cited by a fact.
type Evidence struct {
	URN    string `json:"urn"`
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
}

// Freshness summarizes the observation and validity window of a fact.
type Freshness struct {
	ObservedAt string `json:"observed_at,omitempty"`
	ValidFrom  string `json:"valid_from,omitempty"`
	ValidTo    string `json:"valid_to,omitempty"`
	Status     string `json:"status"`
}

// New constructs a read-only graph-facts service over store. A nil store is
// accepted at construction time and reported as ErrRuntimeUnavailable on use.
func New(store ports.ClaimStore) *Service {
	return &Service{store: store}
}

// List returns a stable, bounded page of facts matching request. It does not
// guarantee a snapshot across pages; records created between calls can appear
// according to the ClaimStore ordering contract.
func (s *Service) List(ctx context.Context, request ListRequest) (ListResponse, error) {
	if s == nil || s.store == nil {
		return ListResponse{}, ErrRuntimeUnavailable
	}
	if strings.TrimSpace(request.TenantID) == "" && strings.TrimSpace(request.RuntimeID) == "" {
		return ListResponse{}, fmt.Errorf("%w: tenant_id or runtime_id is required", ErrInvalidRequest)
	}
	limit := normalizeLimit(request.Limit)
	cursor, err := decodeCursor(request.Cursor)
	if err != nil {
		return ListResponse{}, err
	}
	// Ask the store for one extra row. This proves whether another page exists
	// without issuing a count query against a potentially changing claim set.
	records, err := s.store.ListClaims(ctx, ports.ListClaimsRequest{
		RuntimeID:       strings.TrimSpace(request.RuntimeID),
		TenantID:        strings.TrimSpace(request.TenantID),
		ClaimID:         strings.TrimSpace(request.FactID),
		SubjectURN:      strings.TrimSpace(request.SubjectURN),
		Predicate:       strings.TrimSpace(request.Predicate),
		ObjectURN:       strings.TrimSpace(request.ObjectURN),
		ObjectValue:     strings.TrimSpace(request.ObjectValue),
		ClaimType:       strings.TrimSpace(request.ClaimType),
		Status:          strings.TrimSpace(request.Status),
		SourceEventID:   strings.TrimSpace(request.SourceEventID),
		Limit:           limit + 1,
		AfterObservedAt: cursor.ObservedAt,
		AfterUpdatedAt:  cursor.UpdatedAt,
		AfterID:         cursor.ID,
	})
	if err != nil {
		return ListResponse{}, err
	}
	hasMore := len(records) > int(limit)
	if hasMore {
		records = records[:limit]
	}
	facts := make([]Fact, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		fact := factFromRecord(record)
		shapeFact(&fact, request)
		facts = append(facts, fact)
	}
	nextCursor := ""
	if hasMore && len(records) != 0 {
		// The cursor captures the final store record rather than the shaped API
		// fact because UpdatedAt is intentionally not exposed in the response.
		nextCursor = encodeCursor(records[len(records)-1])
	}
	return ListResponse{Facts: facts, NextCursor: nextCursor, HasMore: hasMore}, nil
}

// Explain resolves one fact and derives its edge, evidence, freshness, and
// human-readable statement. If a broad selector matches multiple records, the
// first record in stable store order is returned.
func (s *Service) Explain(ctx context.Context, request ExplainRequest) (ExplainResponse, error) {
	if strings.TrimSpace(request.FactID) == "" &&
		(strings.TrimSpace(request.SubjectURN) == "" || strings.TrimSpace(request.Predicate) == "" ||
			(strings.TrimSpace(request.ObjectURN) == "" && strings.TrimSpace(request.ObjectValue) == "")) {
		return ExplainResponse{}, fmt.Errorf("%w: fact_id or edge selector is required", ErrInvalidRequest)
	}
	response, err := s.List(ctx, ListRequest{
		TenantID:    request.TenantID,
		RuntimeID:   request.RuntimeID,
		FactID:      request.FactID,
		SubjectURN:  request.SubjectURN,
		Predicate:   request.Predicate,
		ObjectURN:   request.ObjectURN,
		ObjectValue: request.ObjectValue,
		Limit:       2,
	})
	if err != nil {
		return ExplainResponse{}, err
	}
	if len(response.Facts) == 0 {
		return ExplainResponse{}, ErrFactNotFound
	}
	fact := response.Facts[0]
	return ExplainResponse{
		Fact:        fact,
		Edge:        edgeForFact(fact),
		Evidence:    evidenceForFact(fact),
		Freshness:   freshnessForFact(fact),
		Explanation: explanationForFact(fact),
	}, nil
}

// Trace explains one anchor and returns other facts for the same subject. It is
// intended to show local provenance context, not to replace graph path queries.
func (s *Service) Trace(ctx context.Context, request TraceRequest) (TraceResponse, error) {
	anchor, err := s.Explain(ctx, ExplainRequest{
		TenantID:    request.TenantID,
		RuntimeID:   request.RuntimeID,
		FactID:      request.FactID,
		SubjectURN:  request.SubjectURN,
		Predicate:   request.Predicate,
		ObjectURN:   request.ObjectURN,
		ObjectValue: request.ObjectValue,
	})
	if err != nil {
		return TraceResponse{}, err
	}
	if request.OmitAttributes {
		anchor.Fact.Attributes = nil
	}
	list, err := s.List(ctx, ListRequest{
		TenantID:        request.TenantID,
		RuntimeID:       firstNonEmpty(request.RuntimeID, anchor.Fact.RuntimeID),
		SubjectURN:      anchor.Fact.SubjectURN,
		Limit:           firstNonZero(request.Limit, 10),
		OmitAttributes:  request.OmitAttributes,
		IncludeEvidence: request.IncludeEvidence,
		EvidenceLimit:   request.EvidenceLimit,
	})
	if err != nil {
		return TraceResponse{}, err
	}
	related := make([]Fact, 0, len(list.Facts))
	for _, fact := range list.Facts {
		if fact.ID != anchor.Fact.ID {
			related = append(related, fact)
		}
	}
	steps := []TraceStep{{
		Kind:        "anchor_fact",
		Description: explanationForFact(anchor.Fact),
		FactID:      anchor.Fact.ID,
	}}
	if anchor.Edge != nil {
		steps = append(steps, TraceStep{
			Kind:        "projected_edge",
			Description: fmt.Sprintf("The relation fact projects an edge from %s to %s.", anchor.Edge.FromURN, anchor.Edge.ToURN),
			FactID:      anchor.Fact.ID,
		})
	}
	if len(anchor.Evidence) != 0 {
		steps = append(steps, TraceStep{
			Kind:        "evidence",
			Description: fmt.Sprintf("%d evidence pointer(s) support the anchor fact.", len(anchor.Evidence)),
			FactID:      anchor.Fact.ID,
		})
	}
	if len(related) != 0 {
		steps = append(steps, TraceStep{
			Kind:        "related_facts",
			Description: fmt.Sprintf("%d additional fact(s) share the same subject.", len(related)),
		})
	}
	return TraceResponse{
		Anchor:       anchor,
		RelatedFacts: related,
		Steps:        steps,
		RelatedMore:  list.HasMore,
	}, nil
}

func normalizeLimit(limit uint32) uint32 {
	switch {
	case limit == 0:
		return defaultListLimit
	case limit > maxListLimit:
		return maxListLimit
	default:
		return limit
	}
}

func factFromRecord(record *ports.ClaimRecord) Fact {
	attributes := trimAttributes(record.Attributes)
	return Fact{
		ID:            strings.TrimSpace(record.ID),
		RuntimeID:     strings.TrimSpace(record.RuntimeID),
		TenantID:      strings.TrimSpace(record.TenantID),
		SubjectURN:    strings.TrimSpace(record.SubjectURN),
		Predicate:     strings.TrimSpace(record.Predicate),
		ObjectURN:     strings.TrimSpace(record.ObjectURN),
		ObjectValue:   strings.TrimSpace(record.ObjectValue),
		ClaimType:     strings.TrimSpace(record.ClaimType),
		Status:        strings.TrimSpace(record.Status),
		SourceEventID: strings.TrimSpace(record.SourceEventID),
		ObservedAt:    formatTime(record.ObservedAt),
		ValidFrom:     formatTime(record.ValidFrom),
		ValidTo:       formatTime(record.ValidTo),
		Confidence:    firstNonEmpty(attributes["confidence"], attributes["confidence_score"]),
		Attributes:    publicFactAttributes(attributes),
	}
}

func shapeFact(fact *Fact, request ListRequest) {
	if fact == nil {
		return
	}
	if request.IncludeEvidence {
		fact.Evidence = limitEvidence(evidenceForFact(*fact), request.EvidenceLimit)
	}
	if request.Compact {
		fact.RuntimeID = ""
		fact.TenantID = ""
		fact.SourceEventID = ""
		fact.ObservedAt = ""
		fact.ValidFrom = ""
		fact.ValidTo = ""
	}
	if request.Compact || request.OmitAttributes {
		fact.Attributes = nil
	}
}

func edgeForFact(fact Fact) *FactEdge {
	if strings.TrimSpace(fact.ClaimType) != "relation" || strings.TrimSpace(fact.ObjectURN) == "" {
		return nil
	}
	return &FactEdge{
		FromURN:  fact.SubjectURN,
		Relation: fact.Predicate,
		ToURN:    fact.ObjectURN,
		Status:   fact.Status,
		Metadata: map[string]string{
			"fact_id":    fact.ID,
			"claim_type": fact.ClaimType,
		},
	}
}

func evidenceForFact(fact Fact) []Evidence {
	values := map[string]Evidence{}
	add := func(kind string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		values[kind+":"+value] = Evidence{URN: value, Kind: kind, Source: fact.SourceEventID}
	}
	add("event", fact.SourceEventID)
	for _, key := range []string{"evidence_urn", "evidence_id", "finding_evidence_id", "source_evidence_urn"} {
		for _, value := range splitEvidenceValues(fact.Attributes[key]) {
			add(key, value)
		}
	}
	out := make([]Evidence, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			return out[i].URN < out[j].URN
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func limitEvidence(values []Evidence, limit uint32) []Evidence {
	if len(values) == 0 {
		return nil
	}
	if limit == 0 {
		limit = 5
	} else if limit > 25 {
		limit = 25
	}
	if len(values) > int(limit) {
		values = values[:limit]
	}
	return values
}

func freshnessForFact(fact Fact) Freshness {
	return Freshness{
		ObservedAt: fact.ObservedAt,
		ValidFrom:  fact.ValidFrom,
		ValidTo:    fact.ValidTo,
		Status:     fact.Status,
	}
}

func explanationForFact(fact Fact) string {
	target := firstNonEmpty(fact.ObjectURN, fact.ObjectValue, "(empty object)")
	return fmt.Sprintf("Fact %s asserts %s %s %s with status %s.", fact.ID, fact.SubjectURN, fact.Predicate, target, fact.Status)
}

func trimAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for key, value := range attributes {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func publicFactAttributes(attributes map[string]string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	allowed := map[string]struct{}{
		"confidence":          {},
		"confidence_score":    {},
		"evidence_id":         {},
		"evidence_urn":        {},
		"finding_evidence_id": {},
		"observed_at":         {},
		"source_evidence_urn": {},
		"source_event_id":     {},
		"source_runtime_id":   {},
		"source_system":       {},
	}
	out := make(map[string]string, len(allowed))
	for key, value := range attributes {
		if _, ok := allowed[key]; ok {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitEvidenceValues(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstNonZero(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

type pageCursor struct {
	ID         string    `json:"id"`
	ObservedAt time.Time `json:"observed_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func encodeCursor(record *ports.ClaimRecord) string {
	if record == nil || strings.TrimSpace(record.ID) == "" || record.UpdatedAt.IsZero() {
		return ""
	}
	payload, err := json.Marshal(pageCursor{
		ID:         strings.TrimSpace(record.ID),
		ObservedAt: record.ObservedAt.UTC(),
		UpdatedAt:  record.UpdatedAt.UTC(),
	})
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCursor(value string) (pageCursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return pageCursor{}, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return pageCursor{}, fmt.Errorf("%w: invalid cursor", ErrInvalidRequest)
	}
	var cursor pageCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return pageCursor{}, fmt.Errorf("%w: invalid cursor", ErrInvalidRequest)
	}
	if strings.TrimSpace(cursor.ID) == "" || cursor.UpdatedAt.IsZero() {
		return pageCursor{}, fmt.Errorf("%w: invalid cursor", ErrInvalidRequest)
	}
	cursor.ID = strings.TrimSpace(cursor.ID)
	cursor.ObservedAt = cursor.ObservedAt.UTC()
	cursor.UpdatedAt = cursor.UpdatedAt.UTC()
	return cursor, nil
}
