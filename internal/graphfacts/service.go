package graphfacts

import (
	"context"
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
	ErrRuntimeUnavailable = errors.New("graph facts runtime is unavailable")
	ErrInvalidRequest     = errors.New("invalid graph facts request")
	ErrFactNotFound       = errors.New("graph fact not found")
)

type Service struct {
	store ports.ClaimStore
}

type ListRequest struct {
	TenantID      string
	RuntimeID     string
	FactID        string
	SubjectURN    string
	Predicate     string
	ObjectURN     string
	ObjectValue   string
	ClaimType     string
	Status        string
	SourceEventID string
	Limit         uint32
}

type ExplainRequest struct {
	TenantID    string
	RuntimeID   string
	FactID      string
	SubjectURN  string
	Predicate   string
	ObjectURN   string
	ObjectValue string
}

type ListResponse struct {
	Facts []Fact `json:"facts"`
}

type ExplainResponse struct {
	Fact        Fact       `json:"fact"`
	Edge        *FactEdge  `json:"edge,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Freshness   Freshness  `json:"freshness"`
	Explanation string     `json:"explanation"`
}

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
}

type FactEdge struct {
	FromURN  string            `json:"from_urn"`
	Relation string            `json:"relation"`
	ToURN    string            `json:"to_urn"`
	Status   string            `json:"status"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Evidence struct {
	URN    string `json:"urn"`
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
}

type Freshness struct {
	ObservedAt string `json:"observed_at,omitempty"`
	ValidFrom  string `json:"valid_from,omitempty"`
	ValidTo    string `json:"valid_to,omitempty"`
	Status     string `json:"status"`
}

func New(store ports.ClaimStore) *Service {
	return &Service{store: store}
}

func (s *Service) List(ctx context.Context, request ListRequest) (ListResponse, error) {
	if s == nil || s.store == nil {
		return ListResponse{}, ErrRuntimeUnavailable
	}
	if strings.TrimSpace(request.TenantID) == "" && strings.TrimSpace(request.RuntimeID) == "" {
		return ListResponse{}, fmt.Errorf("%w: tenant_id or runtime_id is required", ErrInvalidRequest)
	}
	records, err := s.store.ListClaims(ctx, ports.ListClaimsRequest{
		RuntimeID:     strings.TrimSpace(request.RuntimeID),
		TenantID:      strings.TrimSpace(request.TenantID),
		ClaimID:       strings.TrimSpace(request.FactID),
		SubjectURN:    strings.TrimSpace(request.SubjectURN),
		Predicate:     strings.TrimSpace(request.Predicate),
		ObjectURN:     strings.TrimSpace(request.ObjectURN),
		ObjectValue:   strings.TrimSpace(request.ObjectValue),
		ClaimType:     strings.TrimSpace(request.ClaimType),
		Status:        strings.TrimSpace(request.Status),
		SourceEventID: strings.TrimSpace(request.SourceEventID),
		Limit:         normalizeLimit(request.Limit),
	})
	if err != nil {
		return ListResponse{}, err
	}
	facts := make([]Fact, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		facts = append(facts, factFromRecord(record))
	}
	return ListResponse{Facts: facts}, nil
}

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

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
