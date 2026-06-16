package graphagent

import (
	"context"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

type ReasonResponse struct {
	TraceID            string                    `json:"trace_id,omitempty"`
	Question           string                    `json:"question"`
	TenantID           string                    `json:"tenant_id"`
	ScopeURN           string                    `json:"scope_urn,omitempty"`
	Model              string                    `json:"model"`
	Rationale          string                    `json:"rationale,omitempty"`
	Probe              *GraphProbe               `json:"probe,omitempty"`
	QueryPlan          *QueryPlanEvent           `json:"query_plan,omitempty"`
	Cypher             *CypherEvent              `json:"cypher,omitempty"`
	Recovery           []RecoveryEvent           `json:"recovery,omitempty"`
	Rows               []map[string]any          `json:"rows"`
	Graph              *ports.EntityNeighborhood `json:"graph,omitempty"`
	AnswerMarkdown     string                    `json:"answer_markdown,omitempty"`
	Citations          []Citation                `json:"citations"`
	CitationValidation *CitationValidation       `json:"citation_validation,omitempty"`
	UnsupportedQuery   *UnsupportedQuery         `json:"unsupported_query,omitempty"`
	Progress           []ProgressEvent           `json:"progress,omitempty"`
	Timings            StageTimings              `json:"timings,omitempty"`
	Provenance         ReasonProvenance          `json:"provenance"`
}

type ReasonProvenance struct {
	Surface        string   `json:"surface"`
	TraceID        string   `json:"trace_id,omitempty"`
	SourceURNs     []string `json:"source_urns,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	CitationStatus string   `json:"citation_status"`
	FallbackReason string   `json:"fallback_reason,omitempty"`
}

func (s *Service) Reason(ctx context.Context, request AskRequest) (*ReasonResponse, error) {
	response := &ReasonResponse{
		Question:  strings.TrimSpace(request.Question),
		TenantID:  strings.TrimSpace(request.TenantID),
		ScopeURN:  strings.TrimSpace(request.ScopeURN),
		Model:     normalizeModel(request.Model),
		Rows:      []map[string]any{},
		Citations: []Citation{},
		Provenance: ReasonProvenance{
			Surface:        "graph-reasoning",
			Scope:          reasonScope(request),
			CitationStatus: "not_applicable",
		},
	}
	err := s.Stream(ctx, request, func(event Event) error {
		response.observe(event)
		return nil
	})
	if response.Provenance.TraceID == "" && response.TraceID != "" {
		response.Provenance.TraceID = response.TraceID
	}
	if response.Provenance.CitationStatus == "not_applicable" && len(response.Rows) > 0 {
		response.Provenance.CitationStatus = "missing"
	}
	return response, err
}

func reasonScope(request AskRequest) string {
	if scope := strings.TrimSpace(request.ScopeURN); scope != "" {
		return scope
	}
	return strings.TrimSpace(request.TenantID)
}

func (r *ReasonResponse) observe(event Event) {
	if r == nil {
		return
	}
	switch data := event.Data.(type) {
	case ProgressEvent:
		r.Progress = append(r.Progress, data)
	case GraphProbeEvent:
		probe := data.Probe
		r.Probe = &probe
	case RationaleEvent:
		r.Rationale = data.Text
	case QueryPlanEvent:
		plan := data
		r.QueryPlan = &plan
	case CypherEvent:
		cypher := data
		r.Cypher = &cypher
	case RecoveryEvent:
		r.Recovery = append(r.Recovery, data)
	case RowsEvent:
		r.Rows = data.Rows
		r.Graph = data.Graph
		r.Provenance.SourceURNs = rowURNs(data.Rows)
		if len(data.Rows) > 0 {
			r.Provenance.CitationStatus = "pending"
		}
	case SummaryEvent:
		r.AnswerMarkdown = data.Markdown
		r.Citations = data.Citations
		r.CitationValidation = data.CitationValidation
		r.UnsupportedQuery = data.UnsupportedQuery
		r.Provenance.CitationStatus = citationStatus(data.CitationValidation, data.Citations, r.Rows)
		if data.UnsupportedQuery != nil {
			r.Provenance.FallbackReason = data.UnsupportedQuery.Code
		}
	case DoneEvent:
		r.TraceID = data.TraceID
		r.Timings = data.Timings
		r.Provenance.TraceID = data.TraceID
		if data.CypherRefused && r.Provenance.FallbackReason == "" {
			r.Provenance.FallbackReason = "cypher_refused"
		}
	}
}

func citationStatus(validation *CitationValidation, citations []Citation, rows []map[string]any) string {
	if validation != nil {
		if validation.OK {
			return "valid"
		}
		return "warning"
	}
	if len(rows) == 0 {
		return "not_applicable"
	}
	if len(citations) == 0 {
		return "missing"
	}
	return "unknown"
}

func rowURNs(rows []map[string]any) []string {
	set := map[string]bool{}
	for _, row := range rows {
		for _, value := range row {
			collectURNs(value, set)
		}
	}
	urns := make([]string, 0, len(set))
	for urn := range set {
		urns = append(urns, urn)
	}
	sort.Strings(urns)
	return urns
}

func collectURNs(value any, out map[string]bool) {
	switch typed := value.(type) {
	case string:
		for _, urn := range summaryURNPattern.FindAllString(typed, -1) {
			out[urn] = true
		}
	case []any:
		for _, item := range typed {
			collectURNs(item, out)
		}
	case map[string]any:
		for _, item := range typed {
			collectURNs(item, out)
		}
	}
}
