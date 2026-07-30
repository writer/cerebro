package graphagent

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/writer/cerebro/internal/ports"
)

const (
	EventProgress   = "progress"
	EventGraphProbe = "graph_probe"
	EventRationale  = "rationale"
	EventQueryPlan  = "query_plan"
	EventCypher     = "cypher"
	EventRecovery   = "recovery"
	EventRows       = "rows"
	EventSummary    = "summary"
	EventDone       = "done"
	EventError      = "error"
)

type Event struct {
	Name string
	Data any
}

type ValidatorResult struct {
	OK       bool     `json:"ok"`
	Code     string   `json:"code,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

type ProgressEvent struct {
	Stage     string `json:"stage"`
	Message   string `json:"message"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

type GraphProbeEvent struct {
	Probe GraphProbe `json:"probe"`
}

type RationaleEvent struct {
	Text string `json:"text"`
}

type QueryPlanEvent struct {
	Plan          AskQueryPlan           `json:"plan"`
	Diagnostics   []ConversionDiagnostic `json:"diagnostics,omitempty"`
	Source        string                 `json:"source"`
	Deterministic bool                   `json:"deterministic"`
	Corrected     bool                   `json:"corrected"`
}

type CypherEvent struct {
	Cypher    string          `json:"cypher"`
	Validator ValidatorResult `json:"validator"`
}

type RecoveryEvent struct {
	Attempt    int    `json:"attempt"`
	Reason     string `json:"reason"`
	Action     string `json:"action"`
	Intent     string `json:"intent,omitempty"`
	RowsBefore int    `json:"rows_before"`
	RowsAfter  int    `json:"rows_after,omitempty"`
}

type RowsEvent struct {
	Rows   []map[string]any          `json:"rows"`
	Graph  *ports.EntityNeighborhood `json:"graph"`
	ExecMS int64                     `json:"exec_ms"`
}

type Citation struct {
	URN  string `json:"urn"`
	Span [2]int `json:"span"`
}

type CitationValidation struct {
	OK                 bool     `json:"ok"`
	Warnings           []string `json:"warnings,omitempty"`
	RowURNCount        int      `json:"row_urn_count"`
	ReferencedURNCount int      `json:"referenced_urn_count"`
}

type UnsupportedQuery struct {
	Code              string   `json:"code"`
	Reason            string   `json:"reason"`
	SupportedIntents  []string `json:"supported_intents"`
	SuggestedRewrites []string `json:"suggested_rewrites"`
	TraceID           string   `json:"trace_id"`
}

type SummaryEvent struct {
	Markdown               string                  `json:"markdown"`
	Citations              []Citation              `json:"citations"`
	CitationValidation     *CitationValidation     `json:"citation_validation,omitempty"`
	ConversationValidation *ConversationValidation `json:"conversation_validation,omitempty"`
	ExecutionLane          string                  `json:"execution_lane,omitempty"`
	UnsupportedQuery       *UnsupportedQuery       `json:"unsupported_query,omitempty"`
}

type StageTimings struct {
	RouteMS              int64 `json:"route_ms,omitempty"`
	ConversationMS       int64 `json:"conversation_ms,omitempty"`
	ProbeMS              int64 `json:"probe_ms,omitempty"`
	DraftMS              int64 `json:"draft_ms,omitempty"`
	ConversionMS         int64 `json:"conversion_ms,omitempty"`
	ValidateMS           int64 `json:"validate_ms,omitempty"`
	ExecuteMS            int64 `json:"execute_ms,omitempty"`
	SummarizeMS          int64 `json:"summarize_ms,omitempty"`
	CitationValidationMS int64 `json:"citation_validation_ms,omitempty"`
}

type DoneEvent struct {
	TraceID       string       `json:"trace_id"`
	TotalMS       int64        `json:"total_ms"`
	CypherRefused bool         `json:"cypher_refused"`
	Timings       StageTimings `json:"timings,omitempty"`
}

type ErrorEvent struct {
	Code    string       `json:"code"`
	Message string       `json:"message"`
	TraceID string       `json:"trace_id,omitempty"`
	Timings StageTimings `json:"timings,omitempty"`
}

func WriteSSEEvent(w io.Writer, event Event) error {
	payload, err := json.Marshal(event.Data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", event.Name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
		return err
	}
	return nil
}
