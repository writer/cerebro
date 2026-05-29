package graphagent

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/writer/cerebro/internal/ports"
)

const (
	EventProgress  = "progress"
	EventRationale = "rationale"
	EventCypher    = "cypher"
	EventRows      = "rows"
	EventSummary   = "summary"
	EventDone      = "done"
	EventError     = "error"
)

type Event struct {
	Name string
	Data any
}

type ValidatorResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

type ProgressEvent struct {
	Stage     string `json:"stage"`
	Message   string `json:"message"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

type RationaleEvent struct {
	Text string `json:"text"`
}

type CypherEvent struct {
	Cypher    string          `json:"cypher"`
	Validator ValidatorResult `json:"validator"`
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

type SummaryEvent struct {
	Markdown  string     `json:"markdown"`
	Citations []Citation `json:"citations"`
}

type DoneEvent struct {
	TraceID       string `json:"trace_id"`
	TotalMS       int64  `json:"total_ms"`
	CypherRefused bool   `json:"cypher_refused"`
}

type ErrorEvent struct {
	Code    string `json:"code"`
	Message string `json:"message"`
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
