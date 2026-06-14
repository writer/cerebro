package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/runtimeresponse"
	"github.com/writer/cerebro/internal/workflowevents"
)

type runtimeResponseAppendLog struct {
	events []*cerebrov1.EventEnvelope
}

func (l *runtimeResponseAppendLog) Ping(context.Context) error { return nil }

func (l *runtimeResponseAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func TestRecordRuntimeResponseWorkflowAppendsActionEvent(t *testing.T) {
	appendLog := &runtimeResponseAppendLog{}
	app := &App{deps: Dependencies{AppendLog: appendLog}}
	createdAt := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	entry := &ports.RuntimeBlocklistEntry{
		ID:          "rr-1",
		TenantID:    "writer",
		Type:        "ip",
		Value:       "203.0.113.10",
		Reason:      "contain active incident",
		SourceJobID: "job-1",
		CreatedAt:   createdAt,
	}
	err := app.recordRuntimeResponseWorkflow(context.Background(), runtimeresponse.ExecuteRequest{
		Action: " " + runtimeresponse.ActionBlockIP + " ",
	}, entry)
	if err != nil {
		t.Fatalf("recordRuntimeResponseWorkflow() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("appended events = %d, want 1", len(appendLog.events))
	}
	event := appendLog.events[0]
	if got := event.GetKind(); got != workflowevents.EventKindKnowledgeActionRecorded {
		t.Fatalf("event kind = %q, want %q", got, workflowevents.EventKindKnowledgeActionRecorded)
	}
	if got := event.GetAttributes()[workflowevents.EventAttributeActionID]; got == "" {
		t.Fatal("workflow event missing action_id attribute")
	}
	payload, err := workflowevents.DecodeActionRecorded(event)
	if err != nil {
		t.Fatalf("DecodeActionRecorded() error = %v", err)
	}
	if payload.ActionType != runtimeresponse.ActionBlockIP {
		t.Fatalf("action type = %q, want %q", payload.ActionType, runtimeresponse.ActionBlockIP)
	}
	if payload.Title != "Runtime response "+runtimeresponse.ActionBlockIP {
		t.Fatalf("title = %q, want normalized runtime response title", payload.Title)
	}
	if payload.SourceEventID != entry.ID {
		t.Fatalf("source event id = %q, want %q", payload.SourceEventID, entry.ID)
	}
	if payload.Metadata["source_job_id"] != entry.SourceJobID {
		t.Fatalf("source_job_id metadata = %v, want %q", payload.Metadata["source_job_id"], entry.SourceJobID)
	}
}

func TestWriteRuntimeResponseErrorSanitizesRuntimeUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeRuntimeResponseError(recorder, fmt.Errorf("%w: endpoint token secret leaked", runtimeresponse.ErrRuntimeUnavailable))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "service unavailable" {
		t.Fatalf("error body = %q, want sanitized service unavailable", body["error"])
	}
}
