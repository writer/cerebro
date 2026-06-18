package graphactionworkflow

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type recordingAppendLog struct {
	events []*cerebrov1.EventEnvelope
}

func (l *recordingAppendLog) Ping(context.Context) error { return nil }

func (l *recordingAppendLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func TestRecordUsesCanonicalActionURNForProviderID(t *testing.T) {
	appendLog := &recordingAppendLog{}
	tenantID := "tenant:1/prod"
	externalID := "act:v2/oja?x=1#fragment"
	err := Record(context.Background(), appendLog, &ports.FindingRecord{
		ID:       "finding-1",
		TenantID: tenantID,
		RuleID:   "rule-1",
		Attributes: map[string]string{
			"primary_resource_urn": "urn:cerebro:tenant-1:okta.user:00u123",
		},
	}, &graphactions.GraphAction{
		ID:             "local-action-1",
		ExternalID:     externalID,
		Action:         graphactions.ActionIdentityOktaSuspendUser,
		Provider:       graphactions.ProviderAccessApprovals,
		ExternalStatus: "queued",
		CreatedAtUnix:  1700000000,
	}, "00u123")
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(appendLog.events) != 1 {
		t.Fatalf("recorded events = %d, want 1", len(appendLog.events))
	}
	payload, err := workflowevents.DecodeActionRecorded(appendLog.events[0])
	if err != nil {
		t.Fatalf("DecodeActionRecorded() error = %v", err)
	}
	prefix := "urn:cerebro:tenant%3A1%2Fprod:graph_action:"
	if !strings.HasPrefix(payload.ActionID, prefix) {
		t.Fatalf("ActionID = %q, want %q prefix", payload.ActionID, prefix)
	}
	suffix := strings.TrimPrefix(payload.ActionID, prefix)
	if len(suffix) != 64 || strings.ContainsAny(suffix, ":/?#") || strings.Contains(payload.ActionID, externalID) {
		t.Fatalf("ActionID = %q, want hash-derived canonical URN", payload.ActionID)
	}
	if payload.SourceEventID != externalID {
		t.Fatalf("SourceEventID = %q, want provider external id", payload.SourceEventID)
	}
	if got, _ := payload.Metadata["external_id"].(string); got != externalID {
		t.Fatalf("metadata external_id = %q, want provider external id", got)
	}
}
