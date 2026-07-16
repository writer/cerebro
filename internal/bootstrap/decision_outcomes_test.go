package bootstrap

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type decisionOutcomeStore struct {
	decisionPacketTestReceipts
}

func (*decisionOutcomeStore) Ping(context.Context) error { return nil }

type decisionOutcomeLog struct {
	events []*cerebrov1.EventEnvelope
}

func (*decisionOutcomeLog) Ping(context.Context) error { return nil }

func (l *decisionOutcomeLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.events = append(l.events, event)
	return nil
}

func (l *decisionOutcomeLog) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	result := make([]*cerebrov1.EventEnvelope, 0, len(l.events))
	for _, event := range l.events {
		if request.TenantID != "" && event.GetTenantId() != request.TenantID {
			continue
		}
		if request.ExactKindFilters && !decisionOutcomeContains(request.KindPrefixes, event.GetKind()) {
			continue
		}
		matched := true
		for key, value := range request.AttributeEquals {
			if event.GetAttributes()[key] != value {
				matched = false
				break
			}
		}
		if matched {
			result = append(result, event)
		}
	}
	return result, nil
}

func TestDecisionPacketDispositionAndVerifiedOutcomeHTTP(t *testing.T) {
	store := &decisionOutcomeStore{decisionPacketTestReceipts: decisionPacketTestReceipts{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
		DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
		ScopeURN: "urn:cerebro:tenant-1:finding:1",
	}}}
	log := &decisionOutcomeLog{}
	app := &App{deps: Dependencies{StateStore: store, AppendLog: log}}

	decisionRequest := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/decisions", bytes.NewBufferString(`{
		"packetId":"dpr_1",
		"decisionDisposition":"accepted",
		"metadata":{"tenant_id":"tenant-1"}
	}`))
	decisionRequest.Header.Set("X-Cerebro-Tenant", "tenant-1")
	decisionRequest.Header.Set("X-Cerebro-Actor", "operator-1")
	decisionRecorder := httptest.NewRecorder()
	app.handleWriteDecision(decisionRecorder, decisionRequest)
	if decisionRecorder.Code != http.StatusCreated {
		t.Fatalf("decision status = %d body = %s", decisionRecorder.Code, decisionRecorder.Body.String())
	}
	decisionResponse := &cerebrov1.WriteDecisionResponse{}
	if err := protojson.Unmarshal(decisionRecorder.Body.Bytes(), decisionResponse); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if decisionResponse.GetDecisionId() == "" || decisionResponse.GetDurabilityStatus() != "recorded" || decisionResponse.GetProjectionStatus() != "not_configured" {
		t.Fatalf("decision response = %+v", decisionResponse)
	}

	outcomeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/outcomes", bytes.NewBufferString(`{
		"decisionId":"`+decisionResponse.GetDecisionId()+`",
		"outcomeType":"verified_closed",
		"metadata":{"tenant_id":"tenant-1"}
	}`))
	outcomeRequest.Header.Set("X-Cerebro-Tenant", "tenant-1")
	outcomeRequest.Header.Set("X-Cerebro-Actor", "verifier-1")
	outcomeRecorder := httptest.NewRecorder()
	app.handleWriteOutcome(outcomeRecorder, outcomeRequest)
	if outcomeRecorder.Code != http.StatusCreated {
		t.Fatalf("outcome status = %d body = %s", outcomeRecorder.Code, outcomeRecorder.Body.String())
	}
	if len(log.events) != 2 || log.events[0].GetKind() != workflowevents.EventKindKnowledgeDecisionRecorded || log.events[1].GetKind() != workflowevents.EventKindKnowledgeOutcomeRecorded {
		t.Fatalf("durable events = %+v", log.events)
	}
}

func TestDecisionPacketDispositionRejectsSelfReportedActorForVerification(t *testing.T) {
	store := &decisionOutcomeStore{decisionPacketTestReceipts: decisionPacketTestReceipts{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
		DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
	}}}
	log := &decisionOutcomeLog{}
	app := &App{deps: Dependencies{StateStore: store, AppendLog: log}}

	decisionRequest := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/decisions", bytes.NewBufferString(`{
		"packetId":"dpr_1","decisionDisposition":"accepted","madeBy":"forged-verifier",
		"metadata":{"tenant_id":"tenant-1"}
	}`))
	decisionRequest.Header.Set("X-Cerebro-Tenant", "tenant-1")
	decisionRequest.Header.Set("X-Cerebro-Actor", "operator-1")
	decisionRecorder := httptest.NewRecorder()
	app.handleWriteDecision(decisionRecorder, decisionRequest)
	if decisionRecorder.Code != http.StatusCreated {
		t.Fatalf("decision status = %d body = %s", decisionRecorder.Code, decisionRecorder.Body.String())
	}
	decisionResponse := &cerebrov1.WriteDecisionResponse{}
	if err := protojson.Unmarshal(decisionRecorder.Body.Bytes(), decisionResponse); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}

	outcomeRequest := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/outcomes", bytes.NewBufferString(`{
		"decisionId":"`+decisionResponse.GetDecisionId()+`","outcomeType":"verified_closed",
		"metadata":{"tenant_id":"tenant-1"}
	}`))
	outcomeRequest.Header.Set("X-Cerebro-Tenant", "tenant-1")
	outcomeRequest.Header.Set("X-Cerebro-Actor", "operator-1")
	outcomeRecorder := httptest.NewRecorder()
	app.handleWriteOutcome(outcomeRecorder, outcomeRequest)
	if outcomeRecorder.Code != http.StatusBadRequest {
		t.Fatalf("outcome status = %d body = %s", outcomeRecorder.Code, outcomeRecorder.Body.String())
	}
	if len(log.events) != 1 {
		t.Fatalf("durable event count = %d, want decision only", len(log.events))
	}
}

func TestDecisionPacketDispositionAndOutcomeConnect(t *testing.T) {
	store := &decisionOutcomeStore{decisionPacketTestReceipts: decisionPacketTestReceipts{receipt: &ports.DecisionPacketReceipt{
		TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
		Workflow:      string(decisionworkflow.WorkflowChangeDecision),
		DecisionState: string(decisionworkflow.DecisionSupportedWithGaps), PacketDigest: "sha256:packet",
	}}}
	log := &decisionOutcomeLog{}
	service := &bootstrapService{deps: Dependencies{StateStore: store, AppendLog: log}}
	metadata, err := structpb.NewStruct(map[string]any{"tenant_id": "tenant-1"})
	if err != nil {
		t.Fatalf("build metadata: %v", err)
	}

	decisionRequest := connect.NewRequest(&cerebrov1.WriteDecisionRequest{
		PacketId: "dpr_1", DecisionDisposition: "accepted", Metadata: metadata,
	})
	decisionRequest.Header().Set("X-Cerebro-Tenant", "tenant-1")
	decisionRequest.Header().Set("X-Cerebro-Actor", "operator-1")
	decisionResponse, err := service.WriteDecision(context.Background(), decisionRequest)
	if err != nil {
		t.Fatalf("WriteDecision() error = %v", err)
	}

	outcomeRequest := connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
		DecisionId: decisionResponse.Msg.GetDecisionId(), OutcomeType: "accepted", Metadata: metadata,
	})
	outcomeRequest.Header().Set("X-Cerebro-Tenant", "tenant-1")
	outcomeRequest.Header().Set("X-Cerebro-Actor", "operator-2")
	outcomeResponse, err := service.WriteOutcome(context.Background(), outcomeRequest)
	if err != nil {
		t.Fatalf("WriteOutcome() error = %v", err)
	}
	if outcomeResponse.Msg.GetDurabilityStatus() != "recorded" || len(log.events) != 2 {
		t.Fatalf("outcome response = %+v events = %d", outcomeResponse.Msg, len(log.events))
	}
}

func decisionOutcomeContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
