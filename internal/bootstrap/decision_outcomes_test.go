package bootstrap

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionops"
	"github.com/writer/cerebro/internal/decisionworkflow"
	"github.com/writer/cerebro/internal/knowledge"
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

func TestLegacyKnownOutcomesRetainKnowledgePath(t *testing.T) {
	writeLegacyDecision := func(t *testing.T, log *decisionOutcomeLog, decisionID string) string {
		t.Helper()
		writer := knowledge.New(nil, nil).WithAppendLog(log).WithDurabilityMode(knowledge.DurabilityRequired)
		result, err := writer.WriteDecision(context.Background(), knowledge.DecisionWriteRequest{
			ID: decisionID, DecisionType: "change", Status: "recorded", SourceSystem: "legacy",
			TargetIDs:  []string{"urn:cerebro:tenant-1:resource:1"},
			ObservedAt: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC),
			Metadata:   map[string]any{"tenant_id": "tenant-1"},
		})
		if err != nil {
			t.Fatalf("WriteDecision() error = %v", err)
		}
		return result.DecisionID
	}

	t.Run("HTTP", func(t *testing.T) {
		log := &decisionOutcomeLog{}
		decisionID := writeLegacyDecision(t, log, "decision-legacy-http")
		app := &App{deps: Dependencies{AppendLog: log}}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/outcomes", bytes.NewBufferString(`{
			"decisionId":"`+decisionID+`","outcomeType":"accepted","verdict":"accepted",
			"metadata":{"tenant_id":"tenant-1"}
		}`))
		recorder := httptest.NewRecorder()
		app.handleWriteOutcome(recorder, request)
		if recorder.Code != http.StatusCreated {
			t.Fatalf("outcome status = %d body = %s", recorder.Code, recorder.Body.String())
		}
		if len(log.events) != 2 {
			t.Fatalf("durable event count = %d, want 2", len(log.events))
		}
	})

	t.Run("Connect", func(t *testing.T) {
		log := &decisionOutcomeLog{}
		decisionID := writeLegacyDecision(t, log, "decision-legacy-connect")
		service := &bootstrapService{deps: Dependencies{AppendLog: log}}
		metadata, err := structpb.NewStruct(map[string]any{"tenant_id": "tenant-1"})
		if err != nil {
			t.Fatalf("build metadata: %v", err)
		}
		response, err := service.WriteOutcome(context.Background(), connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
			DecisionId: decisionID, OutcomeType: "accepted", Verdict: "accepted", Metadata: metadata,
		}))
		if err != nil {
			t.Fatalf("WriteOutcome() error = %v", err)
		}
		if response.Msg.GetDurabilityStatus() != "recorded" || len(log.events) != 2 {
			t.Fatalf("outcome response = %+v events = %d", response.Msg, len(log.events))
		}
	})
}

func TestPacketDecisionsRejectNonterminalOutcomeVocabulary(t *testing.T) {
	setup := func(t *testing.T) (Dependencies, *decisionOutcomeLog, string) {
		t.Helper()
		store := &decisionOutcomeStore{decisionPacketTestReceipts: decisionPacketTestReceipts{receipt: &ports.DecisionPacketReceipt{
			TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
			Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
			DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
			ScopeURN: "urn:cerebro:tenant-1:finding:1",
		}}}
		log := &decisionOutcomeLog{}
		deps := Dependencies{StateStore: store, AppendLog: log}
		result, err := newDecisionOutcomeService(deps).RecordDecision(context.Background(), decisionops.RecordDecisionRequest{
			TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1",
			Disposition: decisionworkflow.DispositionAccepted, Reason: decisionworkflow.DismissalNone,
		})
		if err != nil {
			t.Fatalf("RecordDecision() error = %v", err)
		}
		return deps, log, result.Record.ID
	}

	for _, outcomeType := range []string{"custom", "none"} {
		t.Run("HTTP/"+outcomeType, func(t *testing.T) {
			deps, log, decisionID := setup(t)
			app := &App{deps: deps}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/outcomes", bytes.NewBufferString(`{
				"decisionId":"`+decisionID+`","outcomeType":"`+outcomeType+`","verdict":"custom",
				"metadata":{"tenant_id":"tenant-1"}
			}`))
			recorder := httptest.NewRecorder()
			app.handleWriteOutcome(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("outcome status = %d body = %s, want 400", recorder.Code, recorder.Body.String())
			}
			if len(log.events) != 1 {
				t.Fatalf("durable event count = %d, want decision only", len(log.events))
			}
		})

		t.Run("Connect/"+outcomeType, func(t *testing.T) {
			deps, log, decisionID := setup(t)
			metadata, err := structpb.NewStruct(map[string]any{"tenant_id": "tenant-1"})
			if err != nil {
				t.Fatalf("build metadata: %v", err)
			}
			_, err = (&bootstrapService{deps: deps}).WriteOutcome(context.Background(), connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
				DecisionId: decisionID, OutcomeType: outcomeType, Verdict: "custom", Metadata: metadata,
			}))
			if connect.CodeOf(err) != connect.CodeInvalidArgument {
				t.Fatalf("WriteOutcome() code = %s, err = %v; want invalid_argument", connect.CodeOf(err), err)
			}
			if len(log.events) != 1 {
				t.Fatalf("durable event count = %d, want decision only", len(log.events))
			}
		})
	}
}

func TestPacketDecisionOutcomePreplayIsRejected(t *testing.T) {
	setup := func() (Dependencies, *decisionOutcomeLog) {
		store := &decisionOutcomeStore{decisionPacketTestReceipts: decisionPacketTestReceipts{receipt: &ports.DecisionPacketReceipt{
			TenantID: "tenant-1", PacketID: "dpr_1", SchemaVersion: "2026-07-15",
			Workflow:      string(decisionworkflow.WorkflowFindingToVerifiedFix),
			DecisionState: string(decisionworkflow.DecisionSupported), PacketDigest: "sha256:packet",
			ScopeURN: "urn:cerebro:tenant-1:finding:1",
		}}}
		log := &decisionOutcomeLog{}
		return Dependencies{StateStore: store, AppendLog: log}, log
	}
	futureDecisionID := workflowevents.CanonicalWorkflowID(
		"tenant-1", "packet_decision", "dpr_1:accepted", "", nil, time.Time{},
	)
	assertDecisionCanBeRecorded := func(t *testing.T, deps Dependencies, log *decisionOutcomeLog) {
		t.Helper()
		result, err := newDecisionOutcomeService(deps).RecordDecision(context.Background(), decisionops.RecordDecisionRequest{
			TenantID: "tenant-1", ActorID: "operator-1", PacketID: "dpr_1",
			Disposition: decisionworkflow.DispositionAccepted, Reason: decisionworkflow.DismissalNone,
		})
		if err != nil {
			t.Fatalf("RecordDecision() error = %v", err)
		}
		if result.Record.ID != futureDecisionID || len(log.events) != 1 {
			t.Fatalf("recorded decision = %q events = %d, want %q and one decision event", result.Record.ID, len(log.events), futureDecisionID)
		}
	}

	t.Run("HTTP", func(t *testing.T) {
		deps, log := setup()
		app := &App{deps: deps}
		squatRequest := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/decisions", bytes.NewBufferString(`{
			"id":"`+futureDecisionID+`","decisionType":"change","status":"recorded",
			"targetIds":["urn:cerebro:tenant-1:resource:1"],"metadata":{"tenant_id":"tenant-1"}
		}`))
		squatRecorder := httptest.NewRecorder()
		app.handleWriteDecision(squatRecorder, squatRequest)
		if squatRecorder.Code != http.StatusBadRequest || len(log.events) != 0 {
			t.Fatalf("squat status = %d events = %d body = %s, want 400 and no events", squatRecorder.Code, len(log.events), squatRecorder.Body.String())
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/platform/knowledge/outcomes", bytes.NewBufferString(`{
			"decisionId":"`+futureDecisionID+`","outcomeType":"verified_closed","verdict":"verified_closed",
			"metadata":{"tenant_id":"tenant-1"}
		}`))
		recorder := httptest.NewRecorder()
		app.handleWriteOutcome(recorder, request)
		if recorder.Code != http.StatusNotFound || len(log.events) != 0 {
			t.Fatalf("preplay status = %d events = %d body = %s, want 404 and no events", recorder.Code, len(log.events), recorder.Body.String())
		}
		assertDecisionCanBeRecorded(t, deps, log)
	})

	t.Run("Connect", func(t *testing.T) {
		deps, log := setup()
		metadata, err := structpb.NewStruct(map[string]any{"tenant_id": "tenant-1"})
		if err != nil {
			t.Fatalf("build metadata: %v", err)
		}
		service := &bootstrapService{deps: deps}
		_, err = service.WriteDecision(context.Background(), connect.NewRequest(&cerebrov1.WriteDecisionRequest{
			Id: futureDecisionID, DecisionType: "change", Status: "recorded",
			TargetIds: []string{"urn:cerebro:tenant-1:resource:1"}, Metadata: metadata,
		}))
		if connect.CodeOf(err) != connect.CodeInvalidArgument || len(log.events) != 0 {
			t.Fatalf("squat code = %s events = %d err = %v, want invalid_argument and no events", connect.CodeOf(err), len(log.events), err)
		}
		_, err = service.WriteOutcome(context.Background(), connect.NewRequest(&cerebrov1.WriteOutcomeRequest{
			DecisionId: futureDecisionID, OutcomeType: "verified_closed", Verdict: "verified_closed", Metadata: metadata,
		}))
		if connect.CodeOf(err) != connect.CodeNotFound || len(log.events) != 0 {
			t.Fatalf("preplay code = %s events = %d err = %v, want not_found and no events", connect.CodeOf(err), len(log.events), err)
		}
		assertDecisionCanBeRecorded(t, deps, log)
	})
}

func decisionOutcomeContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
