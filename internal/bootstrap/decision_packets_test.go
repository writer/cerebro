package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/decisionpacket"
	"github.com/writer/cerebro/internal/ports"
)

type decisionPacketTestClock struct{ now time.Time }

func (c decisionPacketTestClock) Now() time.Time { return c.now }

type decisionPacketTestResolver struct {
	facts decisionpacket.ResolvedFacts
	seen  decisionpacket.AuthorizedTenant
}

func (r *decisionPacketTestResolver) Resolve(_ context.Context, tenant decisionpacket.AuthorizedTenant, _ decisionpacket.Request) (decisionpacket.ResolvedFacts, error) {
	r.seen = tenant
	return r.facts, nil
}

type decisionPacketTestReceipts struct{ receipt *ports.DecisionPacketReceipt }

func (s *decisionPacketTestReceipts) PutDecisionPacketReceipt(_ context.Context, receipt *ports.DecisionPacketReceipt) error {
	copy := *receipt
	copy.PacketJSON = append([]byte(nil), receipt.PacketJSON...)
	s.receipt = &copy
	return nil
}

func (s *decisionPacketTestReceipts) GetDecisionPacketReceipt(_ context.Context, tenantID, packetID string) (*ports.DecisionPacketReceipt, error) {
	if s.receipt == nil || s.receipt.TenantID != tenantID || s.receipt.PacketID != packetID {
		return nil, ports.ErrDecisionPacketNotFound
	}
	copy := *s.receipt
	copy.PacketJSON = append([]byte(nil), s.receipt.PacketJSON...)
	return &copy, nil
}

func TestDecisionPacketHTTPConnectAndReceiptParity(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	resolver := &decisionPacketTestResolver{facts: decisionpacket.ResolvedFacts{
		Evidence:    []decisionpacket.EvidenceReference{{ID: "evidence-1", Kind: "finding", ObservedAt: now.Add(-time.Minute)}},
		Affected:    []decisionpacket.SubjectReference{{URN: "urn:cerebro:tenant-1:asset:1", Kind: "asset"}},
		ResolverIDs: []string{"test-resolver"}, SourceIDs: []string{"source-1"},
		Rationale: "Current evidence supports the conclusion.",
	}}
	receipts := &decisionPacketTestReceipts{}
	service := decisionpacket.NewPersistentService(resolver, decisionPacketTestClock{now: now}, receipts, 24*time.Hour)
	app := &App{services: appServices{decisionPackets: service}}

	body := []byte(`{"workflow":"triage","question":"Is this finding current?","scopeUrn":"urn:cerebro:tenant-1:finding:1","findingIds":["finding-1"],"requiredSources":["source-1"]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/platform/decision-packets", bytes.NewReader(body))
	request.Header.Set("X-Cerebro-Tenant", "tenant-1")
	request.Header.Set("X-Cerebro-Actor", "actor-1")
	recorder := httptest.NewRecorder()
	app.handleBuildDecisionPacket(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("POST status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var httpPacket decisionpacket.Packet
	if err := json.NewDecoder(recorder.Body).Decode(&httpPacket); err != nil {
		t.Fatalf("decode POST response: %v", err)
	}
	if httpPacket.Scope.TenantID != "tenant-1" || httpPacket.Scope.ActorID != "actor-1" || resolver.seen.ID != "tenant-1" {
		t.Fatalf("forced identity = %+v resolver tenant = %+v", httpPacket.Scope, resolver.seen)
	}
	if receipts.receipt == nil || receipts.receipt.PacketID != httpPacket.ID || receipts.receipt.ExpiresAt == nil {
		t.Fatalf("receipt = %+v", receipts.receipt)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/api/v1/platform/decision-packets/"+httpPacket.ID, nil)
	getRequest.SetPathValue("packetID", httpPacket.ID)
	getRequest.Header.Set("X-Cerebro-Tenant", "tenant-1")
	getRequest.Header.Set("X-Cerebro-Actor", "actor-1")
	getRecorder := httptest.NewRecorder()
	app.handleGetDecisionPacket(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d body = %s", getRecorder.Code, getRecorder.Body.String())
	}
	var reopened decisionpacket.Packet
	if err := json.NewDecoder(getRecorder.Body).Decode(&reopened); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if reopened.ID != httpPacket.ID || reopened.Provenance.EvidenceDigest != httpPacket.Provenance.EvidenceDigest {
		t.Fatalf("reopened packet = %+v want id %q digest %q", reopened, httpPacket.ID, httpPacket.Provenance.EvidenceDigest)
	}
	if len(reopened.Inputs.FindingIDs) != 1 || reopened.Inputs.FindingIDs[0] != "finding-1" || len(reopened.Inputs.RequiredSources) != 1 {
		t.Fatalf("reopened inputs = %+v", reopened.Inputs)
	}

	connectRequest := connect.NewRequest(&cerebrov1.BuildDecisionPacketRequest{
		Workflow: "triage", Question: "Is this finding current?", ScopeUrn: "urn:cerebro:tenant-1:finding:1",
		FindingIds: []string{"finding-1"}, RequiredSources: []string{"source-1"},
	})
	connectRequest.Header().Set("X-Cerebro-Tenant", "tenant-1")
	connectRequest.Header().Set("X-Cerebro-Actor", "actor-1")
	connectResponse, err := (&bootstrapService{decisionPackets: service}).BuildDecisionPacket(context.Background(), connectRequest)
	if err != nil {
		t.Fatalf("BuildDecisionPacket() error = %v", err)
	}
	if connectResponse.Msg.GetPacket().GetId() != httpPacket.ID || connectResponse.Msg.GetPacket().GetDecision().GetState() != httpPacket.Decision.State {
		t.Fatalf("Connect packet = %+v HTTP packet = %+v", connectResponse.Msg.GetPacket(), httpPacket)
	}
}

func TestDecisionPacketHTTPRejectsUnknownFields(t *testing.T) {
	app := &App{services: appServices{decisionPackets: decisionpacket.NewService(&decisionPacketTestResolver{}, decisionPacketTestClock{})}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/platform/decision-packets", bytes.NewBufferString(`{"workflow":"triage","question":"Current?","tenantId":"tenant-2"}`))
	request.Header.Set("X-Cerebro-Tenant", "tenant-1")
	recorder := httptest.NewRecorder()
	app.handleBuildDecisionPacket(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestMCPDecisionPacketUsesAuthenticatedIdentityAndPersistsReceipt(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	resolver := &decisionPacketTestResolver{facts: decisionpacket.ResolvedFacts{
		Evidence:    []decisionpacket.EvidenceReference{{ID: "evidence-1", Kind: "finding", ObservedAt: now.Add(-time.Minute)}},
		ResolverIDs: []string{"test-resolver"}, SourceIDs: []string{"source-1"}, Rationale: "Resolved by the server.",
	}}
	receipts := &decisionPacketTestReceipts{}
	app := &App{services: appServices{decisionPackets: decisionpacket.NewPersistentService(resolver, decisionPacketTestClock{now: now}, receipts, time.Hour)}}
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{principal: authPrincipal{
		Name: "agent-1", TenantID: "tenant-1", Scopes: []string{scopeCosmoSecurityRead},
	}}))

	value, err := app.mcpDecisionPacket(request, map[string]any{
		"workflow": "triage", "question": "Is this finding current?", "finding_ids": []any{"finding-1"},
	})
	if err != nil {
		t.Fatalf("mcpDecisionPacket() error = %v", err)
	}
	packet, ok := value.(*decisionpacket.Packet)
	if !ok {
		t.Fatalf("mcpDecisionPacket() = %T, want *decisionpacket.Packet", value)
	}
	if packet.Scope.TenantID != "tenant-1" || packet.Scope.ActorID != "agent-1" || resolver.seen.ID != "tenant-1" {
		t.Fatalf("forced identity = %+v resolver tenant = %+v", packet.Scope, resolver.seen)
	}
	if receipts.receipt == nil || receipts.receipt.PacketID != packet.ID {
		t.Fatalf("persisted receipt = %+v, packet = %+v", receipts.receipt, packet)
	}

	if _, err := app.mcpDecisionPacket(request, map[string]any{"workflow": "triage", "question": "Current?", "tenant_id": "other"}); !errors.Is(err, errInvalidHTTPRequest) {
		t.Fatalf("caller-supplied tenant error = %v, want invalid request", err)
	}
}

func TestDecisionPacketConnectInternalErrorsHideDetails(t *testing.T) {
	err := decisionPacketConnectError(errors.New("postgres password leaked"))
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error = %T, want *connect.Error", err)
	}
	if connectErr.Code() != connect.CodeInternal || connectErr.Message() != "internal error" || strings.Contains(connectErr.Message(), "postgres") {
		t.Fatalf("connect error = code %s message %q", connectErr.Code(), connectErr.Message())
	}
}
