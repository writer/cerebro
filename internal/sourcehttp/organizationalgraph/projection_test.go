package organizationalgraph

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type sourceProjectorStub struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (s *sourceProjectorStub) Project(context.Context, *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return ports.ProjectionResult{EntitiesProjected: 7}, s.err
}

func (s *sourceProjectorStub) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestAppendLogProjectorUsesExactlyOneAuthority(t *testing.T) {
	var authority = projectionAuthorityLegacy
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projections/events":
			var request projectEventRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if !request.AppendLogCommitted || request.FamilyID != "content_assets" || request.SourceRuntimeID != "box-runtime" {
				t.Fatalf("request = %#v", request)
			}
			response := projectEventResponse{Authority: authority}
			if authority == projectionAuthorityRust {
				revision := uint64(11)
				response.Projected = true
				response.GraphRevision = &revision
				response.EntitiesUpserted = 1
			}
			_ = json.NewEncoder(w).Encode(response)
		case "/v1/projections/authority":
			_ = json.NewEncoder(w).Encode(authorityResponse{Authority: authority})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{}
	projector := NewAppendLogProjector(legacy, client)
	event := projectionEvent()

	result, err := projector.Project(context.Background(), event)
	if err != nil || result.EntitiesProjected != 7 || legacy.callCount() != 1 {
		t.Fatalf("legacy Project() = %#v, %v calls=%d", result, err, legacy.callCount())
	}
	authority = projectionAuthorityRust
	result, err = projector.Project(context.Background(), event)
	if err != nil || result.EntitiesProjected != 1 || legacy.callCount() != 1 {
		t.Fatalf("Rust Project() = %#v, %v calls=%d", result, err, legacy.callCount())
	}
}

func TestProjectionClientRequiresAFixedHTTPOrigin(t *testing.T) {
	for _, value := range []string{
		"",
		"file:///tmp/graph",
		"https://user:password@example.test",
		"https://example.test/path",
		"https://example.test?tenant=other",
		"https://example.test#fragment",
	} {
		if _, err := NewProjectionClient(value, time.Second); err == nil {
			t.Fatalf("NewProjectionClient(%q) error = nil", value)
		}
	}
}

func TestLegacyWriteGuardSuppressesGoAfterPromotion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(authorityResponse{Authority: projectionAuthorityRust})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{}
	result, err := NewLegacyWriteGuard(legacy, client).Project(context.Background(), projectionEvent())
	if err != nil || result != (ports.ProjectionResult{}) || legacy.callCount() != 0 {
		t.Fatalf("Project() = %#v, %v calls=%d", result, err, legacy.callCount())
	}
}

func TestRustAuthorityFailureDoesNotFallBackToGo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	server.Close()
	client, err := NewProjectionClient(server.URL, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{err: errors.New("must not run")}
	_, err = NewAppendLogProjector(legacy, client).Project(context.Background(), projectionEvent())
	if err == nil || legacy.callCount() != 0 {
		t.Fatalf("Project() error = %v calls=%d", err, legacy.callCount())
	}
}

func TestProjectionRejectsMissingOccurrenceTimeBeforeCallingEitherWriter(t *testing.T) {
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		serverCalled = true
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{}
	event := projectionEvent()
	event.OccurredAt = nil
	_, err = NewAppendLogProjector(legacy, client).Project(context.Background(), event)
	if err == nil || serverCalled || legacy.callCount() != 0 {
		t.Fatalf("Project() error = %v server_called=%t legacy_calls=%d", err, serverCalled, legacy.callCount())
	}
}

func projectionEvent() *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "event-1",
		TenantId:   "tenant-a",
		SourceId:   "box",
		Kind:       "box.content_assets",
		OccurredAt: timestamppb.New(time.Unix(100, 0)),
		Payload:    []byte(`{"id":"asset-1"}`),
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: "box-runtime",
			"resource_id":                       "asset-1",
		},
	}
}
