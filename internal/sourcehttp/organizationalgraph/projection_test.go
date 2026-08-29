package organizationalgraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

type sourceProjectorWithDeltaStub struct {
	calls int
	delta ports.SourceProjectionDelta
}

func (s *sourceProjectorWithDeltaStub) Project(context.Context, *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	return ports.ProjectionResult{}, errors.New("Project must not be called when ProjectWithDelta is available")
}

func (s *sourceProjectorWithDeltaStub) ProjectWithDelta(context.Context, *cerebrov1.EventEnvelope) (ports.ProjectionResult, ports.SourceProjectionDelta, error) {
	s.calls++
	return ports.ProjectionResult{EntitiesProjected: 1}, s.delta, nil
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

func projectionAuthorityResponse(authority string) authorityResponse {
	return authorityResponse{
		TenantID:  "tenant-a",
		SourceID:  "box",
		FamilyID:  "content_assets",
		Authority: authority,
	}
}

func TestAppendLogProjectorUsesExactlyOneAuthority(t *testing.T) {
	var authority = projectionAuthorityLegacy
	var authorityRequests int
	var projectionRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(tenantAuthHeader) != "tenant-a" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Fatalf("tenant authentication headers are missing")
		}
		switch r.URL.Path {
		case "/v1/projections/events":
			projectionRequests++
			http.Error(w, "event payload handoff is retired", http.StatusGone)
		case "/v1/projections/authority":
			authorityRequests++
			_ = json.NewEncoder(w).Encode(projectionAuthorityResponse(authority))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
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
	if err != nil || result != (ports.ProjectionResult{}) || legacy.callCount() != 1 {
		t.Fatalf("Rust Project() = %#v, %v calls=%d", result, err, legacy.callCount())
	}
	if authorityRequests != 2 || projectionRequests != 0 {
		t.Fatalf("authority_requests=%d projection_requests=%d", authorityRequests, projectionRequests)
	}
}

func TestAppendLogProjectorAuthorityReadIsTenantScopedUnderRace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.URL.Query().Get("tenant_id")
		if r.URL.Path != "/v1/projections/authority" ||
			r.Header.Get(tenantAuthHeader) != tenantID ||
			(tenantID != "tenant-a" && tenantID != "tenant-b") {
			http.Error(w, "authority scope mismatch", http.StatusBadRequest)
			return
		}
		authority := projectionAuthorityRust
		if tenantID == "tenant-a" {
			authority = projectionAuthorityLegacy
		}
		_ = json.NewEncoder(w).Encode(authorityResponse{
			TenantID:  tenantID,
			SourceID:  r.URL.Query().Get("source_id"),
			FamilyID:  r.URL.Query().Get("family_id"),
			Authority: authority,
		})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{}
	projector := NewAppendLogProjector(legacy, client)

	const iterations = 32
	errorsByCall := make(chan error, iterations*2)
	var wait sync.WaitGroup
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		for range iterations {
			wait.Add(1)
			go func(tenantID string) {
				defer wait.Done()
				event := projectionEvent()
				event.TenantId = tenantID
				result, err := projector.Project(context.Background(), event)
				if err != nil {
					errorsByCall <- fmt.Errorf("tenant %s: %w", tenantID, err)
					return
				}
				if tenantID == "tenant-a" && result.EntitiesProjected != 7 {
					errorsByCall <- fmt.Errorf("tenant-a result = %#v, want legacy projection", result)
				}
				if tenantID == "tenant-b" && result != (ports.ProjectionResult{}) {
					errorsByCall <- fmt.Errorf("tenant-b result = %#v, want Rust authority", result)
				}
			}(tenantID)
		}
	}
	wait.Wait()
	close(errorsByCall)
	for err := range errorsByCall {
		t.Error(err)
	}
	if calls := legacy.callCount(); calls != iterations {
		t.Fatalf("legacy calls = %d, want exactly tenant-a calls %d", calls, iterations)
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
		if _, err := NewProjectionClient(value, testSharedSecret, time.Second); err == nil {
			t.Fatalf("NewProjectionClient(%q) error = nil", value)
		}
	}
}

func TestAppendLogProjectorRecordsExactLegacyDelta(t *testing.T) {
	var deltaRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projections/authority":
			_ = json.NewEncoder(w).Encode(projectionAuthorityResponse(projectionAuthorityLegacy))
		case "/v1/projections/legacy-deltas":
			deltaRequests++
			var request legacyProjectionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatalf("decode legacy delta: %v", err)
			}
			if request.EventID != "event-1" ||
				len(request.Delta.Entities) != 1 ||
				request.Delta.Entities[0].URN != "urn:cerebro:tenant-a:asset:one" ||
				request.Delta.Entities[0].RuntimeID != "box-runtime" {
				t.Fatalf("legacy delta request = %#v", request)
			}
			_ = json.NewEncoder(w).Encode(legacyProjectionResponse{
				Recorded:    true,
				DeltaDigest: strings.Repeat("a", 64),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorWithDeltaStub{delta: ports.SourceProjectionDelta{
		Entities: []*ports.ProjectedEntity{{
			URN:        "urn:cerebro:tenant-a:asset:one",
			TenantID:   "tenant-a",
			SourceID:   "box",
			RuntimeID:  "box-runtime",
			EntityType: "box.asset",
			Label:      "One",
		}},
	}}
	result, err := NewAppendLogProjector(legacy, client).Project(context.Background(), projectionEvent())
	if err != nil || result.EntitiesProjected != 1 || legacy.calls != 1 || deltaRequests != 1 {
		t.Fatalf("Project() = %#v, %v legacy_calls=%d delta_requests=%d", result, err, legacy.calls, deltaRequests)
	}
}

func TestAppendLogProjectorRecordsCollectionManifest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projections/collections" {
			http.NotFound(w, r)
			return
		}
		var request sourceCollectionRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode collection: %v", err)
		}
		if request.CollectionID != "collection-1" ||
			request.Status != "complete" ||
			len(request.ObservedFamilyIDs) != 1 ||
			request.ObservedFamilyIDs[0] != "content_assets" {
			t.Fatalf("collection request = %#v", request)
		}
		_ = json.NewEncoder(w).Encode(sourceCollectionResponse{
			Recorded:       true,
			ManifestDigest: strings.Repeat("b", 64),
		})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	err = NewAppendLogProjector(nil, client).RecordSourceCollection(context.Background(), ports.SourceCollectionManifest{
		CollectionID:      "collection-1",
		TenantID:          "tenant-a",
		SourceID:          "box",
		RuntimeID:         "box-runtime",
		StartedAtUnixMS:   100,
		CompletedAtUnixMS: 200,
		Status:            "complete",
		ObservedFamilyIDs: []string{"content_assets"},
	})
	if err != nil {
		t.Fatalf("RecordSourceCollection() error = %v", err)
	}
}

// The Rust handlers declare these lists as `#[serde(default)] Vec<String>`,
// which accepts an absent field or [] but rejects null. A nil Go slice marshals
// to null, so an empty list has to reach the wire as [] or the request is
// rejected with 422 Unprocessable Entity.
func TestProjectionClientEncodesEmptyStringListsAsArrays(t *testing.T) {
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(sourceCollectionResponse{
			Recorded:       true,
			ManifestDigest: strings.Repeat("b", 64),
		})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}

	// A complete collection must carry no incompleteness reasons, so the common
	// success path always encodes at least one empty list.
	err = NewAppendLogProjector(nil, client).RecordSourceCollection(context.Background(), ports.SourceCollectionManifest{
		CollectionID:      "collection-1",
		TenantID:          "tenant-a",
		SourceID:          "box",
		RuntimeID:         "box-runtime",
		StartedAtUnixMS:   100,
		CompletedAtUnixMS: 200,
		Status:            "complete",
	})
	if err != nil {
		t.Fatalf("RecordSourceCollection() error = %v", err)
	}

	for _, field := range []string{"incompleteness_reasons", "expected_family_ids", "observed_family_ids"} {
		if strings.Contains(string(body), `"`+field+`":null`) {
			t.Fatalf("%s encoded as null, want []: %s", field, body)
		}
		if !strings.Contains(string(body), `"`+field+`":[]`) {
			t.Fatalf("%s missing empty array encoding: %s", field, body)
		}
	}
}

func TestLegacyDeltaRequestEncodesEmptyRetractionsAsArray(t *testing.T) {
	body, err := json.Marshal(legacyDeltaRequest(ports.SourceProjectionDelta{}))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(body), `"entity_retractions":null`) {
		t.Fatalf("entity_retractions encoded as null, want []: %s", body)
	}
	if !strings.Contains(string(body), `"entity_retractions":[]`) {
		t.Fatalf("entity_retractions missing empty array encoding: %s", body)
	}
}

func TestProjectionClientReadsExactSourceCollectionManifest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet ||
			r.URL.Path != "/v1/projections/collections/collection-verified" ||
			r.URL.Query().Get("tenant_id") != "tenant-a" ||
			r.URL.Query().Get("source_runtime_id") != "box-runtime" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get(tenantAuthHeader) != "tenant-a" {
			t.Fatalf("tenant authentication header = %q, want tenant-a", r.Header.Get(tenantAuthHeader))
		}
		_ = json.NewEncoder(w).Encode(sourceCollectionManifestResponse{
			CollectionID:          "collection-verified",
			TenantID:              "tenant-a",
			SourceID:              "box",
			SourceRuntimeID:       "box-runtime",
			StartedAtUnixMS:       100,
			CompletedAtUnixMS:     200,
			Status:                "complete",
			IncompletenessReasons: []string{},
			ExpectedFamilyIDs:     []string{"content_assets"},
			ObservedFamilyIDs:     []string{"content_assets"},
			PagesRead:             1,
			RecordsScanned:        1,
			RecordsAccepted:       1,
		})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	manifest, err := client.GetSourceCollection(context.Background(), "tenant-a", "box-runtime", "collection-verified")
	if err != nil {
		t.Fatalf("GetSourceCollection() error = %v", err)
	}
	if manifest.CollectionID != "collection-verified" ||
		manifest.TenantID != "tenant-a" ||
		manifest.RuntimeID != "box-runtime" ||
		manifest.Status != "complete" ||
		manifest.CompletedAtUnixMS != 200 {
		t.Fatalf("GetSourceCollection() = %#v", manifest)
	}
}

func TestProjectionClientReportsMissingSourceCollection(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	_, err = client.GetSourceCollection(context.Background(), "tenant-a", "box-runtime", "collection-missing")
	if !errors.Is(err, ErrSourceCollectionNotFound) {
		t.Fatalf("GetSourceCollection() error = %v, want ErrSourceCollectionNotFound", err)
	}
}

func TestProjectionClientScopesSourceCollectionLookupByTenantAndRuntime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("tenant_id") != "tenant-a" ||
			r.URL.Query().Get("source_runtime_id") != "runtime-a" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(sourceCollectionManifestResponse{
			CollectionID:    "collection-shared",
			TenantID:        "tenant-a",
			SourceRuntimeID: "runtime-a",
			Status:          "complete",
		})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	for _, scope := range []struct {
		tenantID string
		runtime  string
	}{
		{tenantID: "tenant-b", runtime: "runtime-a"},
		{tenantID: "tenant-a", runtime: "runtime-b"},
	} {
		_, err := client.GetSourceCollection(context.Background(), scope.tenantID, scope.runtime, "collection-shared")
		if !errors.Is(err, ErrSourceCollectionNotFound) {
			t.Fatalf("GetSourceCollection(%q, %q) error = %v, want ErrSourceCollectionNotFound", scope.tenantID, scope.runtime, err)
		}
	}
}

func TestProjectionClientRejectsMismatchedSourceCollectionProvenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(sourceCollectionManifestResponse{
			CollectionID:    "collection-verified",
			TenantID:        "tenant-a",
			SourceRuntimeID: "other-runtime",
			Status:          "complete",
		})
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	_, err = client.GetSourceCollection(context.Background(), "tenant-a", "box-runtime", "collection-verified")
	if !errors.Is(err, ErrSourceCollectionProvenanceMismatch) {
		t.Fatalf("GetSourceCollection() error = %v, want provenance mismatch", err)
	}
}

func TestLegacyWriteGuardSuppressesGoAfterPromotion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(projectionAuthorityResponse(projectionAuthorityRust))
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
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
	client, err := NewProjectionClient(server.URL, testSharedSecret, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{err: errors.New("must not run")}
	_, err = NewAppendLogProjector(legacy, client).Project(context.Background(), projectionEvent())
	if err == nil || legacy.callCount() != 0 {
		t.Fatalf("Project() error = %v calls=%d", err, legacy.callCount())
	}
}

func TestRustAuthorityScopeMismatchDoesNotFallBackToGo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := projectionAuthorityResponse(projectionAuthorityLegacy)
		response.TenantID = "tenant-b"
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	legacy := &sourceProjectorStub{err: errors.New("must not run")}
	_, err = NewAppendLogProjector(legacy, client).Project(context.Background(), projectionEvent())
	if !errors.Is(err, ErrProjectionAuthorityScopeMismatch) || legacy.callCount() != 0 {
		t.Fatalf("Project() error = %v calls=%d, want scope rejection without Go fallback", err, legacy.callCount())
	}
}

func TestProjectionRejectsMissingOccurrenceTimeBeforeCallingEitherWriter(t *testing.T) {
	serverCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		serverCalled = true
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
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

func TestProjectionRejectsInvalidCommittedEventsBeforeAuthorityLookup(t *testing.T) {
	for name, mutate := range map[string]func(*cerebrov1.EventEnvelope){
		"missing runtime": func(event *cerebrov1.EventEnvelope) {
			delete(event.Attributes, ports.EventAttributeSourceRuntimeID)
		},
		"invalid payload": func(event *cerebrov1.EventEnvelope) {
			event.Payload = []byte(`{"unterminated"`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			serverCalled := false
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				serverCalled = true
			}))
			defer server.Close()
			client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
			if err != nil {
				t.Fatalf("NewProjectionClient() error = %v", err)
			}
			legacy := &sourceProjectorStub{}
			event := projectionEvent()
			mutate(event)

			_, err = NewAppendLogProjector(legacy, client).Project(context.Background(), event)
			if err == nil || serverCalled || legacy.callCount() != 0 {
				t.Fatalf(
					"Project() error = %v server_called=%t legacy_calls=%d",
					err,
					serverCalled,
					legacy.callCount(),
				)
			}
		})
	}
}

func projectionEvent() *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "event-1",
		TenantId:   "tenant-a",
		SourceId:   "box",
		Kind:       "box.content_assets",
		SchemaRef:  "box/content_assets/v1",
		OccurredAt: timestamppb.New(time.Unix(100, 0)),
		Payload:    []byte(`{"id":"asset-1"}`),
		Attributes: map[string]string{
			ports.EventAttributeSourceRuntimeID: "box-runtime",
			"resource_id":                       "asset-1",
		},
	}
}
