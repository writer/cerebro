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

func TestAppendLogProjectorReportsLegacyReceiptConflictCause(t *testing.T) {
	const conflictMessage = "legacy projection for source event event-1 conflicts with the stored record"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projections/authority":
			_ = json.NewEncoder(w).Encode(projectionAuthorityResponse(projectionAuthorityLegacy))
		case "/v1/projections/legacy-deltas":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"code":    "projection_receipt_conflict",
				"message": conflictMessage,
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
	_, err = NewAppendLogProjector(legacy, client).Project(context.Background(), projectionEvent())
	if !errors.Is(err, ErrProjectionReceiptConflict) {
		t.Fatalf("Project() error = %v, want ErrProjectionReceiptConflict", err)
	}
	if !errors.Is(err, ports.ErrSourceProjectionRecordRejected) {
		t.Fatalf("Project() error = %v, want a record-scoped rejection", err)
	}
	var responseErr *ProjectionResponseError
	if !errors.As(err, &responseErr) ||
		responseErr.StatusCode != http.StatusConflict ||
		responseErr.Code != "projection_receipt_conflict" ||
		responseErr.Message != conflictMessage {
		t.Fatalf("Project() error = %#v, want status, code, and message", responseErr)
	}
}

func receiptPendingServer(t *testing.T, pendingResponses int) (*httptest.Server, *int) {
	t.Helper()
	var deltaRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projections/authority":
			_ = json.NewEncoder(w).Encode(projectionAuthorityResponse(projectionAuthorityLegacy))
		case "/v1/projections/legacy-deltas":
			deltaRequests++
			if deltaRequests <= pendingResponses {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"code":    sourceEventReceiptPendingCode,
					"message": "legacy projection for source event event-1 has no committed source event receipt",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(legacyProjectionResponse{
				Recorded:    true,
				DeltaDigest: strings.Repeat("a", 64),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &deltaRequests
}

func receiptPendingDelta() *sourceProjectorWithDeltaStub {
	return &sourceProjectorWithDeltaStub{delta: ports.SourceProjectionDelta{
		Entities: []*ports.ProjectedEntity{{
			URN:        "urn:cerebro:tenant-a:asset:one",
			TenantID:   "tenant-a",
			SourceID:   "box",
			RuntimeID:  "box-runtime",
			EntityType: "box.asset",
			Label:      "One",
		}},
	}}
}

func TestLegacyDeltaWaitsForTheConsumerSourceReceipt(t *testing.T) {
	server, deltaRequests := receiptPendingServer(t, 2)
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	result, err := NewAppendLogProjector(receiptPendingDelta(), client).Project(context.Background(), projectionEvent())
	if err != nil || result.EntitiesProjected != 1 || *deltaRequests != 3 {
		t.Fatalf("Project() = %#v, %v delta_requests=%d, want success on the third attempt", result, err, *deltaRequests)
	}
}

func TestLegacyDeltaReceiptPendingIsRejectedAfterTheBudget(t *testing.T) {
	server, deltaRequests := receiptPendingServer(t, 1_000)
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	client.receiptPendingBudget = 300 * time.Millisecond
	_, err = NewAppendLogProjector(receiptPendingDelta(), client).Project(context.Background(), projectionEvent())
	var responseErr *ProjectionResponseError
	if !errors.As(err, &responseErr) || responseErr.Code != sourceEventReceiptPendingCode {
		t.Fatalf("Project() error = %v, want the pending code after the budget", err)
	}
	// Still a record-scoped rejection, so a consumer that never catches up
	// dead-letters the record instead of hanging the sync.
	if !errors.Is(err, ports.ErrSourceProjectionRecordRejected) {
		t.Fatalf("Project() error = %v, want a record-scoped rejection", err)
	}
	if *deltaRequests < 2 || *deltaRequests > 4 {
		t.Fatalf("delta_requests=%d, want a few bounded retries", *deltaRequests)
	}
}

func TestLegacyDeltaReceiptPendingStopsWhenTheContextEnds(t *testing.T) {
	server, _ := receiptPendingServer(t, 1_000)
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = NewAppendLogProjector(receiptPendingDelta(), client).Project(ctx, projectionEvent())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Project() error = %v, want the context deadline", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("Project() took %s after the context ended", elapsed)
	}
}

func TestLegacyDeltaRealReceiptConflictIsNotRetried(t *testing.T) {
	var deltaRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projections/authority":
			_ = json.NewEncoder(w).Encode(projectionAuthorityResponse(projectionAuthorityLegacy))
		case "/v1/projections/legacy-deltas":
			deltaRequests++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "projection_receipt_conflict"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	_, err = NewAppendLogProjector(receiptPendingDelta(), client).Project(context.Background(), projectionEvent())
	if !errors.Is(err, ErrProjectionReceiptConflict) || deltaRequests != 1 {
		t.Fatalf("Project() error = %v delta_requests=%d, want one attempt", err, deltaRequests)
	}
}

func TestProjectionResponseErrorBoundsDetailAndKeepsPlainStatus(t *testing.T) {
	long := strings.Repeat("x", 4*maxErrorDetailRunes)
	body, _ := json.Marshal(map[string]string{"code": "projection_store_unavailable", "message": long})
	err := projectionResponseError(&http.Response{
		Status:     "503 Service Unavailable",
		StatusCode: http.StatusServiceUnavailable,
		Body:       io.NopCloser(strings.NewReader(string(body))),
	})
	var responseErr *ProjectionResponseError
	if errors.Is(err, ErrProjectionReceiptConflict) || !errors.As(err, &responseErr) ||
		responseErr.Code != "projection_store_unavailable" ||
		len([]rune(responseErr.Message)) != maxErrorDetailRunes+1 {
		t.Fatalf("projectionResponseError() = %#v", responseErr)
	}
	err = projectionResponseError(&http.Response{
		Status:     "502 Bad Gateway",
		StatusCode: http.StatusBadGateway,
		Body:       io.NopCloser(strings.NewReader("<html>proxy</html>")),
	})
	if !errors.As(err, &responseErr) || responseErr.StatusCode != http.StatusBadGateway ||
		responseErr.Code != "" || responseErr.Message != "" {
		t.Fatalf("projectionResponseError() = %#v, want status only for non-JSON bodies", responseErr)
	}
}

func TestProjectionResponseErrorClassifiesRecordScopedRejections(t *testing.T) {
	tests := []struct {
		status          int
		recordRejected  bool
		receiptConflict bool
	}{
		{status: http.StatusBadRequest, recordRejected: true},
		{status: http.StatusConflict, recordRejected: true, receiptConflict: true},
		{status: http.StatusUnprocessableEntity, recordRejected: true},
		{status: http.StatusUnauthorized},
		{status: http.StatusNotFound},
		{status: http.StatusTooManyRequests},
		{status: http.StatusInternalServerError},
		{status: http.StatusBadGateway},
		{status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			err := fmt.Errorf("project source event %q: %w", "event-1", &ProjectionResponseError{
				Status:      http.StatusText(test.status),
				StatusCode:  test.status,
				Code:        "invalid_legacy_projection",
				RecordWrite: true,
			})
			if got := errors.Is(err, ports.ErrSourceProjectionRecordRejected); got != test.recordRejected {
				t.Fatalf("errors.Is(ErrSourceProjectionRecordRejected) = %v, want %v", got, test.recordRejected)
			}
			if got := errors.Is(err, ErrProjectionReceiptConflict); got != test.receiptConflict {
				t.Fatalf("errors.Is(ErrProjectionReceiptConflict) = %v, want %v", got, test.receiptConflict)
			}
			var coder ports.SourceProjectionErrorCoder
			if !errors.As(err, &coder) || coder.ProjectionErrorCode() != "invalid_legacy_projection" {
				t.Fatalf("errors.As(SourceProjectionErrorCoder) did not expose the Rust code")
			}
		})
	}
}

func TestAppendLogProjectorAuthorityRejectionIsNotRecordScoped(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/projections/authority" {
					t.Errorf("unexpected request to %s after the authority lookup failed", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": "invalid_projection_scope"})
			}))
			defer server.Close()
			client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
			if err != nil {
				t.Fatalf("NewProjectionClient() error = %v", err)
			}
			_, err = NewAppendLogProjector(&sourceProjectorWithDeltaStub{}, client).Project(context.Background(), projectionEvent())
			var responseErr *ProjectionResponseError
			if !errors.As(err, &responseErr) || responseErr.StatusCode != status {
				t.Fatalf("Project() error = %v, want the authority response error", err)
			}
			if errors.Is(err, ports.ErrSourceProjectionRecordRejected) {
				t.Fatalf("Project() error = %v, want a family-scoped failure that fails the sync", err)
			}
		})
	}
}

func TestAppendLogProjectorTransportFailureIsNotRecordScoped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client, err := NewProjectionClient(server.URL, testSharedSecret, time.Second)
	if err != nil {
		t.Fatalf("NewProjectionClient() error = %v", err)
	}
	server.Close()
	_, err = NewAppendLogProjector(nil, client).Project(context.Background(), projectionEvent())
	if err == nil || errors.Is(err, ports.ErrSourceProjectionRecordRejected) {
		t.Fatalf("Project() error = %v, want a non-record-scoped transport failure", err)
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

// The append-log subject is "<prefix>.<kind>" and Rust reads it back as
// "<prefix>.<source>.<family>", so the kind carries the taxonomy. A shared
// namespace such as asset.data_sensitivity belongs to the asset source whichever
// cloud connector stamped the envelope.
func TestEventTaxonomyComesFromTheKind(t *testing.T) {
	for _, tt := range []struct {
		name       string
		envelopeID string
		kind       string
		wantSource string
		wantFamily string
	}{
		{name: "matching source", envelopeID: "gcp", kind: "gcp.audit", wantSource: "gcp", wantFamily: "audit"},
		{name: "shared namespace", envelopeID: "gcp", kind: "asset.data_sensitivity", wantSource: "asset", wantFamily: "data_sensitivity"},
		{name: "nested family", envelopeID: "github", kind: "github.code.repository", wantSource: "github", wantFamily: "code.repository"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := projectionEvent()
			event.SourceId = tt.envelopeID
			event.Kind = tt.kind
			source, family, err := eventTaxonomy(event)
			if err != nil {
				t.Fatalf("eventTaxonomy() error = %v", err)
			}
			if source != tt.wantSource || family != tt.wantFamily {
				t.Fatalf("eventTaxonomy() = %q/%q, want %q/%q", source, family, tt.wantSource, tt.wantFamily)
			}
		})
	}
}

func TestEventTaxonomyRejectsKindsWithoutTwoSegments(t *testing.T) {
	for _, kind := range []string{"", "gcp", "gcp.", ".audit"} {
		event := projectionEvent()
		event.Kind = kind
		if _, _, err := eventTaxonomy(event); err == nil {
			t.Fatalf("eventTaxonomy(%q) error = nil, want an error", kind)
		}
	}
}

// Production symptom: every gcp sync carrying an asset.data_sensitivity event
// failed with "does not belong to source", taking the whole run with it.
func TestAppendLogProjectorProjectsSharedNamespaceKinds(t *testing.T) {
	var authorityQueries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/projections/authority":
			authorityQueries = append(authorityQueries, r.URL.Query().Get("source_id")+"/"+r.URL.Query().Get("family_id"))
			_ = json.NewEncoder(w).Encode(authorityResponse{
				TenantID:  r.URL.Query().Get("tenant_id"),
				SourceID:  r.URL.Query().Get("source_id"),
				FamilyID:  r.URL.Query().Get("family_id"),
				Authority: projectionAuthorityRust,
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
	event := projectionEvent()
	event.SourceId = "gcp"
	event.Kind = "asset.data_sensitivity"

	if _, err := NewAppendLogProjector(&sourceProjectorStub{}, client).Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if len(authorityQueries) != 1 || authorityQueries[0] != "asset/data_sensitivity" {
		t.Fatalf("authority queries = %v, want [asset/data_sensitivity]", authorityQueries)
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
