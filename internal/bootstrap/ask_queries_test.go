package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

type stubAskQueryStore struct {
	queries map[string]*ports.AskQuery
}

func newStubAskQueryStore() *stubAskQueryStore {
	return &stubAskQueryStore{queries: map[string]*ports.AskQuery{}}
}

func (s *stubAskQueryStore) Ping(context.Context) error { return nil }

func (s *stubAskQueryStore) PutAskQuery(_ context.Context, query *ports.AskQuery) error {
	copied := *query
	if copied.CreatedAt.IsZero() {
		copied.CreatedAt = time.Now().UTC()
	}
	copied.UpdatedAt = time.Now().UTC()
	s.queries[query.ID] = &copied
	return nil
}

func (s *stubAskQueryStore) GetAskQuery(_ context.Context, id string) (*ports.AskQuery, error) {
	query, ok := s.queries[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrAskQueryNotFound
	}
	copied := *query
	return &copied, nil
}

func (s *stubAskQueryStore) ListAskQueries(_ context.Context, filter ports.AskQueryFilter) ([]*ports.AskQuery, error) {
	out := []*ports.AskQuery{}
	for _, query := range s.queries {
		if filter.TenantID != "" && query.TenantID != filter.TenantID {
			continue
		}
		copied := *query
		out = append(out, &copied)
	}
	return out, nil
}

func (s *stubAskQueryStore) DeleteAskQuery(_ context.Context, id string) error {
	delete(s.queries, strings.TrimSpace(id))
	return nil
}

func askQueryTestApp(store ports.StateStore) *App {
	return New(config.Config{HTTPAddr: "127.0.0.1:0"}, Dependencies{StateStore: store}, nil)
}

func askQueryTestRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "local"},
	}))
}

func TestHandleCreateAskQueryValidatesAndPersists(t *testing.T) {
	store := newStubAskQueryStore()
	app := askQueryTestApp(store)

	recorder := httptest.NewRecorder()
	body := `{"name":"Stale okta admins","question":"Which okta.user admins have not signed in for 90 days?","scope_urn":"urn:cerebro:local:identity:admin","pinned":true}`
	app.handleCreateAskQuery(recorder, askQueryTestRequest(http.MethodPost, "/ask-queries", body))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body %s)", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var response askQueryResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if response.Query.TenantID != "local" || response.Query.Name != "Stale okta admins" {
		t.Fatalf("unexpected query %+v", response.Query)
	}
	if !response.Query.Pinned {
		t.Fatal("query should be pinned")
	}
	if response.Query.ScopeURN != "urn:cerebro:local:identity:admin" {
		t.Fatalf("unexpected scope_urn %q", response.Query.ScopeURN)
	}
	if response.Query.CreatedAt == "" {
		t.Fatal("created_at should be set")
	}
	if len(store.queries) != 1 {
		t.Fatalf("stored queries = %d, want 1", len(store.queries))
	}
}

func TestHandleCreateAskQueryRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "missing name", body: `{"question":"who?"}`, want: http.StatusBadRequest},
		{name: "missing question", body: `{"name":"q"}`, want: http.StatusBadRequest},
		{name: "blank question", body: `{"name":"q","question":"   "}`, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStubAskQueryStore()
			app := askQueryTestApp(store)
			recorder := httptest.NewRecorder()
			app.handleCreateAskQuery(recorder, askQueryTestRequest(http.MethodPost, "/ask-queries", tc.body))
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, tc.want, recorder.Body.String())
			}
			if len(store.queries) != 0 {
				t.Fatalf("invalid input should not persist, stored %d", len(store.queries))
			}
		})
	}
}

func TestHandleListAskQueriesScopesToTenant(t *testing.T) {
	store := newStubAskQueryStore()
	store.queries["a"] = &ports.AskQuery{ID: "a", TenantID: "local", Name: "mine", Question: "q"}
	store.queries["b"] = &ports.AskQuery{ID: "b", TenantID: "other", Name: "theirs", Question: "q"}
	app := askQueryTestApp(store)

	recorder := httptest.NewRecorder()
	app.handleListAskQueries(recorder, askQueryTestRequest(http.MethodGet, "/ask-queries", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response askQueryListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(response.Queries) != 1 || response.Queries[0].ID != "a" {
		t.Fatalf("expected only tenant-scoped query, got %+v", response.Queries)
	}
}

func TestHandleUpdateAskQueryAppliesPatchAndScopesTenant(t *testing.T) {
	store := newStubAskQueryStore()
	store.queries["a"] = &ports.AskQuery{ID: "a", TenantID: "local", Name: "mine", Question: "q", Pinned: false}
	store.queries["b"] = &ports.AskQuery{ID: "b", TenantID: "other", Name: "theirs", Question: "q"}
	app := askQueryTestApp(store)

	recorder := httptest.NewRecorder()
	request := askQueryTestRequest(http.MethodPatch, "/ask-queries/a", `{"name":"renamed","pinned":true}`)
	request.SetPathValue("queryID", "a")
	app.handleUpdateAskQuery(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	if store.queries["a"].Name != "renamed" || !store.queries["a"].Pinned {
		t.Fatalf("query a not patched: %+v", store.queries["a"])
	}

	crossRecorder := httptest.NewRecorder()
	crossRequest := askQueryTestRequest(http.MethodPatch, "/ask-queries/b", `{"name":"hijack"}`)
	crossRequest.SetPathValue("queryID", "b")
	app.handleUpdateAskQuery(crossRecorder, crossRequest)
	if crossRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant update status = %d, want 404", crossRecorder.Code)
	}
	if store.queries["b"].Name != "theirs" {
		t.Fatal("cross-tenant query must not be modified")
	}
}

func TestHandleDeleteAskQueryScopesTenant(t *testing.T) {
	store := newStubAskQueryStore()
	store.queries["a"] = &ports.AskQuery{ID: "a", TenantID: "local", Name: "mine", Question: "q"}
	store.queries["b"] = &ports.AskQuery{ID: "b", TenantID: "other", Name: "theirs", Question: "q"}
	app := askQueryTestApp(store)

	recorder := httptest.NewRecorder()
	request := askQueryTestRequest(http.MethodDelete, "/ask-queries/a", "")
	request.SetPathValue("queryID", "a")
	app.handleDeleteAskQuery(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204 (body %s)", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.queries["a"]; ok {
		t.Fatal("query a should be deleted")
	}

	crossRecorder := httptest.NewRecorder()
	crossRequest := askQueryTestRequest(http.MethodDelete, "/ask-queries/b", "")
	crossRequest.SetPathValue("queryID", "b")
	app.handleDeleteAskQuery(crossRecorder, crossRequest)
	if crossRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete status = %d, want 404", crossRecorder.Code)
	}
	if _, ok := store.queries["b"]; !ok {
		t.Fatal("cross-tenant query must not be deleted")
	}
}

func TestHandleAskQueryStoreUnavailable(t *testing.T) {
	app := askQueryTestApp(stubNoAskQueryStore{})
	recorder := httptest.NewRecorder()
	app.handleListAskQueries(recorder, askQueryTestRequest(http.MethodGet, "/ask-queries", ""))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", recorder.Code, recorder.Body.String())
	}
}

type stubNoAskQueryStore struct{}

func (stubNoAskQueryStore) Ping(context.Context) error { return nil }
