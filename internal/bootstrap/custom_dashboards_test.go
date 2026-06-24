package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcehttp/customdashboards"
)

type stubCustomDashboardStore struct {
	dashboards map[string]*ports.CustomDashboard
}

func newStubCustomDashboardStore() *stubCustomDashboardStore {
	return &stubCustomDashboardStore{dashboards: map[string]*ports.CustomDashboard{}}
}

func (s *stubCustomDashboardStore) Ping(context.Context) error { return nil }

func (s *stubCustomDashboardStore) PutCustomDashboard(_ context.Context, dashboard *ports.CustomDashboard) error {
	copied := *dashboard
	if copied.CreatedAt.IsZero() {
		copied.CreatedAt = time.Now().UTC()
	}
	copied.UpdatedAt = time.Now().UTC()
	s.dashboards[copied.ID] = &copied
	return nil
}

func (s *stubCustomDashboardStore) GetCustomDashboard(_ context.Context, id string) (*ports.CustomDashboard, error) {
	dashboard, ok := s.dashboards[strings.TrimSpace(id)]
	if !ok {
		return nil, ports.ErrCustomDashboardNotFound
	}
	copied := *dashboard
	return &copied, nil
}

func (s *stubCustomDashboardStore) ListCustomDashboards(_ context.Context, filter ports.CustomDashboardFilter) ([]*ports.CustomDashboard, error) {
	out := []*ports.CustomDashboard{}
	for _, dashboard := range s.dashboards {
		if filter.TenantID != "" && dashboard.TenantID != filter.TenantID {
			continue
		}
		if filter.WorkspaceID != "" && dashboard.WorkspaceID != filter.WorkspaceID {
			continue
		}
		if !filter.IncludeArchived && !dashboard.ArchivedAt.IsZero() {
			continue
		}
		copied := *dashboard
		out = append(out, &copied)
	}
	return out, nil
}

func (s *stubCustomDashboardStore) DeleteCustomDashboard(_ context.Context, id string) error {
	dashboard, ok := s.dashboards[strings.TrimSpace(id)]
	if !ok {
		return ports.ErrCustomDashboardNotFound
	}
	copied := *dashboard
	copied.ArchivedAt = time.Now().UTC()
	s.dashboards[copied.ID] = &copied
	return nil
}

func customDashboardTestRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{TenantID: "local", Name: "person@example.test"},
	}))
}

func customDashboardTestHandler(app *App) *customdashboards.Handler {
	return customdashboards.NewHandler(app.deps.StateStore, effectiveTenantFilter, authorizeTenantID, customDashboardActorID)
}

func TestHandleCreateCustomDashboardValidatesAndPersists(t *testing.T) {
	store := newStubCustomDashboardStore()
	app := askQueryTestApp(store)

	body := `{"name":"GRC trends","widgets":[{"id":"trend","type":"trend_chart"}],"filters":{"severity":"HIGH"},"layout":{"columns":12},"visibility":"workspace","workspace_id":"workspace-1"}`
	recorder := httptest.NewRecorder()
	customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", body))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d (body %s)", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var response customdashboards.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if response.Dashboard.TenantID != "local" || response.Dashboard.Name != "GRC trends" {
		t.Fatalf("unexpected dashboard %+v", response.Dashboard)
	}
	if response.Dashboard.OwnerUserID != "person@example.test" || response.Dashboard.CreatedBy != "person@example.test" {
		t.Fatalf("dashboard owner/stamp = %+v", response.Dashboard)
	}
	if len(store.dashboards) != 1 {
		t.Fatalf("stored dashboards = %d, want 1", len(store.dashboards))
	}
}

func TestHandleCreateCustomDashboardRejectsInvalidJSONShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "missing name", body: `{"widgets":[]}`},
		{name: "layout array", body: `{"name":"bad","layout":[]}`},
		{name: "widgets object", body: `{"name":"bad","widgets":{}}`},
		{name: "bad visibility", body: `{"name":"bad","visibility":"public"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStubCustomDashboardStore()
			app := askQueryTestApp(store)
			recorder := httptest.NewRecorder()
			customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", tc.body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHandleListCustomDashboardsScopesToTenant(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["a"] = &ports.CustomDashboard{ID: "a", TenantID: "local", OwnerUserID: "person@example.test", Name: "mine", Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	store.dashboards["b"] = &ports.CustomDashboard{ID: "b", TenantID: "other", OwnerUserID: "person@example.test", Name: "theirs", Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	recorder := httptest.NewRecorder()
	customDashboardTestHandler(app).List(recorder, customDashboardTestRequest(http.MethodGet, "/grc/dashboards", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response customdashboards.ListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(response.Dashboards) != 1 || response.Dashboards[0].ID != "a" {
		t.Fatalf("expected local dashboard only, got %+v", response.Dashboards)
	}
}

func TestHandleCreateCustomDashboardRejectsUnknownWidgets(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "unknown type", body: `{"name":"bad","widgets":[{"id":"w1","type":"frobnicate"}]}`},
		{name: "missing id", body: `{"name":"bad","widgets":[{"type":"trend_chart"}]}`},
		{name: "duplicate id", body: `{"name":"bad","widgets":[{"id":"w1","type":"trend_chart"},{"id":"w1","type":"summary_metrics"}]}`},
		{name: "unsupported schema_version", body: `{"name":"bad","schema_version":99,"widgets":[{"id":"w1","type":"summary_metrics"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newStubCustomDashboardStore()
			app := askQueryTestApp(store)
			recorder := httptest.NewRecorder()
			customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", tc.body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHandleCreateCustomDashboardAcceptsBroadenedWidgets(t *testing.T) {
	store := newStubCustomDashboardStore()
	app := askQueryTestApp(store)
	body := `{"name":"Overview","widgets":[{"id":"kpis","type":"summary_metrics"},{"id":"findings","type":"findings_table"},{"id":"frameworks","type":"framework_progress"},{"id":"connectors","type":"connector_health"},{"id":"note","type":"markdown_note"}]}`
	recorder := httptest.NewRecorder()
	customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", body))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestHandleCreateCustomDashboardValidatesWidgetCatalogQuery(t *testing.T) {
	t.Run("accepts a bound catalog query", func(t *testing.T) {
		store := newStubCustomDashboardStore()
		app := askQueryTestApp(store)
		body := `{"name":"Bound","widgets":[{"id":"w1","type":"findings_table","query":{"source_id":"findings","params":{"status":"open","severity":"high"},"limit":50}}]}`
		recorder := httptest.NewRecorder()
		customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", body))
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", recorder.Code, recorder.Body.String())
		}
	})
	t.Run("tolerates a legacy query with no catalog binding", func(t *testing.T) {
		store := newStubCustomDashboardStore()
		app := askQueryTestApp(store)
		body := `{"name":"Legacy","widgets":[{"id":"w1","type":"trend_chart","query":{"endpoint":"/grc/trends","params":{"days":"30"}}}]}`
		recorder := httptest.NewRecorder()
		customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", body))
		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", recorder.Code, recorder.Body.String())
		}
	})
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "unknown source", body: `{"name":"bad","widgets":[{"id":"w1","type":"findings_table","query":{"source_id":"made-up"}}]}`},
		{name: "unknown parameter", body: `{"name":"bad","widgets":[{"id":"w1","type":"findings_table","query":{"source_id":"findings","params":{"not_a_param":"x"}}}]}`},
		{name: "bad enum", body: `{"name":"bad","widgets":[{"id":"w1","type":"trend_chart","query":{"source_id":"trends","params":{"interval":"decade"}}}]}`},
		{name: "over limit", body: `{"name":"bad","widgets":[{"id":"w1","type":"findings_table","query":{"source_id":"findings","limit":100000}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStubCustomDashboardStore()
			app := askQueryTestApp(store)
			recorder := httptest.NewRecorder()
			customDashboardTestHandler(app).Create(recorder, customDashboardTestRequest(http.MethodPost, "/grc/dashboards", tc.body))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestHandleListCustomDashboardRequiresTenant(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["local"] = &ports.CustomDashboard{ID: "local", TenantID: "local", OwnerUserID: "person@example.test", Name: "local", Visibility: "workspace", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	store.dashboards["other"] = &ports.CustomDashboard{ID: "other", TenantID: "other", OwnerUserID: "intruder@example.test", Name: "other", Visibility: "workspace", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	request := httptest.NewRequest(http.MethodGet, "/grc/dashboards", nil)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{
		principal: authPrincipal{Name: "person@example.test"},
	}))
	recorder := httptest.NewRecorder()
	customDashboardTestHandler(app).List(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("list without a resolvable tenant status = %d, want 400 (must not fan out across tenants) (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestHandleCustomDashboardVisibilityHidesPrivateFromNonOwner(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["mine"] = &ports.CustomDashboard{ID: "mine", TenantID: "local", OwnerUserID: "person@example.test", Name: "mine", Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	store.dashboards["theirs"] = &ports.CustomDashboard{ID: "theirs", TenantID: "local", OwnerUserID: "other@example.test", Name: "theirs", Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	store.dashboards["shared"] = &ports.CustomDashboard{ID: "shared", TenantID: "local", OwnerUserID: "other@example.test", Name: "shared", Visibility: "workspace", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	listRecorder := httptest.NewRecorder()
	customDashboardTestHandler(app).List(listRecorder, customDashboardTestRequest(http.MethodGet, "/grc/dashboards", ""))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body %s)", listRecorder.Code, listRecorder.Body.String())
	}
	var listResponse customdashboards.ListResponse
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listResponse); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	got := map[string]bool{}
	for _, dashboard := range listResponse.Dashboards {
		got[dashboard.ID] = true
	}
	if !got["mine"] || !got["shared"] || got["theirs"] {
		t.Fatalf("list visibility filter wrong, got %+v", got)
	}

	getRecorder := httptest.NewRecorder()
	getRequest := customDashboardTestRequest(http.MethodGet, "/grc/dashboards/theirs", "")
	getRequest.SetPathValue("dashboardID", "theirs")
	customDashboardTestHandler(app).Get(getRecorder, getRequest)
	if getRecorder.Code != http.StatusNotFound {
		t.Fatalf("get private dashboard of another owner = %d, want 404", getRecorder.Code)
	}

	sharedRecorder := httptest.NewRecorder()
	sharedRequest := customDashboardTestRequest(http.MethodGet, "/grc/dashboards/shared", "")
	sharedRequest.SetPathValue("dashboardID", "shared")
	customDashboardTestHandler(app).Get(sharedRecorder, sharedRequest)
	if sharedRecorder.Code != http.StatusOK {
		t.Fatalf("get workspace-visible dashboard = %d, want 200 (body %s)", sharedRecorder.Code, sharedRecorder.Body.String())
	}
}

func TestHandleCloneCustomDashboardValidatesName(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["src"] = &ports.CustomDashboard{ID: "src", TenantID: "local", OwnerUserID: "person@example.test", Name: strings.Repeat("a", 200), Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	rejectRecorder := httptest.NewRecorder()
	rejectRequest := customDashboardTestRequest(http.MethodPost, "/grc/dashboards/src/clone", `{"name":"`+strings.Repeat("b", 201)+`"}`)
	rejectRequest.SetPathValue("dashboardID", "src")
	customDashboardTestHandler(app).Clone(rejectRecorder, rejectRequest)
	if rejectRecorder.Code != http.StatusBadRequest {
		t.Fatalf("clone with over-length name status = %d, want 400 (body %s)", rejectRecorder.Code, rejectRecorder.Body.String())
	}

	cloneRecorder := httptest.NewRecorder()
	cloneRequest := customDashboardTestRequest(http.MethodPost, "/grc/dashboards/src/clone", "")
	cloneRequest.SetPathValue("dashboardID", "src")
	customDashboardTestHandler(app).Clone(cloneRecorder, cloneRequest)
	if cloneRecorder.Code != http.StatusCreated {
		t.Fatalf("clone status = %d, want 201 (body %s)", cloneRecorder.Code, cloneRecorder.Body.String())
	}
	var response customdashboards.Response
	if err := json.Unmarshal(cloneRecorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode clone response: %v", err)
	}
	if name := response.Dashboard.Name; name == "" || len(name) > 200 {
		t.Fatalf("clone name length = %d, want 1..200 (%q)", len(name), name)
	}
}

func TestHandleCloneCustomDashboardResetsVisibilityToPrivate(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["shared"] = &ports.CustomDashboard{ID: "shared", TenantID: "local", OwnerUserID: "other@example.test", Name: "Shared dashboard", Visibility: "workspace", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	recorder := httptest.NewRecorder()
	request := customDashboardTestRequest(http.MethodPost, "/grc/dashboards/shared/clone", "")
	request.SetPathValue("dashboardID", "shared")
	customDashboardTestHandler(app).Clone(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("clone status = %d, want 201 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response customdashboards.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode clone response: %v", err)
	}
	if response.Dashboard.Visibility != "private" {
		t.Fatalf("clone visibility = %q, want private", response.Dashboard.Visibility)
	}
	if response.Dashboard.OwnerUserID != "person@example.test" {
		t.Fatalf("clone owner = %q, want person@example.test", response.Dashboard.OwnerUserID)
	}
}

func TestHandleCustomDashboardMutationsRestrictedToOwner(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["shared"] = &ports.CustomDashboard{ID: "shared", TenantID: "local", OwnerUserID: "other@example.test", Name: "Shared dashboard", Visibility: "workspace", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	getRecorder := httptest.NewRecorder()
	getRequest := customDashboardTestRequest(http.MethodGet, "/grc/dashboards/shared", "")
	getRequest.SetPathValue("dashboardID", "shared")
	customDashboardTestHandler(app).Get(getRecorder, getRequest)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200 (non-owner can view shared) (body %s)", getRecorder.Code, getRecorder.Body.String())
	}

	updateRecorder := httptest.NewRecorder()
	updateRequest := customDashboardTestRequest(http.MethodPatch, "/grc/dashboards/shared", `{"name":"renamed"}`)
	updateRequest.SetPathValue("dashboardID", "shared")
	customDashboardTestHandler(app).Update(updateRecorder, updateRequest)
	if updateRecorder.Code != http.StatusForbidden {
		t.Fatalf("update status = %d, want 403 (non-owner) (body %s)", updateRecorder.Code, updateRecorder.Body.String())
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := customDashboardTestRequest(http.MethodDelete, "/grc/dashboards/shared", "")
	deleteRequest.SetPathValue("dashboardID", "shared")
	customDashboardTestHandler(app).Delete(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusForbidden {
		t.Fatalf("delete status = %d, want 403 (non-owner) (body %s)", deleteRecorder.Code, deleteRecorder.Body.String())
	}
}

func TestHandleUpdateAndDeleteCustomDashboardScopeTenant(t *testing.T) {
	store := newStubCustomDashboardStore()
	store.dashboards["a"] = &ports.CustomDashboard{ID: "a", TenantID: "local", OwnerUserID: "person@example.test", Name: "mine", Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	store.dashboards["b"] = &ports.CustomDashboard{ID: "b", TenantID: "other", OwnerUserID: "other@example.test", Name: "theirs", Visibility: "private", SchemaVersion: 1, LayoutJSON: "{}", WidgetsJSON: "[]", FiltersJSON: "{}"}
	app := askQueryTestApp(store)

	updateRecorder := httptest.NewRecorder()
	updateRequest := customDashboardTestRequest(http.MethodPatch, "/grc/dashboards/a", `{"name":"renamed","widgets":[{"id":"metric","type":"trend_metric_cards"}]}`)
	updateRequest.SetPathValue("dashboardID", "a")
	customDashboardTestHandler(app).Update(updateRecorder, updateRequest)
	if updateRecorder.Code != http.StatusOK {
		t.Fatalf("update status = %d, want 200 (body %s)", updateRecorder.Code, updateRecorder.Body.String())
	}
	if store.dashboards["a"].Name != "renamed" {
		t.Fatalf("dashboard a not patched: %+v", store.dashboards["a"])
	}

	crossRecorder := httptest.NewRecorder()
	crossRequest := customDashboardTestRequest(http.MethodPatch, "/grc/dashboards/b", `{"name":"hijack"}`)
	crossRequest.SetPathValue("dashboardID", "b")
	customDashboardTestHandler(app).Update(crossRecorder, crossRequest)
	if crossRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant update status = %d, want 404", crossRecorder.Code)
	}

	deleteRecorder := httptest.NewRecorder()
	deleteRequest := customDashboardTestRequest(http.MethodDelete, "/grc/dashboards/a", "")
	deleteRequest.SetPathValue("dashboardID", "a")
	customDashboardTestHandler(app).Delete(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204 (body %s)", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if store.dashboards["a"].ArchivedAt.IsZero() {
		t.Fatal("dashboard a should be archived")
	}
}
