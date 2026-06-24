package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/writer/cerebro/internal/grccatalog"
)

func TestGRCQuerySourcesMatchCatalog(t *testing.T) {
	app := askQueryTestApp(newStubCustomDashboardStore())
	handlers := app.grcQuerySources()
	for _, source := range grccatalog.Catalog() {
		if _, ok := handlers[source.ID]; !ok {
			t.Fatalf("catalog source %q has no query handler", source.ID)
		}
	}
	for id := range handlers {
		if _, ok := grccatalog.Lookup(id); !ok {
			t.Fatalf("query handler %q is not in the catalog", id)
		}
	}
}

func TestHandleGRCReportCatalogReturnsSources(t *testing.T) {
	app := askQueryTestApp(newStubCustomDashboardStore())
	recorder := httptest.NewRecorder()
	app.handleGRCReportCatalog(recorder, httptest.NewRequest(http.MethodGet, "/grc/report-catalog", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Sources []grccatalog.Source `json:"sources"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	if len(response.Sources) == 0 {
		t.Fatal("catalog response has no sources")
	}
	if _, ok := grccatalog.Lookup(response.Sources[0].ID); !ok {
		t.Fatalf("catalog returned unknown source %q", response.Sources[0].ID)
	}
}

func TestHandleGRCQueryRejectsMalformedBody(t *testing.T) {
	app := askQueryTestApp(newStubCustomDashboardStore())
	recorder := httptest.NewRecorder()
	app.handleGRCQuery(recorder, customDashboardTestRequest(http.MethodPost, "/grc/query", `{"source_id":`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestHandleGRCQueryRejectsUnknownSource(t *testing.T) {
	app := askQueryTestApp(newStubCustomDashboardStore())
	recorder := httptest.NewRecorder()
	app.handleGRCQuery(recorder, customDashboardTestRequest(http.MethodPost, "/grc/query", `{"source_id":"does-not-exist"}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestHandleGRCQueryRejectsUnknownParameter(t *testing.T) {
	app := askQueryTestApp(newStubCustomDashboardStore())
	recorder := httptest.NewRecorder()
	app.handleGRCQuery(recorder, customDashboardTestRequest(http.MethodPost, "/grc/query", `{"source_id":"findings","params":{"not_a_param":"x"}}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func TestDispatchGRCQueryBuildsBoundedRequest(t *testing.T) {
	source, ok := grccatalog.Lookup("findings")
	if !ok {
		t.Fatal("findings source missing from catalog")
	}
	var capturedQuery string
	stub := func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.RawQuery
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
	request := customDashboardTestRequest(http.MethodPost, "/grc/query", "")
	query := grccatalog.WidgetQuery{SourceID: "findings", Params: map[string]string{"status": "open", "runtime_id": "rt-1"}, Limit: 25}
	captured := dispatchGRCQuery(stub, request, source, query)
	if captured.statusCode != http.StatusOK {
		t.Fatalf("dispatch status = %d, want 200", captured.statusCode)
	}
	values, err := url.ParseQuery(capturedQuery)
	if err != nil {
		t.Fatalf("parse forwarded query: %v", err)
	}
	if values.Get("status") != "open" || values.Get("runtime_id") != "rt-1" || values.Get("limit") != "25" {
		t.Fatalf("unexpected forwarded query %q", capturedQuery)
	}
}

func TestWriteGRCQueryResponseEnvelopesSuccessAndPropagatesErrors(t *testing.T) {
	source, _ := grccatalog.Lookup("findings")

	success := &capturedHTTPResponse{header: http.Header{}, statusCode: http.StatusOK}
	success.body.WriteString(`{"findings":[]}`)
	recorder := httptest.NewRecorder()
	writeGRCQueryResponse(recorder, source, success)
	if recorder.Code != http.StatusOK {
		t.Fatalf("success status = %d, want 200", recorder.Code)
	}
	var envelope struct {
		SourceID string          `json:"source_id"`
		Data     json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.SourceID != "findings" || len(envelope.Data) == 0 {
		t.Fatalf("unexpected envelope %+v", envelope)
	}

	failed := &capturedHTTPResponse{header: http.Header{}, statusCode: http.StatusForbidden}
	failed.body.WriteString(`{"error":"forbidden"}`)
	errorRecorder := httptest.NewRecorder()
	writeGRCQueryResponse(errorRecorder, source, failed)
	if errorRecorder.Code != http.StatusForbidden {
		t.Fatalf("error status = %d, want 403", errorRecorder.Code)
	}
}
